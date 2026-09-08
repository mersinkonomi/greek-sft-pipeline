"""Meaningful deduplication, lineage, integrity and path-safety tests."""

import itertools
import json
from pathlib import Path
import random
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from greek_sft.dedup import DedupError, STAGES, _database, _fertility, _jaccard, _load, _near_groups, _shingles, _settings, run_dedup


def candidate(identity, context, answer="Η απάντηση στηρίζεται στο απόσπασμα.", group=None, domain="general", task="qa"):
    return {"id": identity, "messages": [
        {"role": "system", "content": "Απάντησε στα ελληνικά."},
        {"role": "user", "content": context},
        {"role": "assistant", "content": answer}],
        "metadata": {"source_name": "fixture", "source_file": "fixture.jsonl", "source_record_id": identity,
                     "split_group": group or identity, "task_type": task, "domain": domain,
                     "language": "el", "locale": "el-GR", "review_status": "pending"}}


class DedupTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "runs").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="dedup_test_", dir=ROOT / "runs")
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def run_records(self, records, config=None):
        source = self.root / "input.jsonl"
        with source.open("x", encoding="utf-8") as stream:
            for record in records:
                stream.write(json.dumps(record, ensure_ascii=False) + "\n")
        before = source.read_bytes()
        result = run_dedup([source], self.root / "output", config or {})
        self.assertEqual(source.read_bytes(), before)
        return result

    def output_records(self):
        output = []
        for path in (self.root / "output/completed/pre_api").glob("*/canonical.jsonl"):
            output.extend(json.loads(line) for line in path.read_text().splitlines())
        return output

    def test_empty_input_honest_and_resumable(self):
        result = run_dedup([], self.root / "output", {})
        self.assertEqual(result["input_candidates"], 0)
        self.assertEqual(result["awaiting_api_review"], 0)
        self.assertEqual(result["required_stage_order"], list(STAGES))
        self.assertFalse(result["release_ready"])
        self.assertTrue(result["fertility"]["packing_blocked"])
        self.assertEqual(run_dedup([], self.root / "output", {}), result)
        self.assertEqual(len(list((self.root / "output/completed").glob("0*/survivors.jsonl"))), 3)

    def test_exact_and_substring_stages_preserve_removed_records(self):
        body = "Το ιστορικό κείμενο περιγράφει προσεκτικά το γεγονός. " * 12
        long = candidate("long", "Πρόλογος. " + body)
        small = candidate("small", body)
        exact = candidate("exact", body)
        exact["messages"][0]["content"] = "Διαφορετική σταθερή οδηγία συστήματος."
        result = self.run_records([small, long, exact])
        self.assertEqual(result["stages"][0]["removed"], 2)
        self.assertEqual(result["awaiting_api_review"], 1)
        removed = [json.loads(line) for line in (self.root / "output/completed/01_ExactSubstrings/removals.jsonl").read_text().splitlines()]
        self.assertEqual({r["example_id"] for r in removed}, {"small", "exact"})
        self.assertTrue(all("record" in row for row in removed))

    def test_minhash_is_verified_and_retains_different_answers(self):
        words = ["λέξη" + chr(0x3B1 + i // 24) + chr(0x3B1 + i % 24) for i in range(180)]
        context = " ".join(words)
        near_words = list(words)
        near_words[90] = "διαφορετική"
        different = candidate("different", context, answer="Το συμπέρασμα είναι διαφορετικό.")
        result = self.run_records([candidate("a", context), candidate("b", " ".join(near_words)), different])
        self.assertEqual(result["stages"][1]["removed"], 1)
        self.assertEqual(result["awaiting_api_review"], 2)
        output = self.output_records()
        self.assertEqual(len({r["metadata"]["split"] for r in output}), 1)
        self.assertEqual(result["leakage"]["detected_near_pairs"], 1)
        self.assertEqual(result["leakage"]["cross_split_near_pairs"], 0)

    def test_sentence_stage_keeps_unique_short_fact(self):
        sentences = ["Η τεκμηριωμένη περιγραφή για το συμβάν είναι " + word + "." for word in ("ολοκληρωμένη", "αναλυτική", "σαφής", "ακριβής", "προσεκτική", "λεπτομερής")]
        first = candidate("one", " ".join(sentences))
        reordered = candidate("two", " ".join(reversed(sentences)))
        unique = candidate("three", " ".join(sentences) + " Όχι.")
        result = self.run_records([first, reordered, unique], {"dedup": {"minhash_threshold": 1.0}})
        self.assertEqual(result["stages"][2]["removed"], 2)
        remaining = self.output_records()
        self.assertEqual(len(remaining), 1)
        self.assertTrue(any("Όχι." in r["messages"][1]["content"] for r in remaining))

    def test_grouped_domain_cap_after_dedup(self):
        records = [candidate("a", "Ερώτημα άλφα", group="document", domain="legal"),
                   candidate("b", "Ερώτημα βήτα", group="document", domain="legal"),
                   candidate("c", "Ερώτημα γάμμα", domain="general")]
        result = self.run_records(records, {"domain_caps": {"legal": 1}})
        self.assertEqual(result["domain_cap_removed"], 2)
        self.assertEqual(result["awaiting_api_review"], 1)
        self.assertTrue(result["counts_reconciled"])

    def test_metadata_group_and_original_lineage_both_hold(self):
        records = [candidate(str(i), f"Διαφορετικό ερώτημα {i}", group="g" if i < 3 else "other") for i in range(4)]
        records[3]["metadata"]["source_record_id"] = "0"
        result = self.run_records(records)
        self.assertEqual(len({r["metadata"]["split"] for r in self.output_records()}), 1)
        self.assertTrue(result["leakage"]["passed"])
        for path in (self.root / "output/completed/pre_api").glob("*/messages.jsonl"):
            for line in path.read_text().splitlines():
                self.assertEqual(set(json.loads(line)), {"messages"})

    def test_resume_rejects_tampered_artifacts(self):
        self.run_records([candidate("a", "Ποιο είναι το ζήτημα;")])
        path = self.root / "output/completed/01_ExactSubstrings/survivors.jsonl"
        with path.open("a", encoding="utf-8") as stream:
            stream.write("{}\n")
        with self.assertRaises(DedupError):
            run_dedup([self.root / "input.jsonl"], self.root / "output", {})

    def test_resume_rejects_changed_configuration(self):
        run_dedup([], self.root / "output", {})
        with self.assertRaises(DedupError):
            run_dedup([], self.root / "output", {"dedup": {"seed": 12}})

    def test_resume_reuses_completed_stages_after_split_failure(self):
        with patch("greek_sft.dedup._split", side_effect=RuntimeError("simulated interruption")):
            with self.assertRaises(RuntimeError):
                run_dedup([], self.root / "output", {})
        prior = next((self.root / "output").glob("attempt_*/01_ExactSubstrings/survivors.jsonl"))
        with patch("greek_sft.dedup._stage", side_effect=AssertionError("completed stage repeated")):
            result = run_dedup([], self.root / "output", {})
        final = self.root / "output/completed/01_ExactSubstrings/survivors.jsonl"
        self.assertEqual(prior.stat().st_ino, final.stat().st_ino)
        self.assertEqual(result["awaiting_api_review"], 0)

    def test_completed_directory_symlink_is_rejected(self):
        output = self.root / "output"
        output.mkdir()
        redirected = self.root / "different_run"
        redirected.mkdir()
        (output / "completed").symlink_to(redirected, target_is_directory=True)
        with self.assertRaisesRegex(DedupError, "Symlink"):
            run_dedup([], output, {})
        self.assertEqual(list(redirected.iterdir()), [])

    def test_interrupted_stage_directory_symlink_is_rejected(self):
        with patch("greek_sft.dedup._split", side_effect=RuntimeError("simulated interruption")):
            with self.assertRaises(RuntimeError):
                run_dedup([], self.root / "output", {})
        previous = next((self.root / "output").glob("attempt_*/01_ExactSubstrings"))
        redirected = self.root / "redirected_stage"
        previous.rename(redirected)
        previous.symlink_to(redirected, target_is_directory=True)
        before = (redirected / "survivors.jsonl").read_bytes()
        with self.assertRaisesRegex(DedupError, "Symlink"):
            run_dedup([], self.root / "output", {})
        self.assertEqual((redirected / "survivors.jsonl").read_bytes(), before)

    def test_short_near_duplicates_do_not_cross_splits(self):
        records = [candidate("a", "Το παρόν σύντομο κείμενο αναφέρεται σε ένα συγκεκριμένο τεκμηριωμένο γεγονός.", answer="Πρώτη απάντηση."),
                   candidate("b", "Το παρόν σύντομο κείμενο αναφέρεται σε ένα συγκεκριμένο τεκμηριωμένο γεγονός.", answer="Δεύτερη απάντηση.")]
        result = self.run_records(records, {"dedup": {"minhash_threshold": 0.8, "shingle_words": 1}})
        self.assertEqual(result["leakage"]["detected_near_pairs"], 1)
        self.assertEqual(len({r["metadata"]["split"] for r in self.output_records()}), 1)

    def test_rejects_symlink_escape_and_duplicate_ids(self):
        link = self.root / "escape"
        link.symlink_to("/tmp", target_is_directory=True)
        with self.assertRaises(DedupError):
            run_dedup([], link / "not_created", {})
        with self.assertRaises(DedupError):
            self.run_records([candidate("same", "Πρώτο ερώτημα"), candidate("same", "Δεύτερο ερώτημα")])
        self.assertTrue(list((self.root / "output").glob("attempt_*/failure.json")))

    def local_tokenizer(self, character_level=False):
        from tokenizers import Tokenizer, models, pre_tokenizers
        local = self.root / "local_tokenizer"
        local.mkdir()
        if character_level:
            chars = sorted(set("καλημέραφίλεευχαριστώ"))
            tokenizer = Tokenizer(models.BPE(vocab={"[UNK]": 0, **{c: i + 1 for i, c in enumerate(chars)}}, merges=[], unk_token="[UNK]"))
        else:
            tokenizer = Tokenizer(models.WordLevel(vocab={"[UNK]": 0, "καλή": 1, "μέρα": 2}, unk_token="[UNK]"))
        tokenizer.pre_tokenizer = pre_tokenizers.WhitespaceSplit()
        # Persisted limits must not truncate or pad fertility measurements.
        tokenizer.enable_truncation(max_length=1)
        tokenizer.enable_padding(length=20)
        tokenizer.save(str(local / "tokenizer.json"))
        (local / "tokenizer_config.json").write_text("{}")
        return local

    def fallback_mock(self):
        return patch.dict(sys.modules, {"transformers": SimpleNamespace(
            AutoTokenizer=SimpleNamespace(from_pretrained=Mock(side_effect=AttributeError("synthetic unsupported tokenizer"))))})

    def fertility_fixture(self, local, records):
        path = self.root / "fertility_input.jsonl"
        path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records))
        output = self.root / "fertility"
        output.mkdir()
        settings = _settings({"tokenizer": {"local_path": str(local)}})
        with self.fallback_mock():
            return _fertility([path], settings, output)

    def test_native_tokenizer_fallback_counts_full_text(self):
        local = self.local_tokenizer()
        before = {p.name: p.read_bytes() for p in local.iterdir()}
        result = self.fertility_fixture(local, [candidate("one", "καλή μέρα", answer="καλή")])
        self.assertEqual(result["tokenizer_backend"], "tokenizers.Tokenizer.from_file")
        self.assertEqual(result["loader_errors"], {"transformers.AutoTokenizer": "AttributeError"})
        self.assertEqual((result["words"], result["tokens"], result["examples"]), (3, 3, 1))
        self.assertEqual(result["mean_fertility"], 1.0)
        self.assertFalse(result["packing_blocked"])
        self.assertFalse(result["packing_enabled"])
        self.assertEqual({p.name: p.read_bytes() for p in local.iterdir()}, before)
        self.assertIn("tokenizer.json", result["tokenizer_fingerprint"])

    def test_native_tokenizer_fertility_over_three_blocks_packing(self):
        local = self.local_tokenizer(character_level=True)
        result = self.fertility_fixture(local, [candidate("one", "καλημέρα φίλε", answer="ευχαριστώ")])
        self.assertEqual(result["words"], 3)
        self.assertEqual(result["tokens"], len("καλημέραφίλεευχαριστώ"))
        self.assertGreater(result["mean_fertility"], 3.0)
        self.assertTrue(result["packing_blocked"])
        self.assertIn("vocabulary extension", result["reason"])

    def test_native_tokenizer_empty_input_has_no_measured_fertility(self):
        result = self.fertility_fixture(self.local_tokenizer(), [])
        self.assertEqual(result["status"], "not_applicable")
        self.assertEqual((result["words"], result["tokens"], result["examples"]), (0, 0, 0))
        self.assertIsNone(result["mean_fertility"])
        self.assertTrue(result["packing_blocked"])

    def test_tokenizer_fingerprint_change_blocks_resume(self):
        local = self.local_tokenizer()
        config = {"tokenizer": {"local_path": str(local)}}
        with self.fallback_mock():
            run_dedup([], self.root / "output", config)
        request = json.loads((self.root / "output/request.json").read_text())
        self.assertIn("tokenizer.json", request["settings"]["tokenizer_snapshot"]["files"])
        (local / "tokenizer_config.json").write_text('{"changed_fixture":true}')
        with self.assertRaisesRegex(DedupError, "different inputs/configuration"):
            run_dedup([], self.root / "output", config)

    def test_tokenizer_changes_after_request_are_rejected(self):
        local = self.local_tokenizer()
        settings = _settings({"tokenizer": {"local_path": str(local)}})
        (local / "tokenizer_config.json").write_text('{"changed_fixture":true}')
        output = self.root / "fertility"
        output.mkdir()
        with self.assertRaisesRegex(DedupError, "tokenizer assets"):
            _fertility([], settings, output)

    def test_exhaustive_prefix_join_matches_brute_force(self):
        rng = random.Random(24)
        base = ["όρος" + chr(0x3B1 + i // 24) + chr(0x3B1 + i % 24) for i in range(150)]
        records = []
        for i in range(20):
            words = list(base)
            for position in rng.sample(range(150), i % 7):
                words[position] = "παραλλαγή" + chr(0x3B1 + i)
            records.append(candidate(str(i), " ".join(words), answer="Απάντηση " + chr(0x3B1 + i)))
        path = self.root / "pairs.jsonl"
        path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records))
        db = _database(self.root / "pairs.sqlite")
        _load(db, [path])
        db.execute("CREATE TABLE groups(id TEXT PRIMARY KEY,parent TEXT NOT NULL)")
        db.executemany("INSERT INTO groups VALUES(?,?)", ((r["id"], r["id"]) for r in records))
        _near_groups(db, _settings({}))
        actual = {tuple(row) for row in db.execute("SELECT left_id,right_id FROM near_pairs")}
        texts = dict(db.execute("SELECT id,text FROM records"))
        expected = {tuple(sorted((a, b))) for a, b in itertools.combinations(texts, 2) if _jaccard(_shingles(texts[a], 5), _shingles(texts[b], 5)) >= 0.9}
        self.assertEqual(actual, expected)
        self.assertGreater(len(actual), 0)
        db.close()


if __name__ == "__main__":
    unittest.main()
