"""A changed excluded Git index never becomes a fabricated unchanged source."""
import contextlib
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from greek_sft import inventory
from greek_sft.audit import audit_inventory
from greek_sft.contamination import check_contamination
from greek_sft.core import atomic_json, checkpoint_complete, digest
from greek_sft.dedup import run_dedup
from greek_sft.integrity import verify_source_hashes
from greek_sft.reporting import CHECKPOINTS, create_audited_release
from greek_sft.review import estimate_review
from greek_sft.source_io import open_source_readonly
from greek_sft.tasks import run_generation, run_plans, run_validation

ROOT = Path(__file__).resolve().parents[1]


@contextlib.contextmanager
def source_exclusion_fixture():
    """Real synthetic passes, reusable while their temporary evidence exists."""
    with tempfile.TemporaryDirectory(prefix="source_exclusion_e2e_", dir=ROOT / "runtime/tmp") as temporary:
        work = Path(temporary)
        source, run = work / "source", work / "run"
        source.mkdir()
        run.mkdir()
        git = source / "greek_training/.git"
        git.mkdir(parents=True)
        index = git / "index"
        index.write_bytes(b"old-index")
        historical = git / "known.jsonl"
        historical.write_text('{"text":"Παλιό τεκμήριο μεταδεδομένων."}\n', encoding="utf-8")
        family = source / "skroutz_shop_reviews_sentiment_analysis"
        family.mkdir()
        row = {"text": "Το κατάστημα παρέδωσε έγκαιρα την παραγγελία και η εξυπηρέτηση ήταν εξαιρετική.", "label": "Positive"}
        candidate_source = family / "reviews.jsonl"
        candidate_source.write_text(json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")
        candidate_hash = hashlib.sha256(candidate_source.read_bytes()).hexdigest()
        config = {"workers": 1, "inventory_commit_files": 1, "batch_size": 1, "seed": 1729,
                  "max_record_bytes": 1024 * 1024,
                  "validation": {"schema_path": str(ROOT / "schemas/canonical-sft.schema.json")},
                  "dedup": {"seed": 1729}, "tokenizer": {"local_path": None}, "evaluation": {}}
        atomic_json(run / "configuration.json", config)
        checkpoints = {n: run / name for n, name in CHECKPOINTS.items()}
        checkpoint = checkpoints[1]
        checkpoint.mkdir()
        with contextlib.closing(inventory._connect(checkpoint / "inventory_shard_00.sqlite")) as db:
            for source_file in (index, historical):
                relative = str(source_file.relative_to(source))
                before = source_file.stat()
                report = inventory._scan(source_file, relative, before, db, config)
                db.execute("INSERT INTO files VALUES(?,?,?,1)",
                           (relative, inventory._json(inventory._fingerprint(before)), inventory._json(report)))
            db.commit()
            cached = list(db.execute("SELECT * FROM files ORDER BY relative_path"))
            ranges = list(db.execute("SELECT * FROM record_ranges ORDER BY relative_path,first_record"))
        atomic_json(checkpoint / "inventory_state.json", {"version": inventory.VERSION, "workers": 1,
                    "source_root": str(source), "config_sha256": digest(config)})
        original_index_hash = hashlib.sha256(index.read_bytes()).hexdigest()
        index.write_bytes(b"new-index")
        (git / "added.jsonl").write_text('{"added":true}\n', encoding="utf-8")
        incident_path = "integrity_incidents/test_changed_git/incident.json"
        incident = {"run_id": run.name, "status": "halted_source_integrity_failure", "failed_pass": 1,
                    "source_file": "greek_training/.git/index", "baseline_sha256": original_index_hash,
                    "observed_sha256": hashlib.sha256(index.read_bytes()).hexdigest(), "sha256_matches": False,
                    "baseline_size_bytes": 9, "observed_size_bytes": 9, "release_ready": False}
        atomic_json(run / incident_path, incident)
        atomic_json(run / "source_exclusion_amendment.json", {
            "version": 1, "run_id": run.name, "authorized_at": "2026-09-07T15:15:00+00:00",
            "user_instruction": "continue",
            "approved_question": "May I exclude `greek_training/.git/` from source coverage and resume with that exception documented?",
            "excluded_source_roots": ["greek_training/.git"],
            "mode": "exclude_subtree_from_current_source_coverage",
            "base_inventory_config_sha256": digest(config), "record_scope_amendment_sha256": None,
            "integrity_incident_path": incident_path,
            "integrity_incident_sha256": hashlib.sha256((run / incident_path).read_bytes()).hexdigest(),
            "preserve_historical_inventory": True, "full_original_source_integrity_claim_allowed": False,
            "current_excluded_coverage": "unknown"})

        def guarded_read(path, *args, **kwargs):
            if Path(path).is_relative_to(git):
                raise AssertionError("excluded Git source was opened")
            return open_source_readonly(path, *args, **kwargs)

        with patch.object(inventory, "open_source_readonly", guarded_read), \
                patch("greek_sft.integrity.open_source_readonly", guarded_read):
            results = {"1": inventory.run_inventory(source, checkpoint, config)}
            checkpoint_complete(ROOT, checkpoint, results["1"], config)
            inventory_audit = audit_inventory(checkpoint, run / "audits/inventory")
            assert inventory_audit["identified_accounting_passed"]
            results["2"] = run_plans(source, checkpoint, checkpoints[2], config)
            checkpoint_complete(ROOT, checkpoints[2], results["2"], config)
            results["3"] = run_generation(source, checkpoint, checkpoints[2], checkpoints[3], config)
            checkpoint_complete(ROOT, checkpoints[3], results["3"], config)
            results["4"] = run_validation(checkpoints[3], checkpoints[4], config)
            results["4"]["contamination"] = check_contamination(checkpoints[4] / "validated.jsonl", ROOT,
                checkpoints[4] / "contamination", config)
            checkpoint_complete(ROOT, checkpoints[4], results["4"], config)
            results["5"] = run_dedup([checkpoints[4] / "contamination/clean_candidates.jsonl"], checkpoints[5], config)
            verified = verify_source_hashes(source, checkpoint, checkpoints[5] / "source_verification", config)
            results["5"]["source_verification"] = verified
            checkpoint_complete(ROOT, checkpoints[5], results["5"], config)
            paths = sorted((checkpoints[5] / "completed/pre_api").glob("*/canonical.jsonl"))
            review = estimate_review(paths, {"enabled": False})
            yield locals()


class SourceExclusionEndToEndTests(unittest.TestCase):
    def test_five_passes_preserve_changed_git_baseline_and_report_scoped_integrity(self):
        with source_exclusion_fixture() as state:
            run, results, verified, inventory_audit = (state[key] for key in ("run", "results", "verified", "inventory_audit"))
            checkpoint, cached, ranges = (state[key] for key in ("checkpoint", "cached", "ranges"))
            candidate_source, candidate_hash, index, incident_path, incident = (state[key] for key in (
                "candidate_source", "candidate_hash", "index", "incident_path", "incident"))
            final = create_audited_release(run, results, state["review"], verified, inventory_audit)
            self.assertTrue(final["accounting_passed"], final)
            report = json.loads((run / final["report_path"]).read_text())
            self.assertEqual(report["measured"]["source_files"], 3)
            self.assertEqual(report["measured"]["identified_source_records"], 2)
            self.assertFalse(report["gates"]["source_hashes_unchanged"]["passed"])
            self.assertTrue(report["gates"]["scoped_source_hashes_unchanged"]["passed"])
            self.assertFalse(final["release_ready"])
            self.assertEqual(report["source_exclusion_amendment"], results["1"]["source_exclusion_amendment"])
            with contextlib.closing(sqlite3.connect((checkpoint / "inventory_shard_00.sqlite").as_uri() + "?mode=ro", uri=True)) as db:
                self.assertEqual(list(db.execute("SELECT * FROM files WHERE relative_path LIKE 'greek_training/.git/%' ORDER BY relative_path")), cached)
                self.assertEqual(list(db.execute("SELECT * FROM record_ranges WHERE relative_path LIKE 'greek_training/.git/%' ORDER BY relative_path,first_record")), ranges)
            self.assertEqual(hashlib.sha256(candidate_source.read_bytes()).hexdigest(), candidate_hash)
            self.assertEqual(index.read_bytes(), b"new-index")
            self.assertEqual(json.loads((run / incident_path).read_text()), incident)


if __name__ == "__main__":
    unittest.main()
