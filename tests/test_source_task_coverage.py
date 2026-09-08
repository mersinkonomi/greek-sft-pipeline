"""Source-specific annotation tasks, preserved planning, and schema dispatch."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from greek_sft import tasks

ROOT = Path(__file__).resolve().parents[1]
NEWS = {
    "id": "123456", "url": "https://www.amna.gr/home/article/123456/",
    "title": "Νέα ψηφιακή υπηρεσία για την πρόσβαση σε επιστημονικά δεδομένα",
    "text": "Μια νέα ψηφιακή υπηρεσία διευκολύνει την πρόσβαση σε επιστημονικά δεδομένα. Οι χρήστες μπορούν να αναζητούν δημοσιευμένες μελέτες και να συγκρίνουν τις διαθέσιμες πληροφορίες. Η υπηρεσία οργανώνει τα δεδομένα ανά θεματική ενότητα και εξηγεί πώς μπορούν να χρησιμοποιηθούν.",
    "category": "Επιστήμη",
}
RESOURCE = {
    "title": "ΓΕΩΜΕΤΡΙΚΑ ΣΧΗΜΑΤΑ",
    "text": "Το εκπαιδευτικό υλικό παρουσιάζει βασικά γεωμετρικά σχήματα και προτείνει δραστηριότητες παρατήρησης. Τα παιδιά συγκρίνουν τις πλευρές των σχημάτων και εντοπίζουν κοινά χαρακτηριστικά μέσα από παραδείγματα. Η δραστηριότητα υποστηρίζει τη διερεύνηση και τη συζήτηση στην τάξη.",
    "url": "http://photodentro.edu.gr/aggregator/lo/photodentro-lor-8521-12345",
    "classification": {"thematic_area": ["Μαθηματικά > Γεωμετρία > Γεωμετρικά σχήματα"], "learning_object_type": "διερεύνηση"},
    "audience": {"educational_levels": ["δημοτικό"], "age_range": "6 - 12", "target_audience": ["μαθητής/τρια"]},
    "notes": "01/01/2020", "keywords": ["σχήματα"],
}


class SourceTaskConstructionTests(unittest.TestCase):
    def test_news_uses_complete_plain_text_and_exact_six_class_annotation(self):
        built, reason = tasks.construct("AMNA-press", {**NEWS, "text_markdown": "irrelevant alternate text"})
        self.assertIsNone(reason)
        fields, prompt, answer, _ = built
        self.assertEqual(answer, NEWS["category"])
        self.assertIn(NEWS["title"], prompt)
        self.assertTrue(prompt.endswith(NEWS["text"]))
        self.assertNotIn("text_markdown", fields)
        span = tasks._grounding_span("AMNA-press", prompt, fields)
        self.assertTrue(prompt[span["start"]:span["end"]].startswith(NEWS["title"]))
        self.assertNotIn("Διάλεξε", prompt[span["start"]:span["end"]])
        for category in tasks.NEWS_CATEGORIES:
            self.assertEqual(tasks.construct("AMNA-press", {**NEWS, "category": category})[0][2], category)

    def test_news_unknown_missing_and_wrong_typed_labels_are_rejected(self):
        self.assertEqual(tasks.construct("AMNA-press", {**NEWS, "category": "Αθλητισμός"})[1], "unsupported_news_category")
        for category in (None, 1, ["Επιστήμη"], ""):
            self.assertEqual(tasks.construct("AMNA-press", {**NEWS, "category": category})[1], "missing_or_ambiguous_required_field")

    def test_news_does_not_fallback_to_markdown_or_empty_clean_schema(self):
        record = {key: value for key, value in NEWS.items() if key != "text"}
        record.update(text_clean="", text_markdown=NEWS["text"])
        self.assertEqual(tasks.construct("AMNA-press", record)[1], "missing_or_ambiguous_required_field")

    def test_news_id_must_match_url_and_variants_share_article_group(self):
        first = tasks.construct("AMNA-press", NEWS)[0]
        second = tasks.construct("AMNA-press", {**NEWS, "text": NEWS["text"] + " Η παρουσίαση περιλαμβάνει επιπλέον πληροφορίες."})[0]
        self.assertEqual(first[3], second[3])
        for bad in ({"id": "987654"}, {"url": "https://example.org/123456"}, {"id": ""}):
            self.assertIsNotNone(tasks.construct("AMNA-press", {**NEWS, **bad})[1])

    def test_resource_preserves_nested_exact_annotations_without_prompt_leakage(self):
        built, reason = tasks.construct("Photodentro_all_documents", RESOURCE)
        self.assertIsNone(reason)
        fields, prompt, answer, _ = built
        self.assertEqual(json.loads(answer), {
            "θεματικές_περιοχές": RESOURCE["classification"]["thematic_area"],
            "εκπαιδευτικές_βαθμίδες": RESOURCE["audience"]["educational_levels"],
        })
        self.assertEqual(fields["classification"], {"thematic_area": RESOURCE["classification"]["thematic_area"]})
        self.assertEqual(fields["audience"], {"educational_levels": ["δημοτικό"]})
        for key in ("notes", "keywords", "age_range", "target_audience"):
            self.assertNotIn(key, fields)
        self.assertIn(RESOURCE["title"], prompt)  # No invented title accents.
        self.assertTrue(prompt.endswith(RESOURCE["text"]))
        self.assertNotIn(RESOURCE["classification"]["thematic_area"][0], prompt)
        self.assertNotIn("01/01/2020", prompt)
        rebuilt, reason = tasks.construct("Photodentro_all_documents", fields)
        self.assertIsNone(reason)
        self.assertEqual(rebuilt, built)

    def test_resource_rejects_missing_or_wrong_nested_schema(self):
        for change in ({"classification": []}, {"classification": {"thematic_area": "Μαθηματικά"}},
                       {"audience": {"educational_levels": "δημοτικό"}}, {"classification": {"thematic_area": []}},
                       {"audience": {"educational_levels": [1]}}):
            with self.subTest(change=change):
                self.assertEqual(tasks.construct("Photodentro_all_documents", {**RESOURCE, **change})[1], "missing_or_ambiguous_annotation_list")
        self.assertEqual(tasks.construct("Photodentro_all_documents", {"title": RESOURCE["title"], "url": RESOURCE["url"]})[1], "missing_or_ambiguous_required_field")

    def test_resource_rejects_unknown_levels_and_malformed_hierarchies(self):
        record = copy.deepcopy(RESOURCE)
        record["audience"]["educational_levels"] = ["πανεπιστήμιο"]
        self.assertEqual(tasks.construct("Photodentro_all_documents", record)[1], "unsupported_educational_level")
        for area in ("Mathematics > Geometry", "Μαθηματικά > ", "Μαθηματικά >> Γεωμετρία"):
            record = copy.deepcopy(RESOURCE)
            record["classification"]["thematic_area"] = [area]
            self.assertEqual(tasks.construct("Photodentro_all_documents", record)[1], "invalid_or_non_greek_thematic_annotation")
        record = copy.deepcopy(RESOURCE)
        record["audience"]["educational_levels"] = ["δημοτικό", "δημοτικό"]
        self.assertEqual(tasks.construct("Photodentro_all_documents", record)[1], "duplicate_annotation_label")

    def test_resource_retains_array_order_and_groups_object_variants(self):
        record = copy.deepcopy(RESOURCE)
        record["audience"]["educational_levels"] = ["γυμνάσιο", "δημοτικό"]
        first = tasks.construct("Photodentro_all_documents", record)[0]
        self.assertEqual(json.loads(first[2])["εκπαιδευτικές_βαθμίδες"], ["γυμνάσιο", "δημοτικό"])
        record["text"] += " Το υλικό περιλαμβάνει πρόσθετα παραδείγματα."
        record["url"] = record["url"].replace("http:", "https:")
        self.assertEqual(first[3], tasks.construct("Photodentro_all_documents", record)[0][3])
        record["url"] += "?unknown=1"
        self.assertEqual(tasks.construct("Photodentro_all_documents", record)[1], "learning_object_identity_or_url_schema_unverified")

    def test_new_tasks_reject_risks_short_inputs_and_truncation_before_emission(self):
        for family, original in (("AMNA-press", NEWS), ("Photodentro_all_documents", RESOURCE)):
            with self.subTest(family=family):
                self.assertEqual(tasks.construct(family, original, max_chars=30)[1], "whole_field_exceeds_limit_no_truncation")
                self.assertIsNotNone(tasks.construct(family, {**original, "text": "Σύντομο ελληνικό κείμενο χωρίς επαρκές περιεχόμενο."})[1])
                self.assertIn("contact_or_financial_identifier", tasks.construct(family, {**original, "text": original["text"] + " fixture@example.com"})[1])
        record = copy.deepcopy(RESOURCE)
        record["classification"]["thematic_area"] = ["Μαθηματικά fixture@example.com"]
        self.assertIn("contact_or_financial_identifier", tasks.construct("Photodentro_all_documents", record)[1])
        self.assertEqual(tasks.construct("AMNA-press", {**NEWS, "text": "Κατηγορία: Επιστήμη\n" + NEWS["text"]})[1], "source_annotation_label_leakage")
        self.assertEqual(tasks.construct("Photodentro_all_documents", {**RESOURCE, "text": "Εκπαιδευτική βαθμίδα: δημοτικό\n" + RESOURCE["text"]})[1], "source_annotation_label_leakage")

    def test_all_catalogued_families_have_explicit_design_or_adapter(self):
        families = {json.loads(path.read_text())["family"] for path in (ROOT / "configs" / "sources").glob("*.json")}
        self.assertEqual(len(families), 77)
        self.assertFalse(families - (set(tasks.SOURCE_DESIGN) | tasks.ANCIENT_FAMILIES | set(tasks.SUPPORTED)))
        for family in families:
            plan = tasks.make_plan(family)
            self.assertTrue(plan["task_design_is_not_source_unsuitability_finding"])
            self.assertNotIn(plan["reason"], {"no_verified_nontrivial_grounded_task", "catalogued_source_requires_source_specific_adapter_design", "uncatalogued_schema_requires_manual_design"})


class SourceTaskPassTests(unittest.TestCase):
    def setUp(self):
        parent = ROOT / "runtime" / "source_task_coverage_tests"
        parent.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="case_", dir=parent)
        self.root = Path(self.temporary.name)
        self.source, self.inventory = self.root / "source", self.root / "inventory"
        self.source.mkdir(); self.inventory.mkdir()
        self.plans, self.raw, self.valid = (self.root / name for name in ("plans", "raw", "valid"))
        self.config = {"canonical_schema_path": str(ROOT / "schemas" / "canonical-sft.schema.json")}
        self.manifest = []
        self.originals = {}

    def tearDown(self):
        self.temporary.cleanup()

    def add_file(self, family, relative, records):
        path = self.source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = b"".join((json.dumps(row, ensure_ascii=False) + "\n").encode() for row in records)
        path.write_bytes(raw)
        self.originals[path] = raw
        self.manifest.append({"family": family, "relative_path": relative, "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw), "format": "jsonl", "encoding": "utf-8", "record_count": len(records),
            "record_boundary_complete": True, "status": "quarantined", "reason": "license_unverified"})

    def plan(self, catalog=None):
        if catalog is not None:
            (self.source / "DATA_SOURCES.json").write_text(json.dumps(catalog))
        (self.inventory / "source_manifest.jsonl").write_text("".join(json.dumps(row) + "\n" for row in self.manifest))
        return tasks.run_plans(self.source, self.inventory, self.plans, self.config)

    def generate(self):
        return tasks.run_generation(self.source, self.inventory, self.plans, self.raw, self.config)

    def test_new_tasks_stream_and_validate_with_permissions_still_blocked(self):
        self.add_file("AMNA-press", "AMNA-press/AMNA-press.jsonl", [NEWS, {**NEWS, "category": "unknown"}])
        self.add_file("Photodentro_all_documents", "Photodentro_all_documents/Photodentro_all_documents.jsonl", [RESOURCE, {"title": "Ελλιπές"}])
        self.plan()
        result = self.generate()
        self.assertEqual(result["source_records"], 4)
        self.assertEqual(result["classified_records"], 4)
        self.assertEqual(result["candidates"], 2)
        raw_hashes = {path: tasks._file_hash(path) for path in self.raw.glob("shards/*/candidates.jsonl")}
        checked = tasks.run_validation(self.raw, self.valid, self.config)
        self.assertEqual(checked["schema_passed"], 2)
        self.assertEqual(checked["deterministic_content_checks_passed"], 2)
        self.assertEqual(checked["quarantined"], 2)
        self.assertEqual(checked["awaiting_api_review"], 0)
        self.assertEqual(raw_hashes, {path: tasks._file_hash(path) for path in raw_hashes})
        self.assertEqual(self.originals, {path: path.read_bytes() for path in self.originals})
        self.assertEqual(result, self.generate())
        for path in self.raw.glob("shards/*/candidates.jsonl"):
            candidate = next(tasks._rows(path))
            evidence = next(tasks._rows(path.with_name("evidence.jsonl")))
            candidate["messages"][2]["content"] = "Αλλοιωμένη απάντηση"
            evidence["candidate_sha256"] = tasks._hash(candidate)
            self.assertIn("answer_not_exactly_grounded", tasks.validate_candidate(candidate, evidence)[0])

    def test_generation_preserves_catalogue_derived_ancient_plan_reason(self):
        family = "synthetic_ancient_catalogue_family"
        self.add_file(family, family + "/records.jsonl", [{"text": "Συνθετικό κείμενο"}])
        self.plan({family: {"variety": "ancient", "one_line": "Synthetic ancient source fixture", "schema_md": "text: string"}})
        prior = next(tasks._rows(self.plans / "source_dispositions.jsonl"))
        self.assertEqual(prior["reason"], "ancient_language_outside_native_modern_greek_scope")
        # Generation must use checked stored plans rather than call make_plan()
        # without the catalogue and lose this source-specific decision.
        with mock.patch.object(tasks, "make_plan", side_effect=AssertionError("unexpected replanning")):
            result = self.generate()
        after = next(tasks._rows(self.raw / "source_dispositions.jsonl"))
        self.assertEqual(after["reason"], prior["reason"])
        self.assertEqual(after["plan_reason"], prior["reason"])
        self.assertEqual(result["noncandidate_reasons"], {prior["reason"]: 1})

    def test_mitos_dispatch_keeps_inventory_identity_and_distinct_blockers(self):
        for relative in ("mitos_all/mitos_all.jsonl", "mitos_all/mitos_all_rendered.jsonl", "mitos_all/unknown.jsonl"):
            self.add_file("mitos_all", relative, [{"text": "Συνθετικό κείμενο"}])
        self.plan()
        before = list(tasks._rows(self.plans / "source_dispositions.jsonl"))
        self.assertEqual([row["family"] for row in before], ["mitos_all"] * 3)
        self.assertEqual([row["task_specification_family"] for row in before], ["mitos_all", "mitos_all_rendered", None])
        self.assertEqual([row["schema_variant"] for row in before], ["raw_api_response", "rendered_procedure", "unmapped"])
        self.assertEqual(before[0]["reason"], "mitos_raw_nested_procedures_require_verified_field_task_adapter")
        self.assertEqual(before[1]["reason"], "mitos_rendered_procedures_require_raw_alignment_and_task_adapter")
        self.assertEqual(before[2]["reason"], "mitos_unmapped_file_requires_schema_review")
        self.assertTrue(all(row["status"] == "quarantined" for row in before))
        self.assertEqual(self.generate()["candidates"], 0)
        after = list(tasks._rows(self.raw / "source_dispositions.jsonl"))
        self.assertEqual([row["reason"] for row in before], [row["reason"] for row in after])
        self.assertEqual([row["schema_variant"] for row in before], [row["schema_variant"] for row in after])
        rules = tasks.make_plan("mitos_all")["file_schema_dispatch"]
        self.assertEqual(rules[0]["required_fields"]["data"], "object")
        self.assertEqual(rules[1]["required_fields"]["mitos_id"], "string")
        self.assertTrue(all(rule["adapter"] is None and "pending" in rule["schema_validation_status"] for rule in rules))


if __name__ == "__main__":
    unittest.main()
