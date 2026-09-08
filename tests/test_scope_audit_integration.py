"""A user record-scan exclusion must remain visible through all five passes."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import zstandard

from greek_sft.audit import audit_inventory
from greek_sft.contamination import check_contamination
from greek_sft.core import atomic_json, checkpoint_complete, digest
from greek_sft.dedup import run_dedup
from greek_sft.integrity import verify_source_hashes
from greek_sft.inventory import run_inventory
from greek_sft.reporting import CHECKPOINTS, create_audited_release
from greek_sft.review import estimate_review
from greek_sft.tasks import run_generation, run_plans, run_validation

ROOT = Path(__file__).resolve().parents[1]


class ScopeAuditIntegrationTests(unittest.TestCase):
    def test_excluded_rows_remain_unassessed_but_every_file_is_rehashed(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "runtime/tmp") as temporary:
            work = Path(temporary)
            source, run = work / "source", work / "run"
            source.mkdir()
            run.mkdir()
            for family in ("skroutz_shop_reviews_sentiment_analysis", "greek_training", "greek_training_temp"):
                (source / family).mkdir()
            row = {"text": "Το κατάστημα παρέδωσε έγκαιρα την παραγγελία και η εξυπηρέτηση ήταν εξαιρετική.", "label": "Positive"}
            encoded = (json.dumps(row, ensure_ascii=False) + "\n").encode()
            (source / "skroutz_shop_reviews_sentiment_analysis/records.jsonl").write_bytes(encoded)
            (source / "greek_training_temp/records.jsonl").write_bytes(encoded)
            excluded = source / "greek_training/records.jsonl.zst"
            excluded.write_bytes(zstandard.ZstdCompressor(write_checksum=True).compress(encoded + b"not-json\n"))
            before = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in source.rglob("*") if p.is_file()}
            config = {"workers": 1, "batch_size": 1, "seed": 1729, "max_record_bytes": 1024 * 1024,
                      "validation": {"schema_path": str(ROOT / "schemas/canonical-sft.schema.json")},
                      "dedup": {"seed": 1729}, "tokenizer": {"local_path": None}, "evaluation": {}}
            atomic_json(run / "configuration.json", config)
            atomic_json(run / "inventory_scope_amendment.json", {
                "version": 1, "run_id": run.name, "authorized_at": "2026-09-07T13:28:00+00:00",
                "user_instruction": "go past greek training", "excluded_record_roots": ["greek_training"],
                "deferred_hash_roots": ["greek_training"], "mode": "hash_only_for_unscanned_files",
                "original_source_hash_requirement_preserved": True, "prior_scanned_records_preserved": True,
                "base_inventory_config_sha256": digest(config),
                "record_coverage_limitation": "Skipped records are unassessed; zero is an identified-record lower bound."})
            checkpoints = {n: run / name for n, name in CHECKPOINTS.items()}
            results = {"1": run_inventory(source, checkpoints[1], config)}
            checkpoint_complete(ROOT, checkpoints[1], results["1"], config)
            inventory_audit = audit_inventory(checkpoints[1], run / "audits/inventory")
            self.assertTrue(inventory_audit["identified_accounting_passed"])
            self.assertFalse(inventory_audit["complete_semantic_record_coverage"])
            inventory_rows = [json.loads(line) for line in (checkpoints[1] / "source_manifest.jsonl").read_text().splitlines()]
            skipped = next(item for item in inventory_rows if item["relative_path"].startswith("greek_training/"))
            self.assertEqual(skipped["record_count"], 0)
            self.assertFalse(skipped["record_boundary_complete"])
            self.assertEqual(skipped["sha256"], before["greek_training/records.jsonl.zst"])
            results["2"] = run_plans(source, checkpoints[1], checkpoints[2], config)
            checkpoint_complete(ROOT, checkpoints[2], results["2"], config)
            results["3"] = run_generation(source, checkpoints[1], checkpoints[2], checkpoints[3], config)
            checkpoint_complete(ROOT, checkpoints[3], results["3"], config)
            results["4"] = run_validation(checkpoints[3], checkpoints[4], config)
            results["4"]["contamination"] = check_contamination(checkpoints[4] / "validated.jsonl", ROOT, checkpoints[4] / "contamination", config)
            checkpoint_complete(ROOT, checkpoints[4], results["4"], config)
            results["5"] = run_dedup([checkpoints[4] / "contamination/clean_candidates.jsonl"], checkpoints[5], config)
            verified = verify_source_hashes(source, checkpoints[1], checkpoints[5] / "source_verification", config)
            results["5"]["source_verification"] = verified
            checkpoint_complete(ROOT, checkpoints[5], results["5"], config)
            candidates = sorted((checkpoints[5] / "completed/pre_api").glob("*/canonical.jsonl"))
            final = create_audited_release(run, results, estimate_review(candidates, {"enabled": False}), verified, inventory_audit)
            self.assertTrue(final["accounting_passed"], final)
            report_path = run / final["report_path"]
            report = json.loads(report_path.read_text())
            self.assertEqual(report["measured"]["source_files"], 3)
            self.assertEqual(report["measured"]["identified_source_records"], 2)
            self.assertEqual(report["measured"]["unresolved_boundary_files"], 1)
            self.assertFalse(report["gates"]["complete_semantic_record_coverage"]["passed"])
            self.assertTrue(report["gates"]["source_hashes_unchanged"]["passed"])
            self.assertFalse(final["release_ready"])
            self.assertEqual(report["inventory_scope_amendment"], results["1"]["inventory_scope_amendment"])
            self.assertEqual(json.loads((report_path.parent / "inventory_scope_amendment_reference.json").read_text()), report["inventory_scope_amendment"])
            self.assertIn("unassessed", (report_path.parent / "provenance_report.md").read_text())
            after = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in source.rglob("*") if p.is_file()}
            self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
