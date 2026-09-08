"""A stopped pipeline must retain evidence and never advertise stale progress."""
import importlib.util
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from greek_sft.core import atomic_json, sha256_file
from greek_sft.inventory import SourceChangedError

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pipeline_failure_test_driver", ROOT / "scripts/run_pipeline.py")
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


class DriverFailureStateTests(unittest.TestCase):
    def test_integrity_failure_stops_state_and_preserves_predecessor(self):
        with tempfile.TemporaryDirectory(prefix="test_failure_", dir=ROOT / "runs") as temporary:
            run = Path(temporary)
            previous = {"run_id": run.name, "status": "running", "source_immutable": True,
                        "active_pass": 5, "passes": {"1": "complete"}}
            atomic_json(run / "state.json", previous)
            DRIVER.record_failure(run.name, SourceChangedError("source_integrity_failed:source_hash_or_size_changed"))
            state = json.loads((run / "state.json").read_text())
            self.assertEqual(state["status"], "halted_source_integrity_failure")
            self.assertFalse(state["source_immutable"])
            self.assertFalse(state["full_original_source_integrity"])
            self.assertEqual(state["scoped_source_integrity"], "failed")
            self.assertFalse(state["release_ready"])
            self.assertEqual(state["passes"], previous["passes"])
            artifact = run / state["failure_artifact"]
            self.assertEqual(json.loads(artifact.read_text()), state)
            self.assertEqual(json.loads((artifact.parent / "previous_state.json").read_text()), previous)
            for name, checksum in json.loads((artifact.parent / "checksums.json").read_text()).items():
                self.assertEqual(sha256_file(artifact.parent / name), checksum)

    def test_repeated_failures_keep_history_and_omit_exception_payloads(self):
        with tempfile.TemporaryDirectory(prefix="test_failure_", dir=ROOT / "runs") as temporary:
            run = Path(temporary)
            previous = {"run_id": run.name, "status": "running", "passes": {}}
            atomic_json(run / "state.json", previous)
            sensitive_payload = "TEST_ONLY_PRIVATE_EXCEPTION_PAYLOAD"
            DRIVER.record_failure(run.name, ValueError(sensitive_payload))
            first_state = json.loads((run / "state.json").read_text())
            first_bytes = (run / first_state["failure_artifact"]).read_bytes()
            DRIVER.record_failure(run.name, ValueError(sensitive_payload))
            second_state = json.loads((run / "state.json").read_text())
            self.assertEqual(second_state["status"], "failed")
            self.assertNotEqual(first_state["failure_artifact"], second_state["failure_artifact"])
            self.assertEqual((run / first_state["failure_artifact"]).read_bytes(), first_bytes)
            second_previous = run / second_state["failure_artifact"]
            self.assertEqual(json.loads((second_previous.parent / "previous_state.json").read_text()), first_state)
            self.assertNotIn(sensitive_payload, "".join(p.read_text() for p in run.rglob("*.json")))

    def test_generic_exception_preserves_explicit_validation_halt(self):
        with tempfile.TemporaryDirectory(prefix="test_failure_", dir=ROOT / "runs") as temporary:
            run = Path(temporary)
            previous = {"run_id": run.name, "status": "halted_excessive_deterministic_failure_rate",
                        "passes": {"1": "complete", "2": "complete", "3": "complete"}, "active_pass": 4}
            atomic_json(run / "state.json", previous)
            DRIVER.record_failure(run.name, RuntimeError("validation gate blocked"))
            state = json.loads((run / "state.json").read_text())
            self.assertEqual(state["status"], previous["status"])
            self.assertEqual(state["passes"], previous["passes"])
            DRIVER.record_failure(run.name, SourceChangedError("changed"))
            state = json.loads((run / "state.json").read_text())
            self.assertEqual(state["status"], "halted_source_integrity_failure")

    def test_cli_omits_arbitrary_exception_payload_from_logs_and_artifacts(self):
        with tempfile.TemporaryDirectory(prefix="test_failure_", dir=ROOT / "runs") as temporary:
            run = Path(temporary)
            payload = "TEST_ONLY_PRIVATE_EXCEPTION_PAYLOAD"
            stderr = io.StringIO()
            with patch.object(DRIVER, "run_pipeline", side_effect=ValueError(payload)), contextlib.redirect_stderr(stderr):
                result = DRIVER.main(["--run-id", run.name, "--through", "5"])
            self.assertEqual(result, 1)
            self.assertNotIn(payload, stderr.getvalue())
            self.assertEqual(json.loads(stderr.getvalue())["reason"], "pipeline_execution_failed")
            self.assertNotIn(payload, "".join(p.read_text() for p in run.rglob("*.json")))

    def test_source_failure_before_pass_six_is_never_labelled_api_gate(self):
        with tempfile.TemporaryDirectory(prefix="test_failure_", dir=ROOT / "runs") as temporary:
            run = Path(temporary)
            stderr = io.StringIO()
            with patch.object(DRIVER, "run_pipeline", side_effect=SourceChangedError("private-source-reference")), contextlib.redirect_stderr(stderr):
                result = DRIVER.main(["--run-id", run.name, "--through", "6"])
            self.assertEqual(result, 1)
            self.assertEqual(json.loads(stderr.getvalue())["reason"], "source_integrity_failure")
            self.assertEqual(json.loads((run / "state.json").read_text())["status"], "halted_source_integrity_failure")
            self.assertEqual(DRIVER.safe_failure_reason(DRIVER.Pass6ApprovalRequired(), 6), "pass_6_approval_gate_not_satisfied")


if __name__ == "__main__":
    unittest.main()
