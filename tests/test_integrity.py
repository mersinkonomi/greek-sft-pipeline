import contextlib
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest import mock

from greek_sft import integrity
from greek_sft.core import PIPELINE_ROOT
from greek_sft.inventory import SourceChangedError, _fingerprint


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        root = PIPELINE_ROOT / "runtime" / "integrity_tests"
        root.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="case_", dir=root)
        self.root = Path(self.temporary.name)
        self.source = self.root / "synthetic_source"
        self.checkpoint = self.root / "inventory"
        self.output = self.root / "verification"
        self.source.mkdir()
        self.checkpoint.mkdir()
        self.config = {"workers": 2}

    def tearDown(self):
        self.temporary.cleanup()

    def baseline(self, hash_override=None):
        lines = []
        for path in sorted(self.source.rglob("*")):
            if path.is_file() and not path.is_symlink():
                relative = path.relative_to(self.source).as_posix()
                row = {"relative_path": relative, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                       "size_bytes": path.stat().st_size, "stat_fingerprint": _fingerprint(path.stat())}
                if hash_override and relative in hash_override:
                    row["sha256"] = hash_override[relative]
                lines.append(json.dumps(row, sort_keys=True) + "\n")
        raw = "".join(lines).encode()
        (self.checkpoint / "source_manifest.jsonl").write_bytes(raw)
        (self.checkpoint / "manifest.json").write_text(json.dumps({"complete": True, "source_manifest_sha256": hashlib.sha256(raw).hexdigest()}))

    def run_verification(self):
        return integrity.verify_source_hashes(self.source, self.checkpoint, self.output, self.config)

    def reports(self):
        return [json.loads(path.read_text()) for path in sorted(self.output.glob("attempt_*/source_integrity.json"))]

    def results(self, report):
        return [json.loads(line) for line in (self.output / report["artifacts"]["results"]).read_text().splitlines()]

    def test_unchanged_full_byte_verification_and_unique_attempts(self):
        (self.source / "one.jsonl").write_bytes('{"text":"Ελληνικά."}\n'.encode())
        (self.source / "subdirectory").mkdir()
        (self.source / "subdirectory" / "two.bin").write_bytes(bytes(range(256)))
        self.baseline()
        before = {path: _fingerprint(path.stat()) for path in self.source.rglob("*") if path.is_file()}
        first = self.run_verification()
        first_bytes = (self.output / first["artifacts"]["source_integrity"]).read_bytes()
        second = self.run_verification()
        self.assertEqual(self.root / first["source_hashes_path"], self.output / first["artifacts"]["results"])
        self.assertEqual(self.root / first["integrity_report_path"], self.output / first["artifacts"]["source_integrity"])
        self.assertTrue(first["passed"])
        self.assertTrue(first["baseline_manifest_verified"])
        self.assertEqual(first["statistics"]["verified_files"], 2)
        self.assertEqual(first["statistics"]["unverified_files"], 0)
        self.assertEqual(first["statistics"]["final_rechecked_files"], 2)
        self.assertEqual({row["status"] for row in self.results(first)}, {"unchanged"})
        self.assertNotEqual(first["artifacts"], second["artifacts"])
        self.assertEqual((self.output / first["artifacts"]["source_integrity"]).read_bytes(), first_bytes)
        self.assertEqual({path: _fingerprint(path.stat()) for path in before}, before)

    def test_first_stat_change_stops_without_hashing_later_files(self):
        for index in range(30):
            (self.source / f"{index:02}.bin").write_bytes(b"original bytes")
        self.baseline()
        (self.source / "00.bin").write_bytes(b"changed source bytes")
        # Deterministic enumeration for this synthetic fixture only.
        def walk(source):
            for path in sorted(source.iterdir()):
                yield path, path.name, path.stat()
        with mock.patch.object(integrity, "_walk_regular", walk), mock.patch.object(integrity, "_read_block") as read:
            with self.assertRaises(SourceChangedError):
                self.run_verification()
            read.assert_not_called()
        report = self.reports()[0]
        self.assertFalse(report["passed"])
        self.assertEqual(report["statistics"]["observed_files"], 1)
        self.assertEqual(report["statistics"]["changed"], 1)
        self.assertEqual(report["statistics"]["unverified_files"], 30)
        self.assertFalse(report["enumeration_complete"])
        with contextlib.closing(sqlite3.connect(self.output / report["artifacts"]["accounting"])) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM expected").fetchone()[0], 30)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM expected WHERE status='unverified'").fetchone()[0], 29)

    def test_hash_mismatch_cancels_running_reads_promptly(self):
        (self.source / "00.bin").write_bytes(b"first")
        for index in range(1, 12):
            with (self.source / f"{index:02}.bin").open("wb") as handle:
                for _ in range(4):
                    handle.write(b"x" * integrity.BLOCK)
        self.baseline({"00.bin": "0" * 64})
        first_inode = (self.source / "00.bin").stat().st_ino
        another_started = threading.Event()
        real_read = integrity._read_block
        def controlled_read(handle):
            if os.fstat(handle.fileno()).st_ino == first_inode:
                self.assertTrue(another_started.wait(timeout=2))
            else:
                another_started.set()
                time.sleep(0.05)
            return real_read(handle)
        def walk(source):
            for path in sorted(source.iterdir()):
                yield path, path.name, path.stat()
        real_worker = integrity._source_result
        failed_at = []
        worker_finished = []
        def observed_worker(item, expected, cancelled, fail):
            def observed_failure(*args):
                failed_at.append(time.monotonic())
                fail(*args)
            result = real_worker(item, expected, cancelled, observed_failure)
            worker_finished.append(time.monotonic())
            return result
        with mock.patch.object(integrity, "_walk_regular", walk), mock.patch.object(integrity, "_read_block", controlled_read), mock.patch.object(integrity, "_source_result", observed_worker):
            with self.assertRaises(SourceChangedError):
                self.run_verification()
        self.assertTrue(failed_at)
        self.assertLess(max(worker_finished) - min(failed_at), 1.0)
        report = self.reports()[0]
        self.assertEqual(report["failure"]["reason"], "source_hash_or_size_changed")
        self.assertGreater(report["statistics"]["unverified_files"], 0)
        self.assertLess(report["statistics"]["observed_files"], 12)
        self.assertLess(report["statistics"]["bytes"], 2 * integrity.BLOCK)
        self.assertGreaterEqual(report["statistics"]["cancelled"], 1)

    def test_replacement_with_fifo_cannot_block_or_open_for_writing(self):
        path = self.source / "replaced.bin"
        path.write_bytes(b"original")
        before = path.stat()
        expected = (hashlib.sha256(b"original").hexdigest(), before.st_size, _fingerprint(before))
        actual_open = os.open
        failures = []
        def replacing_open(target, flags, *args, **kwargs):
            if Path(target) == path:
                path.unlink()
                os.mkfifo(path)
                # Fail the test safely if a regression would otherwise block.
                if not flags & os.O_NONBLOCK or flags & os.O_ACCMODE != os.O_RDONLY:
                    raise RuntimeError("unsafe source open flags")
            return actual_open(target, flags, *args, **kwargs)
        with mock.patch.object(integrity.os, "open", replacing_open):
            result = integrity._source_result((path, path.name, before), expected,
                                              threading.Event(), lambda *args: failures.append(args))
        self.assertEqual(result["status"], "changed")
        self.assertEqual(result["reason"], "source_identity_changed_while_opening_or_reading")
        self.assertEqual(result["bytes_hashed"], 0)
        self.assertTrue(failures)

    def test_mutation_mid_read_is_reported_and_never_passes(self):
        path = self.source / "large.bin"
        path.write_bytes(b"x" * (3 * integrity.BLOCK))
        self.baseline()
        original = integrity._read_block
        changed = False
        def mutating_read(handle):
            nonlocal changed
            result = original(handle)
            if not changed:
                changed = True
                with path.open("ab") as synthetic_mutation:
                    synthetic_mutation.write(b"changed")
            return result
        with mock.patch.object(integrity, "_read_block", mutating_read):
            with self.assertRaises(SourceChangedError):
                self.run_verification()
        report = self.reports()[0]
        self.assertFalse(report["passed"])
        self.assertEqual(report["failure"]["reason"], "source_stat_changed_during_read")
        self.assertEqual(report["statistics"]["unverified_files"], 1)

    def test_added_file_fails_and_removed_file_checked_after_enumeration(self):
        (self.source / "original.bin").write_bytes(b"original")
        self.baseline()
        (self.source / "added.bin").write_bytes(b"added")
        with self.assertRaises(SourceChangedError):
            self.run_verification()
        added_report = self.reports()[0]
        self.assertEqual(added_report["statistics"]["added"], 1)
        (self.source / "added.bin").unlink()
        (self.source / "original.bin").unlink()
        with self.assertRaises(SourceChangedError):
            self.run_verification()
        removed_report = next(report for report in self.reports() if report["statistics"]["removed"])
        self.assertTrue(removed_report["enumeration_complete"])
        self.assertEqual(removed_report["statistics"]["removed"], 1)
        self.assertEqual(removed_report["statistics"]["unverified_files"], 1)

    def test_post_hash_mutation_is_detected_by_final_sweep(self):
        path = self.source / "one.bin"
        path.write_bytes(b"original")
        self.baseline()
        real_walk = integrity._walk_regular
        invocations = 0
        def walk(source):
            nonlocal invocations
            invocations += 1
            if invocations == 2:
                path.write_bytes(b"changed after hashing")
            yield from real_walk(source)
        with mock.patch.object(integrity, "_walk_regular", walk):
            with self.assertRaises(SourceChangedError):
                self.run_verification()
        report = self.reports()[0]
        self.assertEqual(report["failure"]["reason"], "source_stat_changed_after_verification")
        self.assertEqual(report["statistics"]["verified_files"], 0)
        self.assertEqual(report["statistics"]["unverified_files"], 1)

    def test_baseline_checksum_tampering_never_reads_source(self):
        (self.source / "one.bin").write_bytes(b"original")
        self.baseline()
        manifest = self.checkpoint / "source_manifest.jsonl"
        manifest.write_bytes(b" " + manifest.read_bytes())
        with mock.patch.object(integrity, "_read_block") as read:
            with self.assertRaises(SourceChangedError):
                self.run_verification()
            read.assert_not_called()
        report = self.reports()[0]
        self.assertFalse(report["baseline_manifest_verified"])
        self.assertFalse(report["passed"])
        self.assertEqual(report["failure"]["reason"], "immutable_inventory_manifest_changed")

    def test_unknown_read_error_is_sanitized_and_quarantined(self):
        (self.source / "one.bin").write_bytes(b"original")
        self.baseline()
        secret_marker = "PRIVATE-CREDENTIAL-DO-NOT-LOG"
        with mock.patch.object(integrity, "_read_block", side_effect=RuntimeError(secret_marker)):
            with self.assertRaises(SourceChangedError) as error:
                self.run_verification()
        report = self.reports()[0]
        serialized = json.dumps(report) + json.dumps(self.results(report)) + str(error.exception)
        self.assertNotIn(secret_marker, serialized)
        self.assertEqual(report["failure"]["error_type"], "RuntimeError")
        self.assertEqual(report["statistics"]["unverified_files"], 1)

    def test_output_and_sqlite_sidecar_symlinks_rejected(self):
        original = self.source / "one.bin"
        original.write_bytes(b"original")
        self.baseline()
        original_hash = hashlib.sha256(original.read_bytes()).hexdigest()
        for name in ("verification.sqlite", "verification.sqlite-wal", "verification.sqlite-shm", "source_integrity.json", ".temporary.partial"):
            output = self.root / ("symlink_" + name)
            output.mkdir()
            (output / name).symlink_to(original)
            with self.assertRaises(ValueError):
                integrity.verify_source_hashes(self.source, self.checkpoint, output, self.config)
            self.assertEqual(hashlib.sha256(original.read_bytes()).hexdigest(), original_hash)
        ancestor = self.root / "linked_parent"
        ancestor.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(ValueError):
            integrity.verify_source_hashes(self.source, self.checkpoint, ancestor / "output", self.config)
        self.assertFalse((self.source / "output").exists())
        with self.assertRaises(ValueError):
            integrity.verify_source_hashes(self.source, self.checkpoint, self.source / "output", self.config)
        with self.assertRaises(ValueError):
            integrity.verify_source_hashes(self.source, self.checkpoint, Path("/tmp/forbidden_integrity_output"), self.config)


if __name__ == "__main__":
    unittest.main()
