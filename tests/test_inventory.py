import hashlib
import os
import contextlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from greek_sft import inventory

class InventoryTests(unittest.TestCase):
    def setUp(self):
        root = inventory.PIPELINE_ROOT / "tests" / "runtime"
        root.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="inventory_", dir=root)
        self.base = Path(self.tmp.name)
        self.source = self.base / "source"
        self.source.mkdir()
        self.checkpoint = self.base / "run" / "checkpoint"
        self.config = {"workers": 2, "max_record_bytes": 1024, "inventory_range_records": 2}
    def tearDown(self):
        self.tmp.cleanup()
    def records(self):
        return [json.loads(line) for line in (self.checkpoint / "source_manifest.jsonl").read_text().splitlines()]
    def test_jsonl_accounting_hash_and_resume(self):
        payload = ('{"text":"Μια πλήρης ελληνική πρόταση."}\n\nnot json\n{"text":"Δεύτερη πρόταση."}').encode()
        (self.source / "data.jsonl").write_bytes(payload)
        initial = inventory.run_inventory(self.source, self.checkpoint, self.config)
        report = self.records()[0]
        self.assertEqual(report["record_count"], 4)
        self.assertEqual(report["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(report["stats"]["status_malformed"], 2)
        ranges = []
        for shard in self.checkpoint.glob("inventory_shard_*.sqlite"):
            with contextlib.closing(sqlite3.connect(shard)) as conn:
                ranges.extend(conn.execute("SELECT first_record,last_record FROM record_ranges"))
        self.assertEqual(sum(last - first + 1 for first, last in ranges), 4)
        self.assertEqual(inventory.run_inventory(self.source, self.checkpoint, self.config), initial)
        self.assertTrue(inventory.verify_source_hashes(self.source, self.checkpoint, self.base / "verify", self.config)["passed"])
        self.assertEqual((self.source / "data.jsonl").read_bytes(), payload)
    def test_added_removed_and_changed_fail(self):
        (self.source / "one.jsonl").write_text('{"text":"ένα"}\n')
        (self.source / "two.jsonl").write_text('{"text":"δύο"}\n')
        inventory.run_inventory(self.source, self.checkpoint, self.config)
        (self.source / "one.jsonl").write_text('{"text":"άλλαξε"}\n')
        (self.source / "two.jsonl").unlink()
        (self.source / "three.jsonl").write_text('{"text":"τρία"}\n')
        with self.assertRaises(inventory.SourceChangedError):
            inventory.verify_source_hashes(self.source, self.checkpoint, self.base / "verify", self.config)
        result = json.loads((self.base / "verify/source_integrity.json").read_text())
        self.assertEqual(result["statistics"]["changed"], 1)
        self.assertEqual(result["statistics"]["removed"], 1)
        self.assertEqual(result["statistics"]["added"], 1)
    def test_compressed_and_artifact_records(self):
        import zstandard
        payload = '{"text":"Ελληνικό κείμενο."}\n{"text":"Πλήρης πρόταση."}\n'.encode()
        original = self.source / "greek_training" / "part.jsonl.zst"
        original.parent.mkdir()
        original.write_bytes(zstandard.ZstdCompressor().compress(payload))
        inventory.run_inventory(self.source, self.checkpoint, self.config)
        report = self.records()[0]
        self.assertEqual(report["record_count"], 2)
        self.assertEqual(report["status"], "unsupported")
        self.assertEqual(report["stats"]["status_unsupported"], 2)
        self.assertEqual(report["sha256"], hashlib.sha256(original.read_bytes()).hexdigest())
    def test_oversized_row_is_one_accounted_record(self):
        data = b'{"text":"' + b'x' * 5000 + b'"}\n{}\n'
        (self.source / "large.jsonl").write_bytes(data)
        inventory.run_inventory(self.source, self.checkpoint, self.config)
        report = self.records()[0]
        self.assertEqual(report["record_count"], 2)
        self.assertEqual(report["stats"]["reason_record_exceeds_safe_parse_limit"], 1)
        self.assertEqual(report["sha256"], hashlib.sha256(data).hexdigest())
    def test_unknown_binary_remains_unresolved(self):
        (self.source / "model.bin").write_bytes(bytes(range(256)))
        inventory.run_inventory(self.source, self.checkpoint, self.config)
        report = self.records()[0]
        self.assertFalse(report["record_boundary_complete"])
        self.assertEqual(report["status"], "unsupported")
    def test_output_escape_is_rejected(self):
        with self.assertRaises(ValueError):
            inventory.run_inventory(self.source, Path("/tmp/not_allowed_inventory"), self.config)
        with self.assertRaises(ValueError):
            inventory.run_inventory(self.source, self.source / "bad_output", self.config)
        self.assertFalse((self.source / "bad_output").exists())
    def test_source_symlink_not_followed(self):
        (self.source / "a.jsonl").write_text('{}\n')
        (self.source / "link.jsonl").symlink_to(self.source / "a.jsonl")
        inventory.run_inventory(self.source, self.checkpoint, self.config)
        self.assertEqual(len(self.records()), 1)

    def test_worker_crash_leaves_resumable_checkpoint(self):
        (self.source / "a.jsonl").write_text('{"text":"ελληνικά"}\n')
        (self.source / "b.jsonl").write_text('{"text":"περισσότερα ελληνικά"}\n')
        original_scan = inventory._scan
        def crash(path, *args, **kwargs):
            if path.name == "b.jsonl":
                os._exit(23)
            return original_scan(path, *args, **kwargs)
        inventory._scan = crash
        try:
            with self.assertRaises(RuntimeError):
                inventory.run_inventory(self.source, self.checkpoint, self.config)
        finally:
            inventory._scan = original_scan
        self.assertFalse((self.checkpoint / "manifest.json").exists())
        result = inventory.run_inventory(self.source, self.checkpoint, self.config)
        self.assertEqual(result["statistics"]["files"], 2)
        self.assertEqual(result["statistics"]["records"], 2)
        progress = [json.loads(path.read_text()) for path in self.checkpoint.glob("worker_*_heartbeat.json")]
        self.assertEqual(len(progress), 2)
        self.assertTrue(all(p["phase"] == "complete" for p in progress))
        self.assertTrue(all(p["pid"] != os.getpid() for p in progress))

    def test_crash_preserves_committed_batch_and_rolls_back_incomplete_batch(self):
        config={**self.config,"workers":1,"inventory_commit_files":2}
        for name in ('a','b','c','d'):
            (self.source/(name+'.jsonl')).write_text('{"text":"Ελληνικό κείμενο."}\n')
        original_scan=inventory._scan
        def crash(path,*args,**kwargs):
            if path.name=='d.jsonl': os._exit(23)
            return original_scan(path,*args,**kwargs)
        inventory._scan=crash
        try:
            with self.assertRaises(RuntimeError): inventory.run_inventory(self.source,self.checkpoint,config)
        finally: inventory._scan=original_scan
        with contextlib.closing(sqlite3.connect(self.checkpoint/'inventory_shard_00.sqlite')) as db:
            self.assertEqual([x[0] for x in db.execute('SELECT relative_path FROM files WHERE completed=1 ORDER BY relative_path')],['a.jsonl','b.jsonl'])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM record_ranges').fetchone()[0],2)
        result=inventory.run_inventory(self.source,self.checkpoint,config)
        self.assertEqual(result['statistics']['files'],4)
        self.assertEqual(result['statistics']['records'],4)
        heartbeat=json.loads((self.checkpoint/'worker_00_heartbeat.json').read_text())
        self.assertEqual(heartbeat['files_resumed_this_attempt'],2)

    def test_output_leaf_symlinks_cannot_modify_source(self):
        original = self.source / "unchanged.jsonl"
        original.write_bytes(b'{}\n')
        original_hash = hashlib.sha256(original.read_bytes()).hexdigest()
        for leaf in ("inventory_shard_00.sqlite", "inventory_shard_00.sqlite-wal", "progress.json.partial", ".inventory.lock"):
            checkpoint = self.base / ("bad_" + leaf.replace(".", "_"))
            checkpoint.mkdir()
            (checkpoint / leaf).symlink_to(original)
            with self.assertRaises(ValueError):
                inventory.run_inventory(self.source, checkpoint, self.config)
            self.assertEqual(hashlib.sha256(original.read_bytes()).hexdigest(), original_hash)
        inventory.run_inventory(self.source, self.checkpoint, self.config)
        verify = self.base / "unsafe_verification"
        verify.mkdir()
        (verify / "verification.sqlite").symlink_to(original)
        with self.assertRaises(ValueError):
            inventory.verify_source_hashes(self.source, self.checkpoint, verify, self.config)
        self.assertEqual(hashlib.sha256(original.read_bytes()).hexdigest(), original_hash)

if __name__ == "__main__":
    unittest.main()
