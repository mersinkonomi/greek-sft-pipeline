"""Baseline batching preserves identities, row validation and fresh-attempt safety."""
import contextlib
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from greek_sft import integrity
from greek_sft.core import PIPELINE_ROOT
from greek_sft.inventory import SourceChangedError, _fingerprint

SCHEMA = "CREATE TABLE expected(relative_path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL, fingerprint TEXT NOT NULL, seen INTEGER DEFAULT 0, final_seen INTEGER DEFAULT 0, status TEXT DEFAULT 'unverified', excluded INTEGER NOT NULL DEFAULT 0)"


class BaselineBatchTests(unittest.TestCase):
    def setUp(self):
        parent = PIPELINE_ROOT / 'runtime/baseline_batch_tests'
        parent.mkdir(parents=True, exist_ok=True)
        temp = tempfile.TemporaryDirectory(prefix='case_', dir=parent)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.checkpoint = self.root / 'inventory'
        self.checkpoint.mkdir()

    def rows(self, count):
        return [{'relative_path': ('greek_training/' if index % 2 else 'other/') + f'{index:06}.jsonl',
                 'sha256': hashlib.sha256(str(index).encode()).hexdigest(),
                 'size_bytes': index, 'stat_fingerprint': [1, index + 1, index, 4, 5]}
                for index in range(count)]

    def manifest(self, rows):
        raw = ''.join(json.dumps(row, sort_keys=True) + '\n' for row in rows).encode()
        checksum = hashlib.sha256(raw).hexdigest()
        (self.checkpoint / 'source_manifest.jsonl').write_bytes(raw)
        (self.checkpoint / 'manifest.json').write_text(json.dumps({
            'complete': True, 'source_manifest_sha256': checksum}))
        return checksum

    def load(self, batch_size, scope=None):
        # These large fixtures test logical SQL behavior only. Real FULL/DELETE
        # interruption coverage below and the separate benchmark retain durability.
        with contextlib.closing(sqlite3.connect(':memory:')) as connection:
            connection.execute('PRAGMA synchronous=OFF')
            connection.execute(SCHEMA)
            with patch.object(integrity, 'BASELINE_INSERT_BATCH', batch_size):
                result = integrity._load_baseline(self.checkpoint, connection, scope)
            contents = connection.execute('SELECT * FROM expected ORDER BY relative_path').fetchall()
        return result, contents

    def test_below_at_above_boundary_and_trailing_partial_are_identical(self):
        scope = {'amendment': {'excluded_source_roots': ['greek_training']}, 'sha256': 'a' * 64}
        for count in (0, 9999, 10000, 10001, 20017):
            with self.subTest(count=count):
                rows = self.rows(count)
                checksum = self.manifest(rows)
                old_result, old_contents = self.load(1000, scope)
                new_result, new_contents = self.load(10000, scope)
                self.assertEqual(new_result[:2], old_result[:2])
                self.assertEqual(_fingerprint(new_result[2]), _fingerprint(old_result[2]))
                self.assertEqual(new_result[:2], (count, checksum))
                self.assertEqual(new_contents, old_contents)
                expected = sorted((row['relative_path'], row['sha256'], row['size_bytes'],
                    json.dumps(row['stat_fingerprint']), 0, 0, 'unverified',
                    int(row['relative_path'].startswith('greek_training/'))) for row in rows)
                self.assertEqual(new_contents, expected)

    def test_duplicate_paths_across_boundary_are_rejected(self):
        rows = self.rows(10001)
        rows[-1] = dict(rows[0])
        self.manifest(rows)
        for batch_size in (1000, 10000):
            with self.subTest(batch_size=batch_size), self.assertRaises(sqlite3.IntegrityError):
                self.load(batch_size)

    def test_malformed_record_after_boundary_is_rejected(self):
        rows = self.rows(10001)
        rows[-1]['relative_path'] = '../escape'
        self.manifest(rows)
        for batch_size in (1000, 10000):
            with self.subTest(batch_size=batch_size), self.assertRaisesRegex(
                    integrity._BaselineError, 'invalid_inventory_manifest_record'):
                self.load(batch_size)

    def test_checksum_drift_after_full_batch_is_rejected(self):
        self.manifest(self.rows(10001))
        metadata = self.checkpoint / 'manifest.json'
        metadata.write_text(json.dumps({'complete': True, 'source_manifest_sha256': '0' * 64}))
        for batch_size in (1000, 10000):
            with self.subTest(batch_size=batch_size), self.assertRaisesRegex(
                    integrity._BaselineError, 'immutable_inventory_manifest_changed'):
                self.load(batch_size)

    def test_real_durable_interruption_never_passes_and_retry_uses_fresh_attempt(self):
        source = self.root / 'source'
        source.mkdir()
        path = source / 'one.jsonl'
        payload = b'{"text":"synthetic"}\n'
        path.write_bytes(payload)
        self.manifest([{'relative_path': path.name, 'sha256': hashlib.sha256(payload).hexdigest(),
                        'size_bytes': len(payload), 'stat_fingerprint': _fingerprint(path.stat())}])
        output = self.root / 'verification'
        real_connect = sqlite3.connect
        interrupted = []
        durability = []
        class InterruptedConnection(sqlite3.Connection):
            def commit(connection):
                super().commit()
                if not interrupted:
                    durability.append((connection.execute('PRAGMA synchronous').fetchone()[0],
                                       connection.execute('PRAGMA journal_mode').fetchone()[0]))
                    interrupted.append(True)
                    raise KeyboardInterrupt('synthetic interruption after durable baseline commit')
        def connect(*args, **kwargs):
            return real_connect(*args, factory=InterruptedConnection, **kwargs)
        with patch.object(integrity.sqlite3, 'connect', connect), patch.object(integrity, '_read_block') as read:
            with self.assertRaises(SourceChangedError):
                integrity.verify_source_hashes(source, self.checkpoint, output, {'workers': 1})
            read.assert_not_called()
        self.assertEqual(durability, [(2, 'delete')])
        first_path = next(output.glob('attempt_*/source_integrity.json'))
        first_raw = first_path.read_bytes()
        first = json.loads(first_raw)
        self.assertFalse(first['passed'])
        self.assertFalse(first['complete'])
        self.assertFalse(first['baseline_manifest_verified'])
        self.assertEqual(first['failure']['error_type'], 'KeyboardInterrupt')
        self.assertEqual(first['statistics']['expected_files'], 1)
        self.assertEqual(first['statistics']['unverified_files'], 1)
        self.assertFalse((first_path.parent / 'source_hashes_after.jsonl').exists())
        second = integrity.verify_source_hashes(source, self.checkpoint, output, {'workers': 1})
        self.assertTrue(second['passed'])
        self.assertNotEqual(first['artifacts']['accounting'], second['artifacts']['accounting'])
        self.assertEqual(first_path.read_bytes(), first_raw)
        self.assertEqual(len(list(output.glob('attempt_*'))), 2)


if __name__ == '__main__':
    unittest.main()
