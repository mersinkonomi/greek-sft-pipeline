import contextlib
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import zstandard
from greek_sft import inventory

ROOT = Path(__file__).resolve().parents[1]


class InventoryScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='inventory_scope_', dir=ROOT / 'runtime/tmp')
        self.base = Path(self.temp.name)
        self.source = self.base / 'source'
        self.source.mkdir()
        self.run = self.base / 'unique_run'
        self.run.mkdir()
        self.checkpoint = self.run / 'checkpoint_01_inventory'
        self.config = {'workers': 1, 'inventory_commit_files': 1, 'max_record_bytes': 1024}
        self.addCleanup(self.temp.cleanup)

    def amendment(self, **overrides):
        value = {'version': 1, 'run_id': self.run.name, 'authorized_at': '2026-09-07T13:29:25+00:00',
                 'user_instruction': 'go past greek training', 'excluded_record_roots': ['greek_training'],
                 'deferred_hash_roots': ['greek_training'], 'mode': 'hash_only_for_unscanned_files',
                 'original_source_hash_requirement_preserved': True, 'prior_scanned_records_preserved': True,
                 'base_inventory_config_sha256': hashlib.sha256(inventory._json(self.config).encode()).hexdigest(),
                 'record_coverage_limitation': 'Zero is an identified-record lower bound; total records remain unassessed.'}
        value.update(overrides)
        (self.run / 'inventory_scope_amendment.json').write_text(json.dumps(value, indent=2) + '\n')
        return value

    def source_file(self, relative, data):
        path = self.source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def scan(self, path, scope):
        with contextlib.closing(sqlite3.connect(':memory:')) as db:
            db.execute('CREATE TABLE record_ranges(relative_path TEXT,first_record INTEGER,last_record INTEGER,status TEXT,reason TEXT,row_hash_chain TEXT)')
            report = inventory._scan(path, str(path.relative_to(self.source)), path.lstat(), db, self.config, scope_amendment=scope)
            ranges = list(db.execute('SELECT * FROM record_ranges'))
        return report, ranges

    def test_readonly_preview_freeze_checksums_and_no_scope_legacy(self):
        self.assertIsNone(inventory.validate_inventory_scope(self.checkpoint, self.config))
        self.assertFalse(self.checkpoint.exists())
        self.amendment()
        preview = inventory.validate_inventory_scope(self.checkpoint, self.config)
        self.assertFalse(preview['frozen'])
        self.assertFalse(self.checkpoint.exists())
        frozen = inventory.validate_inventory_scope(self.checkpoint, self.config, freeze=True)
        self.assertTrue(frozen['frozen'])
        copy = self.checkpoint / frozen['artifact']
        self.assertEqual(frozen['sha256'], hashlib.sha256(copy.read_bytes()).hexdigest())
        marker = json.loads((self.checkpoint / frozen['checksum_artifact']).read_text())
        self.assertEqual(marker['run_local_sha256'], hashlib.sha256((self.run / 'inventory_scope_amendment.json').read_bytes()).hexdigest())
        self.assertEqual(frozen, inventory.validate_inventory_scope(self.checkpoint, self.config))

    def test_priority_exact_root_preserves_all_files_and_does_not_follow_links(self):
        names = ['greek_training/a.jsonl', 'zeta/z.jsonl', 'alpha/a.jsonl', 'greek_training_temp/x.jsonl',
                 'nested/greek_training/x.jsonl', 'root.jsonl']
        for name in names:
            self.source_file(name, b'{}\n')
        (self.source / 'link').symlink_to(self.source / 'greek_training', target_is_directory=True)
        legacy = [relative for _, relative, _ in inventory._walk(self.source)]
        ordered = [relative for _, relative, _ in inventory._walk(self.source, deferred_roots=['greek_training'])]
        self.assertEqual(set(legacy), set(names))
        self.assertEqual(set(ordered), set(names))
        self.assertEqual(ordered[-1], 'greek_training/a.jsonl')
        self.assertLess(ordered.index('zeta/z.jsonl'), ordered.index('greek_training/a.jsonl'))
        self.amendment()
        scope = inventory.validate_inventory_scope(self.checkpoint, self.config)
        self.assertTrue(inventory._record_scope_excluded('greek_training/a.jsonl', scope))
        for relative in ('greek_training_temp/x', 'nested/greek_training/x', 'greek_training'):
            self.assertFalse(inventory._record_scope_excluded(relative, scope))

    def test_excluded_zstd_hashes_without_decoder_parser_language_or_pii(self):
        self.amendment()
        scope = inventory.validate_inventory_scope(self.checkpoint, self.config)
        raw = zstandard.ZstdCompressor(write_checksum=True).compress(b'{"text":"secret@example.test"}\n' * 100)
        path = self.source_file('greek_training/data.jsonl.zst', raw)
        with patch('zstandard.ZstdDecompressor', side_effect=AssertionError('decoder called')) as decoder, \
             patch.object(inventory, '_loads', side_effect=AssertionError('record parser called')) as parser, \
             patch.object(inventory, '_inspect_record', side_effect=AssertionError('PII/language called')):
            report, ranges = self.scan(path, scope)
        decoder.assert_not_called()
        parser.assert_not_called()
        self.assertEqual(report['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(report['status'], 'unsupported')
        self.assertEqual(report['reason'], 'user_requested_intermediate_data_exclusion')
        self.assertEqual(report['record_count'], 0)
        self.assertIsNone(report['total_record_count'])
        self.assertFalse(report['record_boundary_complete'])
        self.assertTrue(report['record_assessment_skipped'])
        self.assertFalse(report['generation_eligible'])
        self.assertTrue(report['compression_integrity']['framing_complete'])
        self.assertFalse(report['compression_integrity']['native_decoder_reached_eof'])
        self.assertEqual(ranges, [])
        self.assertFalse(any(k.startswith(('status_', 'reason_', 'risk_')) for k in report['stats']))

    def test_excluded_malformed_bytes_are_unassessed_and_framing_failure_still_detected(self):
        self.amendment()
        scope = inventory.validate_inventory_scope(self.checkpoint, self.config)
        invalid = self.source_file('greek_training/unparsed.jsonl', b'not JSON\n\xff\n')
        report, ranges = self.scan(invalid, scope)
        self.assertEqual(report['status'], 'unsupported')
        self.assertEqual(report['record_count'], 0)
        self.assertEqual(ranges, [])
        encoded = zstandard.ZstdCompressor(write_checksum=True).compress(b'{}\n')[:-1]
        truncated = self.source_file('greek_training/truncated.jsonl.zst', encoded)
        with patch('zstandard.ZstdDecompressor', side_effect=AssertionError('decoder called')):
            report, _ = self.scan(truncated, scope)
        self.assertEqual(report['status'], 'processing_error')
        self.assertEqual(report['reason'], 'zstandard_truncated_content_checksum')
        self.assertTrue(report['record_assessment_skipped'])
        self.assertEqual(report['sha256'], hashlib.sha256(encoded).hexdigest())

    def test_unaffected_root_keeps_record_parsing(self):
        self.amendment()
        scope = inventory.validate_inventory_scope(self.checkpoint, self.config)
        for relative in ('other/data.jsonl', 'greek_training_temp/data.jsonl', 'nested/greek_training/data.jsonl'):
            path = self.source_file(relative, b'{}\ninvalid\n')
            report, ranges = self.scan(path, scope)
            self.assertEqual(report['record_count'], 2)
            self.assertTrue(report['record_boundary_complete'])
            self.assertEqual(report['stats']['status_malformed'], 1)
            self.assertNotIn('record_assessment_skipped', report)

    def test_invalid_amendments_fail_without_freezing(self):
        cases = [{'excluded_record_roots': ['greek_training_temp']}, {'deferred_hash_roots': ['../source']},
                 {'user_instruction': 'invented approval'}, {'original_source_hash_requirement_preserved': False},
                 {'prior_scanned_records_preserved': False}, {'mode': 'skip_hashes'}, {'version': True},
                 {'run_id': 'other_run'}, {'base_inventory_config_sha256': '0' * 64},
                 {'authorized_at': '2026-09-07T14:00:00+01:00'}, {'record_coverage_limitation': ''}, {'extra': 'field'}]
        for changed in cases:
            with self.subTest(changed=changed):
                self.amendment(**changed)
                with self.assertRaises(ValueError):
                    inventory.validate_inventory_scope(self.checkpoint, self.config, freeze=True)
                self.assertFalse(self.checkpoint.exists())

    def test_existing_frozen_config_conflict_does_not_publish_scope(self):
        self.amendment()
        self.checkpoint.mkdir()
        (self.checkpoint / 'inventory_state.json').write_text(json.dumps({'config_sha256': '0' * 64}))
        with self.assertRaisesRegex(ValueError, 'existing_config_state_conflict'):
            inventory.validate_inventory_scope(self.checkpoint, self.config, freeze=True)
        self.assertFalse((self.checkpoint / 'inventory_scope_amendment.json').exists())
        self.assertFalse((self.checkpoint / 'inventory_scope_amendment.sha256.json').exists())

    def test_drift_removal_and_snapshot_tampering_fail(self):
        self.amendment()
        scope = inventory.validate_inventory_scope(self.checkpoint, self.config, freeze=True)
        run_file = self.run / 'inventory_scope_amendment.json'
        original = run_file.read_bytes()
        run_file.write_bytes(original + b' ')
        with self.assertRaisesRegex(ValueError, 'identity_changed'):
            inventory.validate_inventory_scope(self.checkpoint, self.config)
        run_file.write_bytes(original)
        run_file.unlink()
        with self.assertRaisesRegex(ValueError, 'authorization_removed'):
            inventory.validate_inventory_scope(self.checkpoint, self.config)
        run_file.write_bytes(original)
        (self.checkpoint / scope['artifact']).write_text('{}\n')
        with self.assertRaisesRegex(ValueError, 'snapshot_or_authorization_changed'):
            inventory.validate_inventory_scope(self.checkpoint, self.config)

    def test_new_amendment_on_complete_inventory_and_symlinks_fail(self):
        self.checkpoint.mkdir()
        (self.checkpoint / 'manifest.json').write_text('{"complete":true}')
        self.amendment()
        with self.assertRaisesRegex(ValueError, 'cannot_amend_completed'):
            inventory.validate_inventory_scope(self.checkpoint, self.config)
        run_file = self.run / 'inventory_scope_amendment.json'
        raw = run_file.read_bytes()
        run_file.unlink()
        target = self.base / 'authorization'
        target.write_bytes(raw)
        run_file.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            inventory.validate_inventory_scope(self.checkpoint, self.config)

    def test_cached_exclusions_require_same_scope_even_if_authorization_artifacts_removed(self):
        self.amendment()
        self.source_file('greek_training/data.jsonl', b'{}\n')
        result = inventory.run_inventory(self.source, self.checkpoint, self.config)
        self.assertIn('total_records_unassessed', result['record_accounting'])
        self.assertIn('user-excluded record content is unassessed', result['privacy_method'])
        scope = result['inventory_scope_amendment']
        report = json.loads((self.checkpoint / 'source_manifest.jsonl').read_text())
        for current in (None, dict(scope, sha256='0' * 64)):
            with self.assertRaises(inventory.InventoryScopeConflict):
                inventory._require_current_record_scope(report, current)
        for path in (self.run / 'inventory_scope_amendment.json', self.checkpoint / scope['artifact'],
                     self.checkpoint / scope['checksum_artifact']):
            path.unlink()
        with self.assertRaises(inventory.InventoryScopeConflict):
            inventory.run_inventory(self.source, self.checkpoint, self.config)

    def test_resume_preserves_cached_record_reports_ranges_and_config_state(self):
        old_path = self.source_file('greek_training/already_scanned.jsonl', b'{}\n{}\n')
        raw = zstandard.ZstdCompressor().compress(b'{}\n' * 50)
        self.source_file('greek_training/unscanned.jsonl.zst', raw)
        self.source_file('zeta/data.jsonl', b'{}\n')
        self.checkpoint.mkdir()
        with contextlib.closing(inventory._connect(self.checkpoint / 'inventory_shard_00.sqlite')) as db:
            relative = str(old_path.relative_to(self.source))
            old_report = inventory._scan(old_path, relative, old_path.lstat(), db, self.config)
            old_text = inventory._json(old_report)
            db.execute('INSERT INTO files VALUES(?,?,?,1)', (relative, inventory._json(inventory._fingerprint(old_path.lstat())), old_text))
            old_ranges = list(db.execute('SELECT * FROM record_ranges'))
            db.commit()
        state = {'version': inventory.VERSION, 'workers': 1, 'source_root': str(self.source.resolve()),
                 'config_sha256': hashlib.sha256(inventory._json(self.config).encode()).hexdigest()}
        state_path = self.checkpoint / 'inventory_state.json'
        inventory._atomic_json(state_path, state)
        original_state = state_path.read_bytes(), state_path.stat().st_mtime_ns
        self.amendment()
        original_scan = inventory._scan
        def guarded(path, *args, **kwargs):
            if path == old_path:
                raise AssertionError('cached source was reparsed')
            return original_scan(path, *args, **kwargs)
        with patch.object(inventory, '_scan', guarded):
            result = inventory.run_inventory(self.source, self.checkpoint, self.config)
        self.assertEqual(result['statistics']['files'], 3)
        self.assertEqual(result['statistics']['records'], 3)
        self.assertEqual(result['statistics']['files_with_unresolved_record_boundaries'], 1)
        self.assertTrue(result['inventory_scope_amendment']['frozen'])
        self.assertEqual(original_state, (state_path.read_bytes(), state_path.stat().st_mtime_ns))
        with contextlib.closing(sqlite3.connect(self.checkpoint / 'inventory_shard_00.sqlite')) as db:
            self.assertEqual(db.execute('SELECT report FROM files WHERE relative_path=?', (relative,)).fetchone()[0], old_text)
            self.assertEqual(list(db.execute('SELECT * FROM record_ranges WHERE relative_path=?', (relative,))), old_ranges)
        self.assertEqual(result, inventory.run_inventory(self.source, self.checkpoint, self.config))
        self.assertEqual(inventory.VERSION, 'inventory-1.0.0')


if __name__ == '__main__':
    unittest.main()
