import contextlib
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from greek_sft import inventory
from greek_sft.source_scope import (APPROVED_QUESTION, SourceExclusionConflict,
    is_source_excluded, validate_source_exclusion, validate_source_exclusion_binding)

ROOT = Path(__file__).resolve().parents[1]


class SourceExclusionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='source_exclusion_', dir=ROOT / 'runtime/tmp')
        self.base = Path(self.temp.name)
        self.source = self.base / 'source'
        self.source.mkdir()
        self.run = self.base / 'fixture_run'
        self.checkpoint = self.run / 'checkpoint_01_inventory'
        self.checkpoint.mkdir(parents=True)
        self.config = {'workers': 1, 'inventory_commit_files': 1, 'max_record_bytes': 1024}
        self.addCleanup(self.temp.cleanup)
        self.index = self.file('greek_training/.git/index', b'old index')
        self.seed(self.index)
        self.index.write_bytes(b'changed external index')
        self.incident_path = self.run / 'integrity_incidents/fixture/incident.json'
        self.incident_path.parent.mkdir(parents=True)
        self.incident = {'run_id': self.run.name, 'status': 'halted_source_integrity_failure',
            'source_file': 'greek_training/.git/index', 'sha256_matches': False,
            'baseline_sha256': hashlib.sha256(b'old index').hexdigest(),
            'observed_sha256': hashlib.sha256(b'changed external index').hexdigest()}
        self.incident_path.write_text(json.dumps(self.incident) + '\n')

    def file(self, relative, payload):
        path = self.source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return path

    def seed(self, path):
        relative = str(path.relative_to(self.source))
        with contextlib.closing(inventory._connect(self.checkpoint / 'inventory_shard_00.sqlite')) as db:
            report = inventory._scan(path, relative, path.lstat(), db, self.config)
            db.execute('INSERT INTO files VALUES(?,?,?,1)', (relative,
                inventory._json(inventory._fingerprint(path.lstat())), inventory._json(report)))
            db.commit()
        return report

    def record_scope(self):
        body = {'version': 1, 'run_id': self.run.name, 'authorized_at': '2026-09-07T13:29:25+00:00',
            'user_instruction': 'go past greek training', 'excluded_record_roots': ['greek_training'],
            'deferred_hash_roots': ['greek_training'], 'mode': 'hash_only_for_unscanned_files',
            'original_source_hash_requirement_preserved': True, 'prior_scanned_records_preserved': True,
            'base_inventory_config_sha256': hashlib.sha256(inventory._json(self.config).encode()).hexdigest(),
            'record_coverage_limitation': 'Unscanned records are unassessed; zero is only an identified lower bound.'}
        (self.run / 'inventory_scope_amendment.json').write_text(json.dumps(body) + '\n')
        return inventory.validate_inventory_scope(self.checkpoint, self.config, freeze=True)

    def amendment(self, **changes):
        record_scope = inventory.validate_inventory_scope(self.checkpoint, self.config)
        body = {'version': 1, 'run_id': self.run.name, 'authorized_at': '2026-09-07T15:30:00+00:00',
            'user_instruction': 'continue', 'approved_question': APPROVED_QUESTION,
            'excluded_source_roots': ['greek_training/.git'], 'mode': 'exclude_subtree_from_current_source_coverage',
            'base_inventory_config_sha256': hashlib.sha256(inventory._json(self.config).encode()).hexdigest(),
            'record_scope_amendment_sha256': record_scope['sha256'] if record_scope else None,
            'integrity_incident_path': str(self.incident_path.relative_to(self.run)),
            'integrity_incident_sha256': hashlib.sha256(self.incident_path.read_bytes()).hexdigest(),
            'preserve_historical_inventory': True, 'full_original_source_integrity_claim_allowed': False,
            'current_excluded_coverage': 'unknown'}
        body.update(changes)
        (self.run / 'source_exclusion_amendment.json').write_text(json.dumps(body, indent=2) + '\n')
        return body

    def test_readonly_validation_freeze_and_exact_boundary(self):
        self.assertIsNone(validate_source_exclusion(self.checkpoint, self.config))
        self.amendment()
        scope = validate_source_exclusion(self.checkpoint, self.config)
        self.assertFalse(scope['frozen'])
        self.assertFalse((self.checkpoint / scope['artifact']).exists())
        for path in ('greek_training/.git', 'greek_training/.git/index', 'greek_training/.git/objects/a'):
            self.assertTrue(is_source_excluded(path, scope))
        for path in ('greek_training/.gitignore', 'greek_training/.github/a', 'greek_training/.gitfoo/index',
                     '.git/index', 'nested/greek_training/.git/index', 'greek_training/.Git/index'):
            self.assertFalse(is_source_excluded(path, scope))
        frozen = validate_source_exclusion(self.checkpoint, self.config, freeze=True)
        self.assertTrue(frozen['frozen'])
        self.assertEqual(frozen['sha256'], hashlib.sha256((self.checkpoint / frozen['artifact']).read_bytes()).hexdigest())
        self.assertEqual(frozen, validate_source_exclusion(self.checkpoint, self.config))

    def test_walk_never_enters_or_lstats_excluded_children(self):
        self.amendment()
        scope = validate_source_exclusion(self.checkpoint, self.config)
        names = ['greek_training/.gitignore', 'greek_training/.gitfoo/index', 'greek_training/data.jsonl', 'other/data.jsonl']
        for name in names:
            self.file(name, b'{}\n')
        real_scandir, real_lstat = os.scandir, Path.lstat
        git = self.source / 'greek_training/.git'
        def guarded_scandir(path):
            if Path(path) == git or git in Path(path).parents:
                raise AssertionError('entered excluded subtree')
            return real_scandir(path)
        def guarded_lstat(path, *args, **kwargs):
            if path == git or git in path.parents:
                raise AssertionError('lstat excluded subtree')
            return real_lstat(path, *args, **kwargs)
        with patch('os.scandir', guarded_scandir), patch.object(Path, 'lstat', guarded_lstat):
            actual = [relative for _, relative, _ in inventory._walk(self.source, source_exclusion=scope)]
        self.assertEqual(set(actual), set(names))

    def test_changed_excluded_index_resumes_and_preserves_every_cached_byte_and_range(self):
        history = self.file('greek_training/.git/historical.jsonl', b'{}\n{}\n')
        self.seed(history)
        self.file('other/data.jsonl', b'{}\n')
        self.file('greek_training/.git/new_unobserved.lock', b'unknown current file')
        self.record_scope()
        self.file('greek_training/data.jsonl', b'{}\n' * 100)
        self.amendment()
        shard = self.checkpoint / 'inventory_shard_00.sqlite'
        with contextlib.closing(sqlite3.connect(shard)) as db:
            original_rows = list(db.execute('SELECT * FROM files ORDER BY relative_path'))
            original_ranges = list(db.execute('SELECT * FROM record_ranges ORDER BY relative_path,first_record'))
        result = inventory.run_inventory(self.source, self.checkpoint, self.config)
        counts = result['statistics']
        self.assertEqual(counts['historical_excluded_files'], 2)
        self.assertEqual(counts['historical_excluded_identified_records'], 2)
        self.assertEqual(counts['in_scope_files'], 2)
        self.assertEqual(counts['in_scope_identified_records'], 1)
        self.assertEqual(counts['files'], counts['historical_excluded_files'] + counts['in_scope_files'])
        self.assertEqual(counts['records'], counts['historical_excluded_identified_records'] + counts['in_scope_identified_records'])
        self.assertFalse(result['full_original_source_integrity'])
        self.assertIsNone(result['source_exclusion_accounting']['current_excluded_files'])
        with contextlib.closing(sqlite3.connect(shard)) as db:
            for row in original_rows:
                self.assertEqual(db.execute('SELECT * FROM files WHERE relative_path=?', (row[0],)).fetchone(), row)
            self.assertEqual(list(db.execute('SELECT * FROM record_ranges WHERE relative_path GLOB ? ORDER BY relative_path,first_record', ('greek_training/.git/*',))), original_ranges)
        manifest = [json.loads(line) for line in (self.checkpoint / 'source_manifest.jsonl').read_text().splitlines()]
        self.assertEqual(len(manifest), 4)
        index = next(x for x in manifest if x['relative_path'] == 'greek_training/.git/index')
        self.assertEqual(index['sha256'], hashlib.sha256(b'old index').hexdigest())
        accounting = result['source_exclusion_accounting']
        ledger = [json.loads(line) for line in (self.checkpoint / accounting['artifacts']['files.jsonl']).read_text().splitlines()]
        self.assertEqual(len(ledger), 2)
        self.assertTrue(all(x['current_sha256'] is None for x in ledger))
        checksum_path = self.checkpoint / accounting['artifacts']['checksums.json']
        checksums = json.loads(checksum_path.read_text())
        self.assertEqual(accounting['checksums_sha256'], hashlib.sha256(checksum_path.read_bytes()).hexdigest())
        for name, details in checksums['artifacts'].items():
            path = checksum_path.parent / name
            self.assertEqual(details['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(inventory.run_inventory(self.source, self.checkpoint, self.config), result)
        self.assertEqual(self.index.read_bytes(), b'changed external index')

    def test_neighboring_changed_and_removed_files_still_halt(self):
        neighbor = self.file('greek_training/.gitignore', b'old content')
        self.seed(neighbor)
        self.amendment()
        neighbor.write_bytes(b'changed content')
        with self.assertRaises(inventory.SourceChangedError):
            inventory.run_inventory(self.source, self.checkpoint, self.config)
        neighbor.unlink()
        with self.assertRaises(inventory.SourceChangedError):
            inventory.run_inventory(self.source, self.checkpoint, self.config)

    def test_scope_drift_removal_and_incident_tampering_rejected(self):
        self.amendment()
        scope = validate_source_exclusion(self.checkpoint, self.config, freeze=True)
        authorization = self.run / 'source_exclusion_amendment.json'
        original = authorization.read_bytes()
        authorization.write_bytes(original + b' ')
        with self.assertRaises(SourceExclusionConflict):
            validate_source_exclusion(self.checkpoint, self.config)
        authorization.unlink()
        with self.assertRaises(SourceExclusionConflict):
            validate_source_exclusion(self.checkpoint, self.config)
        authorization.write_bytes(original)
        self.incident_path.write_text(json.dumps(dict(self.incident, observed_sha256='3' * 64)))
        with self.assertRaisesRegex(SourceExclusionConflict, 'incident_changed'):
            validate_source_exclusion(self.checkpoint, self.config)
        for active in (None, dict(scope, sha256='4' * 64)):
            with self.assertRaises(SourceExclusionConflict):
                validate_source_exclusion_binding({'source_exclusion_amendment_sha256': scope['sha256']}, active)

    def test_completed_binding_survives_removal_of_all_amendment_artifacts(self):
        self.amendment()
        result = inventory.run_inventory(self.source, self.checkpoint, self.config)
        scope = result['source_exclusion_amendment']
        self.assertEqual(result['statistics']['in_scope_files'], 0)
        for path in (self.run / scope['artifact'], self.checkpoint / scope['artifact'], self.checkpoint / scope['checksum_artifact']):
            path.unlink()
        with self.assertRaises(SourceExclusionConflict):
            validate_source_exclusion(self.checkpoint, self.config)

    def test_invalid_scope_config_incident_and_symlinks_rejected(self):
        cases = [{'excluded_source_roots': ['greek_training']}, {'excluded_source_roots': ['greek_training/.gitfoo']},
            {'approved_question': 'A different question'}, {'user_instruction': 'maybe'}, {'version': True},
            {'full_original_source_integrity_claim_allowed': True}, {'preserve_historical_inventory': False},
            {'current_excluded_coverage': 'complete'}, {'base_inventory_config_sha256': '0' * 64},
            {'record_scope_amendment_sha256': '0' * 64}, {'integrity_incident_path': '../incident.json'},
            {'integrity_incident_sha256': '0' * 64}, {'authorized_at': '2026-09-07T16:00:00+01:00'}, {'extra': True}]
        for changed in cases:
            with self.subTest(changed=changed):
                self.amendment(**changed)
                with self.assertRaises((SourceExclusionConflict, ValueError)):
                    validate_source_exclusion(self.checkpoint, self.config, freeze=True)
                self.assertFalse((self.checkpoint / 'source_exclusion_amendment.json').exists())
        self.amendment()
        authorization = self.run / 'source_exclusion_amendment.json'
        payload = authorization.read_bytes()
        authorization.unlink()
        target = self.base / 'auth'
        target.write_bytes(payload)
        authorization.symlink_to(target)
        with self.assertRaises(ValueError):
            validate_source_exclusion(self.checkpoint, self.config)

    def test_record_scope_pin_and_completed_new_amendment_rejected(self):
        record_scope = self.record_scope()
        self.amendment()
        validate_source_exclusion(self.checkpoint, self.config)
        for path in (self.run / record_scope['artifact'], self.checkpoint / record_scope['artifact'],
                     self.checkpoint / record_scope['checksum_artifact']):
            path.unlink()
        with self.assertRaises(SourceExclusionConflict):
            validate_source_exclusion(self.checkpoint, self.config)
        self.amendment()
        (self.checkpoint / 'manifest.json').write_text('{"complete":true}')
        with self.assertRaisesRegex(SourceExclusionConflict, 'cannot_amend_completed'):
            validate_source_exclusion(self.checkpoint, self.config, freeze=True)


if __name__ == '__main__':
    unittest.main()
