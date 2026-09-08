"""Regression coverage for the separately authorized derived collection scope."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import patch

from greek_sft import inventory, integrity
from greek_sft.source_scope import (DERIVED_NAME, DERIVED_CHECKSUM_NAME,
    DERIVED_ROOT, DERIVED_INSTRUCTION, DERIVED_REASON, DERIVED_MODE,
    SourceExclusionConflict, is_source_excluded, validate_source_exclusion,
    validate_source_exclusion_binding)
import test_source_exclusion as legacy_fixture


def create_derived_amendment(case, **changes):
    """Add extension to an existing legacy fixture without freezing the legacy."""
    predecessor = validate_source_exclusion(case.checkpoint, case.config)
    incident_path = case.run / 'integrity_incidents/derived_fixture/incident.json'
    incident_path.parent.mkdir(parents=True, exist_ok=True)
    incident = dict(case.incident, source_file='greek_training/.gitignore')
    incident_path.write_text(json.dumps(incident) + '\n')
    body = dict(predecessor['amendment'])
    body.pop('approved_question')
    body.update(user_instruction=DERIVED_INSTRUCTION, excluded_source_roots=[DERIVED_ROOT],
        mode=DERIVED_MODE, reason=DERIVED_REASON,
        predecessor_run_local_sha256=predecessor['run_local_sha256'],
        predecessor_checkpoint_sha256=predecessor['sha256'],
        integrity_incident_path=str(incident_path.relative_to(case.run)),
        integrity_incident_sha256=hashlib.sha256(incident_path.read_bytes()).hexdigest())
    body.update(changes)
    (case.run / DERIVED_NAME).write_text(json.dumps(body, indent=2) + '\n')
    return body


class DerivedCollectionScopeTests(unittest.TestCase):
    setUp = legacy_fixture.SourceExclusionTests.setUp
    file = legacy_fixture.SourceExclusionTests.file
    seed = legacy_fixture.SourceExclusionTests.seed
    record_scope = legacy_fixture.SourceExclusionTests.record_scope
    amendment = legacy_fixture.SourceExclusionTests.amendment

    def setUp(self):
        # Durability is covered by the existing real-fsync tests.
        self.sync_patch = patch('os.fsync')
        self.sync_patch.start()
        self.addCleanup(self.sync_patch.stop)
        original_connect = inventory._connect
        def connect(path):
            db = original_connect(path)
            db.execute('PRAGMA synchronous=OFF')
            return db
        connect_patch = patch.object(inventory, '_connect', connect)
        connect_patch.start()
        self.addCleanup(connect_patch.stop)
        legacy_fixture.SourceExclusionTests.setUp(self)

    def extension(self):
        self.amendment()
        return create_derived_amendment(self)

    def test_chain_freeze_exact_boundary_and_cached_identity(self):
        self.extension()
        legacy_bytes = (self.run / 'source_exclusion_amendment.json').read_bytes()
        scope = validate_source_exclusion(self.checkpoint, self.config)
        self.assertFalse(scope['frozen'])
        self.assertFalse(scope['predecessor']['frozen'])
        self.assertEqual(scope['artifact'], DERIVED_NAME)
        for name in ('greek_training', 'greek_training/.gitignore', 'greek_training/data.jsonl'):
            self.assertTrue(is_source_excluded(name, scope))
        for name in ('greek_training_temp/data.jsonl', 'nested/greek_training/data.jsonl'):
            self.assertFalse(is_source_excluded(name, scope))
        with self.assertRaises(SourceExclusionConflict):
            validate_source_exclusion_binding({'source_exclusion_amendment_sha256': scope['predecessor']['sha256']}, scope)
        frozen = validate_source_exclusion(self.checkpoint, self.config, freeze=True)
        self.assertTrue(frozen['frozen'] and frozen['predecessor']['frozen'])
        self.assertEqual(legacy_bytes, (self.run / 'source_exclusion_amendment.json').read_bytes())
        self.assertEqual(frozen, validate_source_exclusion(self.checkpoint, self.config))

    def test_inventory_preserves_history_without_accessing_collection(self):
        history = self.file('greek_training/data.jsonl', b'{}\n{}\n')
        self.seed(history)
        self.file('greek_training_temp/data.jsonl', b'{}\n')
        self.extension()
        shard = self.checkpoint / 'inventory_shard_00.sqlite'
        with contextlib.closing(sqlite3.connect(shard)) as db:
            rows = list(db.execute('SELECT * FROM files ORDER BY relative_path'))
            ranges = list(db.execute('SELECT * FROM record_ranges ORDER BY relative_path,first_record'))
        excluded = self.source / 'greek_training'
        real_scandir, real_lstat, real_open = os.scandir, Path.lstat, Path.open
        def guard(path):
            path = Path(path)
            if path == excluded or excluded in path.parents:
                raise AssertionError('accessed excluded collection: ' + str(path))
        def scandir(path):
            guard(path)
            return real_scandir(path)
        def lstat(path, *args, **kwargs):
            guard(path)
            return real_lstat(path, *args, **kwargs)
        def open_path(path, *args, **kwargs):
            guard(path)
            return real_open(path, *args, **kwargs)
        with patch('os.scandir', scandir), patch.object(Path, 'lstat', lstat), patch.object(Path, 'open', open_path):
            result = inventory.run_inventory(self.source, self.checkpoint, self.config)
            self.assertEqual(result, inventory.run_inventory(self.source, self.checkpoint, self.config))
        self.assertEqual(result['statistics']['historical_excluded_files'], 2)
        self.assertEqual(result['statistics']['in_scope_files'], 1)
        self.assertIsNone(result['source_exclusion_accounting']['current_excluded_files'])
        self.assertFalse(result['full_original_source_integrity'])
        with contextlib.closing(sqlite3.connect(shard)) as db:
            for row in rows:
                self.assertEqual(db.execute('SELECT * FROM files WHERE relative_path=?', (row[0],)).fetchone(), row)
            self.assertEqual(list(db.execute("SELECT * FROM record_ranges WHERE relative_path LIKE 'greek_training/%' ORDER BY relative_path,first_record")), ranges)

    def test_integrity_never_reads_collection_and_neighbor_drift_halts(self):
        self.file('greek_training/.gitignore', b'changed ignored metadata')
        neighbor = self.file('greek_training_temp/data.jsonl', b'{}\n')
        self.extension()
        inventory.run_inventory(self.source, self.checkpoint, self.config)
        real_open, real_scandir = integrity.open_source_readonly, os.scandir
        excluded = self.source / 'greek_training'
        def check(path):
            path = Path(path)
            if path == excluded or excluded in path.parents:
                raise AssertionError('integrity accessed excluded collection')
        def open_source(path, *args, **kwargs):
            check(path)
            return real_open(path, *args, **kwargs)
        def scandir(path):
            check(path)
            return real_scandir(path)
        with patch.object(integrity, 'open_source_readonly', open_source), patch('os.scandir', scandir):
            report = integrity.verify_source_hashes(self.source, self.checkpoint,
                self.run / 'source_verification', self.config)
            self.assertTrue(report['passed'])
            self.assertFalse(report['full_original_source_integrity'])
            self.assertEqual(report['current_excluded_coverage'], 'unknown')
            self.assertEqual(report['statistics']['excluded_files'], 1)
            self.assertEqual(report['statistics']['verified_files'], 1)
            neighbor.write_bytes(b'{"changed":true}\n')
            with self.assertRaises(inventory.SourceChangedError):
                integrity.verify_source_hashes(self.source, self.checkpoint,
                    self.run / 'source_verification', self.config)

    def test_similarly_named_collection_changes_still_halt(self):
        path = self.file('greek_training_temp/data.jsonl', b'{}\n')
        self.seed(path)
        self.extension()
        path.write_bytes(b'{"changed":true}\n')
        with self.assertRaises(inventory.SourceChangedError):
            inventory.run_inventory(self.source, self.checkpoint, self.config)

    def test_strict_schema_and_bindings_before_freeze(self):
        original = self.extension()
        changes = ({'excluded_source_roots': ['greek_training_temp']}, {'user_instruction': 'continue'},
            {'mode': 'hash_only'}, {'reason': 'skip'}, {'version': True},
            {'base_inventory_config_sha256': '0' * 64}, {'record_scope_amendment_sha256': '0' * 64},
            {'predecessor_run_local_sha256': '0' * 64}, {'predecessor_checkpoint_sha256': '0' * 64},
            {'integrity_incident_sha256': '0' * 64}, {'extra': True})
        for change in changes:
            with self.subTest(change=change):
                (self.run / DERIVED_NAME).write_text(json.dumps(dict(original, **change)))
                with self.assertRaises(SourceExclusionConflict):
                    validate_source_exclusion(self.checkpoint, self.config, freeze=True)
                self.assertFalse((self.checkpoint / 'source_exclusion_amendment.json').exists())

    def test_frozen_chain_tamper_and_removal(self):
        self.extension()
        scope = validate_source_exclusion(self.checkpoint, self.config, freeze=True)
        paths = [self.run / DERIVED_NAME, self.checkpoint / DERIVED_NAME,
            self.checkpoint / DERIVED_CHECKSUM_NAME,
            self.run / 'source_exclusion_amendment.json',
            self.checkpoint / 'source_exclusion_amendment.json',
            self.checkpoint / 'source_exclusion_amendment.sha256.json',
            self.run / scope['amendment']['integrity_incident_path'], self.incident_path]
        for path in paths:
            original = path.read_bytes()
            with self.subTest(path=path, action='tamper'):
                path.write_bytes(original + b' ')
                if path.name.endswith('sha256.json'):
                    path.write_text('{}')
                with self.assertRaises((SourceExclusionConflict, ValueError)):
                    validate_source_exclusion(self.checkpoint, self.config)
                path.write_bytes(original)
            # Missing one frozen file must never silently downgrade scope.
            with self.subTest(path=path, action='remove'):
                path.unlink()
                if path == self.checkpoint / DERIVED_NAME:
                    recovered = validate_source_exclusion(self.checkpoint, self.config, freeze=True)
                    self.assertEqual(recovered['sha256'], scope['sha256'])
                else:
                    with self.assertRaises((SourceExclusionConflict, ValueError, FileNotFoundError)):
                        validate_source_exclusion(self.checkpoint, self.config)
                path.write_bytes(original)

    def test_interrupted_freeze_recovers_only_with_pinned_identity(self):
        self.extension()
        original_atomic = inventory._atomic_json
        def interrupted(path, body):
            if Path(path) == self.checkpoint / DERIVED_NAME:
                raise OSError('simulated interruption')
            return original_atomic(path, body)
        with patch.object(inventory, '_atomic_json', interrupted):
            with self.assertRaisesRegex(OSError, 'simulated interruption'):
                validate_source_exclusion(self.checkpoint, self.config, freeze=True)
        self.assertTrue((self.checkpoint / DERIVED_CHECKSUM_NAME).exists())
        self.assertFalse((self.checkpoint / DERIVED_NAME).exists())
        authorization = self.run / DERIVED_NAME
        raw = authorization.read_bytes()
        authorization.write_bytes(raw + b' ')
        with self.assertRaises(SourceExclusionConflict):
            validate_source_exclusion(self.checkpoint, self.config, freeze=True)
        authorization.write_bytes(raw)
        result = validate_source_exclusion(self.checkpoint, self.config, freeze=True)
        self.assertTrue(result['frozen'] and result['predecessor']['frozen'])

    def test_completed_inventory_cannot_acquire_extension_or_lose_it(self):
        self.amendment()
        legacy = validate_source_exclusion(self.checkpoint, self.config, freeze=True)
        (self.checkpoint / 'manifest.json').write_text(json.dumps({'complete': True,
            'source_exclusion_amendment_sha256': legacy['sha256']}))
        create_derived_amendment(self)
        with self.assertRaisesRegex(SourceExclusionConflict, 'cannot_amend_completed'):
            validate_source_exclusion(self.checkpoint, self.config, freeze=True)
        (self.checkpoint / 'manifest.json').unlink()
        effective = validate_source_exclusion(self.checkpoint, self.config, freeze=True)
        (self.checkpoint / 'manifest.json').write_text(json.dumps({'complete': True,
            'source_exclusion_amendment_sha256': effective['sha256']}))
        self.assertEqual(effective, validate_source_exclusion(self.checkpoint, self.config))
        for path in (self.run / DERIVED_NAME, self.checkpoint / DERIVED_NAME,
                     self.checkpoint / DERIVED_CHECKSUM_NAME):
            path.unlink()
        with self.assertRaises(SourceExclusionConflict):
            validate_source_exclusion(self.checkpoint, self.config)


if __name__ == '__main__':
    unittest.main()
