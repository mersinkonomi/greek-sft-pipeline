"""A current-scope amendment cannot rewrite completed historical checkpoints."""
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from greek_sft import integrity, inventory
from greek_sft.source_scope import (DERIVED_NAME, TEMPORARY_NAME, TEMPORARY_CHECKSUM_NAME,
    TEMPORARY_FROZEN_DIR, TEMPORARY_ROOT, TEMPORARY_INSTRUCTION, TEMPORARY_QUESTION,
    TEMPORARY_REASON, TEMPORARY_MODE, SourceExclusionConflict, historical_source_exclusion,
    is_source_excluded, source_exclusion_artifact_paths, validate_source_exclusion,
    validate_source_exclusion_binding)
import test_derived_collection_scope as derived_fixture


def create_temporary_amendment(case, **changes):
    """Authorize a synthetic completed fixture; never freeze or rewrite its inventory."""
    predecessor = validate_source_exclusion(case.checkpoint, case.config)
    incident_path = case.run / 'integrity_incidents/temporary_fixture/incident.json'
    incident_path.parent.mkdir(parents=True, exist_ok=True)
    incident = {'run_id': case.run.name, 'status': 'halted_source_integrity_failure',
        'source_file': 'greek_training_temp/data.jsonl', 'sha256_matches': False,
        'baseline_sha256': hashlib.sha256(b'old temporary').hexdigest(),
        'observed_sha256': hashlib.sha256(b'changed temporary').hexdigest()}
    incident_path.write_text(json.dumps(incident) + '\n')
    body = dict(predecessor['amendment'])
    body.update(user_instruction=TEMPORARY_INSTRUCTION, approved_question=TEMPORARY_QUESTION,
        excluded_source_roots=['greek_training', TEMPORARY_ROOT], mode=TEMPORARY_MODE,
        reason=TEMPORARY_REASON, predecessor_run_local_sha256=predecessor['run_local_sha256'],
        predecessor_checkpoint_sha256=predecessor['sha256'],
        integrity_incident_path=str(incident_path.relative_to(case.run)),
        integrity_incident_sha256=hashlib.sha256(incident_path.read_bytes()).hexdigest(),
        inventory_checkpoint_manifest_sha256=hashlib.sha256((case.checkpoint / 'checkpoint_manifest.json').read_bytes()).hexdigest(),
        inventory_manifest_sha256=hashlib.sha256((case.checkpoint / 'manifest.json').read_bytes()).hexdigest(),
        inventory_source_manifest_sha256=json.loads((case.checkpoint / 'manifest.json').read_text())['source_manifest_sha256'])
    body.update(changes)
    (case.run / TEMPORARY_NAME).write_text(json.dumps(body, indent=2) + '\n')
    return body


class TemporaryCollectionScopeTests(unittest.TestCase):
    file = derived_fixture.DerivedCollectionScopeTests.file
    seed = derived_fixture.DerivedCollectionScopeTests.seed
    amendment = derived_fixture.DerivedCollectionScopeTests.amendment
    record_scope = derived_fixture.DerivedCollectionScopeTests.record_scope
    extension = derived_fixture.DerivedCollectionScopeTests.extension

    def setUp(self):
        derived_fixture.DerivedCollectionScopeTests.setUp(self)
        self.temporary_source = self.file('greek_training_temp/data.jsonl', b'{}\n')
        self.neighbor = self.file('greek_training_temp_other/data.jsonl', b'{}\n')
        self.extension()
        inventory.run_inventory(self.source, self.checkpoint, self.config)
        artifacts = [{'path': str(path.relative_to(self.checkpoint)),
                      'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                     for path in sorted(self.checkpoint.rglob('*')) if path.is_file()]
        (self.checkpoint / 'checkpoint_manifest.json').write_text(json.dumps({
            'configuration_hash': hashlib.sha256(inventory._json(self.config).encode()).hexdigest(),
            'artifacts': artifacts}))
        self.historical = validate_source_exclusion(self.checkpoint, self.config)

    def snapshot(self):
        return {str(path.relative_to(self.checkpoint)): path.read_bytes()
                for path in self.checkpoint.rglob('*') if path.is_file()}

    def test_completed_transition_preserves_every_checkpoint_byte(self):
        original = self.snapshot()
        create_temporary_amendment(self)
        readonly = validate_source_exclusion(self.checkpoint, self.config)
        self.assertFalse(readonly['frozen'])
        self.assertEqual(historical_source_exclusion(readonly), self.historical)
        scope = validate_source_exclusion(self.checkpoint, self.config, freeze=True)
        self.assertTrue(scope['frozen'])
        self.assertEqual(original, self.snapshot())
        self.assertEqual(scope, validate_source_exclusion(self.checkpoint, self.config))
        paths = source_exclusion_artifact_paths(self.checkpoint, scope)
        self.assertEqual(paths['frozen'], self.run / TEMPORARY_FROZEN_DIR / TEMPORARY_NAME)
        self.assertEqual(paths['checksum'], self.run / TEMPORARY_FROZEN_DIR / TEMPORARY_CHECKSUM_NAME)
        self.assertTrue(all(path.is_file() for path in paths.values()))
        for relative in ('greek_training', 'greek_training/data', 'greek_training_temp', 'greek_training_temp/data'):
            self.assertTrue(is_source_excluded(relative, scope))
        for relative in ('greek_training_temp_other/a', 'nested/greek_training_temp/a', 'greek_training2/a'):
            self.assertFalse(is_source_excluded(relative, scope))

    def test_historical_binding_is_narrow_and_cannot_be_deserialized_into_authority(self):
        create_temporary_amendment(self)
        scope = validate_source_exclusion(self.checkpoint, self.config, freeze=True)
        row = {'source_exclusion_amendment_sha256': self.historical['sha256']}
        with self.assertRaises(SourceExclusionConflict):
            validate_source_exclusion_binding(row, scope)
        validate_source_exclusion_binding(row, historical_source_exclusion(scope))
        copied = json.loads(json.dumps(scope))
        self.assertIs(historical_source_exclusion(copied), copied)
        with self.assertRaises(SourceExclusionConflict):
            validate_source_exclusion_binding(row, historical_source_exclusion(copied))
        with self.assertRaises(SourceExclusionConflict):
            validate_source_exclusion_binding({'source_exclusion_amendment_sha256': self.historical['predecessor']['sha256']},
                historical_source_exclusion(scope))

    def test_schema_and_inventory_pins_rejected_without_any_freeze(self):
        original = create_temporary_amendment(self)
        for changes in ({'excluded_source_roots': ['greek_training_temp']}, {'version': True},
            {'user_instruction': 'leave it'}, {'approved_question': 'another question'},
            {'mode': 'skip'}, {'reason': 'skip'}, {'base_inventory_config_sha256': '0' * 64},
            {'predecessor_run_local_sha256': '0' * 64}, {'predecessor_checkpoint_sha256': '0' * 64},
            {'inventory_checkpoint_manifest_sha256': '0' * 64}, {'inventory_manifest_sha256': '0' * 64},
            {'inventory_source_manifest_sha256': '0' * 64}, {'record_scope_amendment_sha256': '0' * 64},
            {'integrity_incident_path': '../outside.json'}, {'extra': True}):
            with self.subTest(changes=changes):
                (self.run / TEMPORARY_NAME).write_text(json.dumps(dict(original, **changes)))
                with self.assertRaises((SourceExclusionConflict, ValueError)):
                    validate_source_exclusion(self.checkpoint, self.config, freeze=True)
                self.assertFalse((self.run / TEMPORARY_FROZEN_DIR).exists())

    def test_wrong_collection_incident_and_incomplete_inventory_are_rejected(self):
        body = create_temporary_amendment(self)
        incident_path = self.run / body['integrity_incident_path']
        original_incident = incident_path.read_bytes()
        incident = json.loads(original_incident)
        incident['source_file'] = 'greek_training/.gitignore'
        incident_path.write_text(json.dumps(incident))
        body['integrity_incident_sha256'] = hashlib.sha256(incident_path.read_bytes()).hexdigest()
        (self.run / TEMPORARY_NAME).write_text(json.dumps(body))
        with self.assertRaisesRegex(SourceExclusionConflict, 'temporary_incident_not_applicable'):
            validate_source_exclusion(self.checkpoint, self.config, freeze=True)
        self.assertFalse((self.run / TEMPORARY_FROZEN_DIR).exists())
        incident_path.write_bytes(original_incident)
        body['integrity_incident_sha256'] = hashlib.sha256(original_incident).hexdigest()
        manifest_path = self.checkpoint / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        manifest['complete'] = False
        manifest_path.write_text(json.dumps(manifest))
        body['inventory_manifest_sha256'] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        checkpoint_path = self.checkpoint / 'checkpoint_manifest.json'
        checkpoint = json.loads(checkpoint_path.read_text())
        for item in checkpoint['artifacts']:
            if item['path'] == 'manifest.json':
                item['sha256'] = body['inventory_manifest_sha256']
        checkpoint_path.write_text(json.dumps(checkpoint))
        body['inventory_checkpoint_manifest_sha256'] = hashlib.sha256(checkpoint_path.read_bytes()).hexdigest()
        (self.run / TEMPORARY_NAME).write_text(json.dumps(body))
        with self.assertRaisesRegex(SourceExclusionConflict, 'historical_inventory_identity_changed'):
            validate_source_exclusion(self.checkpoint, self.config, freeze=True)
        self.assertFalse((self.run / TEMPORARY_FROZEN_DIR).exists())

    def test_frozen_chain_and_original_metadata_tampering_or_removal_rejected(self):
        create_temporary_amendment(self)
        scope = validate_source_exclusion(self.checkpoint, self.config, freeze=True)
        paths = list(source_exclusion_artifact_paths(self.checkpoint, scope).values())
        predecessor = scope['predecessor']
        while predecessor:
            paths.extend(source_exclusion_artifact_paths(self.checkpoint, predecessor).values())
            predecessor = predecessor.get('predecessor')
        paths.extend(self.checkpoint / name for name in ('manifest.json', 'checkpoint_manifest.json'))
        for path in paths:
            original = path.read_bytes()
            with self.subTest(path=path, mutation='tamper'):
                path.write_bytes(b'{}' if path.name.endswith('sha256.json') else original + b' ')
                with self.assertRaises((SourceExclusionConflict, ValueError)):
                    validate_source_exclusion(self.checkpoint, self.config)
                path.write_bytes(original)
            with self.subTest(path=path, mutation='remove'):
                path.unlink()
                if path == self.run / TEMPORARY_FROZEN_DIR / TEMPORARY_NAME:
                    recovered = validate_source_exclusion(self.checkpoint, self.config, freeze=True)
                    self.assertEqual(recovered['sha256'], scope['sha256'])
                else:
                    with self.assertRaises((SourceExclusionConflict, ValueError, FileNotFoundError)):
                        validate_source_exclusion(self.checkpoint, self.config)
                path.write_bytes(original)

    def test_interrupted_freeze_recovers_with_checksum_and_symlinks_are_rejected(self):
        create_temporary_amendment(self)
        real_atomic = inventory._atomic_json
        copy = self.run / TEMPORARY_FROZEN_DIR / TEMPORARY_NAME
        def interrupt(path, body):
            if Path(path) == copy:
                raise OSError('interrupted temporary freeze')
            return real_atomic(path, body)
        with patch.object(inventory, '_atomic_json', interrupt):
            with self.assertRaises(OSError):
                validate_source_exclusion(self.checkpoint, self.config, freeze=True)
        self.assertFalse(copy.exists())
        self.assertTrue(copy.with_name(TEMPORARY_CHECKSUM_NAME).exists())
        scope = validate_source_exclusion(self.checkpoint, self.config, freeze=True)
        self.assertTrue(scope['frozen'])
        raw = copy.read_bytes()
        copy.unlink()
        target = self.base / 'linked_copy'
        target.write_bytes(raw)
        copy.symlink_to(target)
        with self.assertRaises(ValueError):
            validate_source_exclusion(self.checkpoint, self.config)

    def test_fresh_verifier_never_reads_either_root_but_rejects_other_changes(self):
        create_temporary_amendment(self)
        scope = validate_source_exclusion(self.checkpoint, self.config, freeze=True)
        self.temporary_source.write_bytes(b'changed ignored temporary data')
        real_open, real_scandir = integrity.open_source_readonly, os.scandir
        def guard(path):
            path = Path(path)
            if path != self.source and self.source not in path.parents:
                return
            relative = path.relative_to(self.source).as_posix()
            if relative != '.' and is_source_excluded(relative, scope):
                raise AssertionError('entered excluded source')
        def open_source(path, *args, **kwargs):
            guard(path)
            return real_open(path, *args, **kwargs)
        def scandir(path):
            guard(path)
            return real_scandir(path)
        with patch.object(integrity, 'open_source_readonly', open_source), patch('os.scandir', scandir):
            first = integrity.verify_source_hashes(self.source, self.checkpoint, self.run / 'verification', self.config)
            self.assertTrue(first['passed'])
            self.assertFalse(first['full_original_source_integrity'])
            self.assertEqual(first['statistics']['excluded_files'], 2)
            self.assertEqual(first['statistics']['verified_files'], 1)
            self.assertEqual(first['source_exclusion_amendment_sha256'], scope['sha256'])
            self.neighbor.write_bytes(b'changed in-scope data')
            with self.assertRaises(inventory.SourceChangedError):
                integrity.verify_source_hashes(self.source, self.checkpoint, self.run / 'verification', self.config)
        reports = list((self.run / 'verification').glob('attempt_*/source_integrity.json'))
        self.assertEqual(len(reports), 2)
        self.assertEqual(sum(json.loads(path.read_text())['passed'] for path in reports), 1)


if __name__ == '__main__':
    unittest.main()
