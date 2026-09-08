"""Approved Git exclusions never become false full-source integrity claims."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from greek_sft import integrity
from greek_sft.core import PIPELINE_ROOT
from greek_sft.inventory import SourceChangedError, _fingerprint, _json
from greek_sft.source_scope import APPROVED_QUESTION, SourceExclusionConflict, validate_source_exclusion


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')


def freeze_exclusion_fixture(run, checkpoint, config, baseline_hash, observed_hash):
    """Freeze a synthetic incident-bound amendment before marking inventory complete."""
    incident_path = 'integrity_incidents/fixture/incident.json'
    incident = {'run_id': run.name, 'status': 'halted_source_integrity_failure',
        'source_file': 'greek_training/.git/index', 'sha256_matches': False,
        'baseline_sha256': baseline_hash, 'observed_sha256': observed_hash}
    write_json(run / incident_path, incident)
    amendment = {'version': 1, 'run_id': run.name, 'authorized_at': '2026-09-07T14:00:00+00:00',
        'user_instruction': 'continue', 'approved_question': APPROVED_QUESTION,
        'excluded_source_roots': ['greek_training/.git'], 'mode': 'exclude_subtree_from_current_source_coverage',
        'base_inventory_config_sha256': hashlib.sha256(_json(config).encode()).hexdigest(),
        'record_scope_amendment_sha256': None, 'integrity_incident_path': incident_path,
        'integrity_incident_sha256': hashlib.sha256((run / incident_path).read_bytes()).hexdigest(),
        'preserve_historical_inventory': True, 'full_original_source_integrity_claim_allowed': False,
        'current_excluded_coverage': 'unknown'}
    write_json(run / 'source_exclusion_amendment.json', amendment)
    return validate_source_exclusion(checkpoint, config, freeze=True)


class SourceExclusionIntegrityTests(unittest.TestCase):
    def setUp(self):
        parent = PIPELINE_ROOT / 'runtime' / 'source_exclusion_integrity_tests'
        parent.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='case_', dir=parent)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'synthetic_source'
        self.run = self.root / 'run'
        self.checkpoint = self.run / 'checkpoint_01_inventory'
        self.output = self.run / 'source_verification'
        self.checkpoint.mkdir(parents=True)
        self.config = {'workers': 2}
        write_json(self.run / 'configuration.json', self.config)
        fixtures = {
            'data.jsonl': '{"text":"Συνθετικό ελληνικό κείμενο."}\n'.encode(),
            'greek_training/.git/index': b'historical git index',
            'greek_training/.git/known.jsonl': b'{"historical":true}\n',
            'greek_training/.git2/neighbor.jsonl': b'{"outside_exclusion":true}\n',
            'greek_training/.github/keep.txt': b'neighbor metadata remains protected',
        }
        self.baseline = []
        for relative, raw in sorted(fixtures.items()):
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            self.baseline.append({'relative_path': relative, 'sha256': hashlib.sha256(raw).hexdigest(),
                'size_bytes': len(raw), 'stat_fingerprint': _fingerprint(path.stat())})
        self.manifest = self.checkpoint / 'source_manifest.jsonl'
        self.manifest.write_text(''.join(json.dumps(row, sort_keys=True) + '\n' for row in self.baseline))
        original = next(row for row in self.baseline if row['relative_path'] == 'greek_training/.git/index')
        changed = b'changed git index after external activity'
        (self.source / original['relative_path']).write_bytes(changed)
        self.scope = freeze_exclusion_fixture(self.run, self.checkpoint, self.config, original['sha256'], hashlib.sha256(changed).hexdigest())
        write_json(self.checkpoint / 'manifest.json', {'complete': True,
            'source_manifest_sha256': hashlib.sha256(self.manifest.read_bytes()).hexdigest(),
            'source_exclusion_amendment_sha256': self.scope['sha256']})
        # Durability is covered elsewhere. These tests retain real descriptors,
        # filesystem state and SQLite joins while avoiding shared-disk sync waits.
        syncing = mock.patch('greek_sft.integrity.os.fsync')
        syncing.start(); self.addCleanup(syncing.stop)

    def verify(self):
        return integrity.verify_source_hashes(self.source, self.checkpoint, self.output, self.config)

    def rows(self, report):
        return [json.loads(raw) for raw in (self.run / report['source_hashes_path']).read_text().splitlines()]

    def test_scoped_mutation_addition_and_removal_never_open_excluded_sources(self):
        (self.source / 'greek_training/.git/known.jsonl').unlink()
        (self.source / 'greek_training/.git/new_uninventoried.bin').write_bytes(b'unknown current excluded file')
        real_open, real_scandir = integrity.open_source_readonly, os.scandir
        reads = []
        def protected_open(path, *args, **kwargs):
            relative = Path(path).relative_to(self.source).as_posix()
            self.assertFalse(relative == 'greek_training/.git' or relative.startswith('greek_training/.git/'))
            reads.append(relative)
            return real_open(path, *args, **kwargs)
        def protected_scandir(path):
            self.assertNotEqual(Path(path), self.source / 'greek_training/.git')
            return real_scandir(path)
        with mock.patch.object(integrity, 'open_source_readonly', side_effect=protected_open), mock.patch.object(integrity.os, 'scandir', side_effect=protected_scandir):
            report = self.verify()
        self.assertTrue(report['passed'])
        self.assertTrue(report['complete'])
        self.assertFalse(report['full_original_source_integrity'])
        self.assertFalse(report['full_original_source_coverage'])
        self.assertEqual(report['verification_scope'], 'approved_current_source_scope')
        self.assertEqual(report['source_exclusion_amendment'], self.scope)
        self.assertEqual(report['current_excluded_coverage'], 'unknown')
        self.assertIsNone(report['current_excluded_files'])
        stats = report['statistics']
        self.assertEqual(stats['expected_files'], 5)
        self.assertEqual(stats['verified_files'], 3)
        self.assertEqual(stats['excluded_files'], 2)
        self.assertEqual(stats['unverified_files'], 2)
        self.assertEqual(stats['scoped_unverified_files'], 0)
        self.assertEqual(stats['scoped_expected_files'], 3)
        self.assertEqual(stats['final_rechecked_files'], 3)
        self.assertCountEqual(reads, ['data.jsonl', 'greek_training/.git2/neighbor.jsonl', 'greek_training/.github/keep.txt'])
        rows = self.rows(report)
        self.assertEqual(len(rows), 5)
        for row in rows:
            baseline = next(old for old in self.baseline if old['relative_path'] == row['relative_path'])
            if row['status'] == 'excluded_by_user':
                self.assertEqual(row['baseline_sha256'], baseline['sha256'])
                self.assertEqual(row['baseline_size_bytes'], baseline['size_bytes'])
                self.assertIsNone(row['sha256']); self.assertIsNone(row['size_bytes'])
                self.assertEqual(row['bytes_hashed'], 0)
                self.assertEqual(row['source_exclusion_amendment_sha256'], self.scope['sha256'])
            else:
                self.assertEqual(row['status'], 'unchanged')
                self.assertEqual(row['sha256'], baseline['sha256'])

    def test_neighbor_git2_mutation_still_fails(self):
        (self.source / 'greek_training/.git2/neighbor.jsonl').write_bytes(b'changed protected neighbor')
        with self.assertRaises(SourceChangedError):
            self.verify()
        reports = list(self.output.glob('attempt_*/source_integrity.json'))
        report = json.loads(reports[0].read_text())
        self.assertFalse(report['passed'])
        self.assertEqual(report['failure']['relative_path'], 'greek_training/.git2/neighbor.jsonl')

    def test_neighbor_github_removal_still_fails(self):
        (self.source / 'greek_training/.github/keep.txt').unlink()
        with self.assertRaises(SourceChangedError):
            self.verify()
        report = json.loads(next(self.output.glob('attempt_*/source_integrity.json')).read_text())
        self.assertFalse(report['passed'])
        self.assertEqual(report['failure']['relative_path'], 'greek_training/.github/keep.txt')

    def test_historical_excluded_hash_spoof_is_not_hidden_by_filtering(self):
        rows = [json.loads(raw) for raw in self.manifest.read_text().splitlines()]
        for row in rows:
            if row['relative_path'] == 'greek_training/.git/index':
                row['sha256'] = 'f' * 64
        self.manifest.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        with mock.patch.object(integrity, '_read_block') as read:
            with self.assertRaises(SourceChangedError):
                self.verify()
            read.assert_not_called()
        report = json.loads(next(self.output.glob('attempt_*/source_integrity.json')).read_text())
        self.assertFalse(report['baseline_manifest_verified'])
        self.assertEqual(report['failure']['reason'], 'immutable_inventory_manifest_changed')

    def test_tampered_or_removed_authorization_never_starts_reads(self):
        path = self.run / 'source_exclusion_amendment.json'
        original = path.read_bytes()
        amendment = json.loads(original)
        amendment['excluded_source_roots'] = ['greek_training']
        write_json(path, amendment)
        with mock.patch.object(integrity, '_read_block') as read:
            with self.assertRaises(SourceExclusionConflict):
                self.verify()
            read.assert_not_called()
        path.write_bytes(original)
        path.unlink()
        with self.assertRaises(SourceExclusionConflict):
            self.verify()

    def test_changed_incident_and_configuration_are_rejected(self):
        incident = self.run / self.scope['amendment']['integrity_incident_path']
        original = incident.read_bytes()
        incident.write_bytes(original + b' ')
        with self.assertRaises(SourceExclusionConflict):
            self.verify()
        incident.write_bytes(original)
        with self.assertRaises(SourceExclusionConflict):
            integrity.verify_source_hashes(self.source, self.checkpoint, self.output, {'workers': 3})

    def test_scope_is_reauthenticated_after_hashing(self):
        real_result = integrity._source_result
        modified = []
        def mutate_authorization(*args, **kwargs):
            result = real_result(*args, **kwargs)
            if not modified:
                modified.append(True)
                incident = self.run / self.scope['amendment']['integrity_incident_path']
                incident.write_bytes(incident.read_bytes() + b' ')
            return result
        with mock.patch.object(integrity, '_source_result', side_effect=mutate_authorization):
            with self.assertRaises(SourceChangedError):
                self.verify()
        report = json.loads(next(self.output.glob('attempt_*/source_integrity.json')).read_text())
        self.assertFalse(report['passed'])
        self.assertEqual(report['failure']['error_type'], 'SourceExclusionConflict')


if __name__ == '__main__':
    unittest.main()
