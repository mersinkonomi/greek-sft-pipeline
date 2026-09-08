"""Independent accounting must reject equal-count swaps, drift, and missing rows."""
import copy
import json
import tempfile
import unittest
from unittest import mock
import sqlite3
from pathlib import Path

from greek_sft.core import digest, sha256_file
from greek_sft.reporting import CHECKPOINTS, STAGES, create_audited_release

ROOT = Path(__file__).resolve().parents[1]


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')


def write_rows(path, values):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(''.join(json.dumps(v, ensure_ascii=False) + '\n' for v in values), encoding='utf-8')


class ReportingTests(unittest.TestCase):
    def setUp(self):
        # These tests exercise joins and accounting, not power-loss durability.
        # Keep real files/SQLite but avoid concurrent journal/fsync stalls on the
        # corpus disk. Production code retains full syncing and atomic attempts.
        original_connect = sqlite3.connect
        def fast_connection(*args, **kwargs):
            connection = original_connect(*args, **kwargs)
            connection.execute("PRAGMA synchronous=OFF")
            return connection
        fsync_patch = mock.patch('greek_sft.reporting.os.fsync')
        sqlite_patch = mock.patch('greek_sft.reporting.sqlite3.connect', side_effect=fast_connection)
        fsync_patch.start(); sqlite_patch.start()
        self.addCleanup(fsync_patch.stop); self.addCleanup(sqlite_patch.stop)
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / 'runtime/tmp')
        self.addCleanup(self.temporary.cleanup)
        self.run = Path(self.temporary.name) / 'run'; self.run.mkdir()
        self.c = {n: self.run / name for n, name in CHECKPOINTS.items()}
        self.family = 'synthetic_family'
        self.source_file = self.family + '/data.jsonl'
        self.file_hash = 'a' * 64
        self.raw = [self.candidate(i) for i in range(1, 8)]
        self.validated = [self.valid(c) for c in self.raw[1:]]
        self.clean = self.validated[1:]
        self.final = copy.deepcopy(self.clean[-1])
        self.final['metadata'].update(split='train', dedup_group=self.final['id'])
        self.manifest = [
            {'relative_path': self.source_file, 'family': self.family, 'record_count': 8,
             'record_boundary_complete': True, 'sha256': self.file_hash, 'size_bytes': 1234,
             'status': 'license_blocked', 'reason': 'license_unknown'},
            {'relative_path': 'opaque.bin', 'family': 'opaque', 'record_count': 0,
             'record_boundary_complete': False, 'sha256': 'b' * 64, 'size_bytes': 2,
             'status': 'unsupported', 'reason': 'unknown_binary_record_boundaries'},
            {'relative_path': 'text/data.jsonl', 'family': 'text', 'record_count': 2,
             'record_boundary_complete': True, 'sha256': 'c' * 64, 'size_bytes': 456,
             'status': 'license_blocked', 'reason': 'license_unknown'},
        ]
        write_rows(self.c[1] / 'source_manifest.jsonl', self.manifest)
        self.inventory_audit = {
            'identified_accounting_passed': True, 'complete_semantic_record_coverage': False,
            'totals': {'files': 3, 'records': 10, 'bytes': 1692, 'unresolved_boundary_files': 1},
            'input_identity': {'manifest_sha256': sha256_file(self.c[1] / 'source_manifest.jsonl')},
        }
        dispositions = []
        for row in self.manifest:
            dispositions.append({'source_file': row['relative_path'], 'family': row['family'],
                'record_count': row['record_count'], 'record_start': 1 if row['record_count'] else None,
                'record_end': row['record_count'], 'record_boundary_complete': row['record_boundary_complete'],
                'status': 'accepted' if row['family'] == self.family else 'quarantined',
                'reason': 'individual_statuses_in_family_shard' if row['family'] == self.family else 'unsupported_task_family'})
        write_rows(self.c[2] / 'source_dispositions.jsonl', dispositions)
        dispositions[0]['shard'] = 'shards/synthetic'
        write_rows(self.c[3] / 'source_dispositions.jsonl', dispositions)
        self.shard = self.c[3] / 'shards/synthetic'
        write_rows(self.shard / 'candidates.jsonl', self.raw)
        generated = [{'source_file': self.source_file, 'source_line': c['metadata']['source_line'],
                      'source_record_hash': c['metadata']['source_record_hash'], 'status': 'accepted',
                      'reason': 'internal_candidate_constructed', 'example_id': c['id']} for c in self.raw]
        rejected = {'source_file': self.source_file, 'source_line': 8, 'source_record_hash': 'f' * 64,
                    'status': 'malformed', 'reason': 'malformed_json_or_encoding'}
        write_rows(self.shard / 'record_dispositions.jsonl', generated + [rejected])
        write_rows(self.shard / 'rejected.jsonl', [rejected])
        write_rows(self.c[4] / 'validated.jsonl', self.validated)
        write_rows(self.c[4] / 'quarantined.jsonl', [{'candidate': self.raw[0], 'status': 'quarantined', 'reasons': ['license_unverified']}])
        write_rows(self.c[4] / 'record_decisions.jsonl', [{'example_id': c['id'], 'source_name': self.family,
                    'status': 'quarantined' if i == 0 else 'accepted', 'reasons': ['license_unverified'] if i == 0 else [],
                    'schema_passed': True, 'content_checks_passed': True, 'greek_statistics': {'greek_ratio': .99}}
                    for i, c in enumerate(self.raw)])
        contamination = self.c[4] / 'contamination'
        write_rows(contamination / 'clean_candidates.jsonl', self.clean)
        write_rows(contamination / 'contaminated_candidates.jsonl', [{'candidate': self.validated[0], 'reason': 'benchmark_contamination'}])
        write_json(contamination / 'report.json', {'complete': False, 'private_scope_confirmed': False,
            'counts': {'input': 6, 'quarantined': 1, 'clean_against_available_evaluations': 5}, 'references': []})
        self.complete = self.c[5] / 'completed'
        current = self.clean
        for stage in STAGES:
            write_rows(self.complete / stage / 'survivors.jsonl', current[1:])
            write_rows(self.complete / stage / 'removals.jsonl', [{'example_id': current[0]['id'],
                'keeper_id': current[1]['id'], 'stage': stage[3:], 'reason': 'synthetic_duplicate', 'record': current[0]}])
            write_json(self.complete / stage / 'statistics.json', {'entering': len(current), 'surviving': len(current)-1, 'removed': 1})
            current = current[1:]
        pre_api = self.complete / 'pre_api'
        write_rows(pre_api / 'balancing_removals.jsonl', [{'example_id': current[0]['id'], 'record': current[0], 'reason': 'post_dedup_domain_cap_whole_group'}])
        for split in ('train', 'validation', 'test'):
            selected = [self.final] if split == 'train' else []
            write_rows(pre_api / split / 'canonical.jsonl', selected)
            write_rows(pre_api / split / 'messages.jsonl', [{'messages': c['messages']} for c in selected])
        write_rows(pre_api / 'near_pairs.jsonl', [])
        write_json(pre_api / 'leakage.json', {'passed': True, 'remaining_exact_duplicates': 0,
                   'cross_split_near_pairs': 0, 'cross_split_group_violations': 0})
        write_json(pre_api / 'fertility.json', {'status': 'measured', 'mean_fertility': 3.2, 'packing_blocked': True})
        write_json(self.run / 'configuration.json', {'seed': 1729})
        self.results = {'1': {'statistics': {'files': 3, 'records': 10, 'bytes': 1692}},
            '2': {'source_files': 3, 'source_records': 10},
            '3': {'source_files': 3, 'source_records': 10, 'classified_records': 10, 'candidates': 7},
            '4': {'candidates_entering': 7, 'candidates_leaving': 6},
            '5': {'input_candidates': 5, 'awaiting_api_review': 1, 'dedup_removed': 3, 'domain_cap_removed': 1}}
        for n, checkpoint in self.c.items():
            write_json(checkpoint / 'statistics.json', self.results[str(n)])
        self.review = {'candidates': 1}
        self.verification = {'passed': True, 'statistics': {'expected_files': 3, 'verified_files': 3, 'unverified_files': 0},
            'source_hashes_path': 'source_verifications/attempt/source_hashes_after.jsonl',
            'integrity_report_path': 'source_verifications/attempt/source_integrity.json'}
        write_rows(self.run / self.verification['source_hashes_path'], [
            {'relative_path': row['relative_path'], 'sha256': row['sha256'], 'size_bytes': row['size_bytes'], 'status': 'unchanged'}
            for row in self.manifest])
        write_json(self.run / self.verification['integrity_report_path'], self.verification)

    def candidate(self, number):
        record_hash = digest({'record': number})
        version, task = 'synthetic-v1', 'classification'
        identity = digest({'family': self.family, 'file': self.source_file, 'line': number,
                           'record_hash': record_hash, 'task': task, 'version': version})
        return {'id': identity, 'messages': [{'role': 'system', 'content': 'Απάντησε στα ελληνικά.'},
            {'role': 'user', 'content': f'Αξιολόγησε την τεκμηριωμένη πρόταση με αριθμό {number}.'},
            {'role': 'assistant', 'content': 'θετική'}], 'metadata': {
                'language': 'el', 'locale': 'el-GR', 'source_name': self.family, 'source_file': self.source_file,
                'source_record_id': str(number), 'source_line': number, 'source_record_hash': record_hash,
                'source_file_hash': self.file_hash, 'task_type': task, 'generation_method': 'deterministic_source_annotation',
                'generator_version': version, 'template_version': version, 'grounded': True,
                'split_group': digest({'entity': number}), 'validation_status': 'pending', 'review_status': 'pending',
                'license_status': 'verified', 'privacy_status': 'approved', 'domain': 'synthetic'}}

    @staticmethod
    def valid(candidate):
        candidate = copy.deepcopy(candidate); candidate['metadata']['validation_status'] = 'passed'
        return candidate

    def audit(self):
        result = create_audited_release(self.run, self.results, self.review, self.verification, self.inventory_audit)
        return result, json.loads((self.run / result['report_path']).read_text())

    def test_exact_partitions_and_immutable_audit_attempts(self):
        before = {str(p.relative_to(self.run)): sha256_file(p) for p in self.run.rglob('*') if p.is_file()}
        result, report = self.audit()
        self.assertTrue(result['accounting_passed'], report['error_counts'])
        self.assertEqual(result['candidate_count'], 1)
        self.assertFalse(report['release_ready'])
        self.assertEqual(report['measured']['identified_source_records'], 10)
        self.assertFalse(report['gates']['complete_semantic_record_coverage']['passed'])
        self.assertEqual(report['measured']['dedup_removed'], 3)
        self.assertIsNone(report['api']['acceptance_rate'])
        self.assertEqual(report['counts']['split'], {'train': 1})
        output = self.run / result['audit_path']
        self.assertEqual(len((output / 'candidate_dispositions.jsonl').read_text().splitlines()), 7)
        self.assertEqual(len((output / 'source_dispositions.jsonl').read_text().splitlines()), 3)
        self.assertNotIn('Αξιολόγησε', (output / 'candidate_dispositions.jsonl').read_text())
        for line in (output / 'SHA256SUMS').read_text().splitlines():
            checksum, name = line.split('  ', 1)
            self.assertEqual(sha256_file(output / name), checksum)
        audit_before = {p.name: sha256_file(p) for p in output.iterdir() if p.is_file()}
        again, _ = self.audit()
        self.assertNotEqual(result['audit_path'], again['audit_path'])
        self.assertEqual(audit_before, {p.name: sha256_file(p) for p in output.iterdir() if p.is_file()})
        self.assertEqual(before, {name: sha256_file(self.run / name) for name in before})

    def test_all_candidates_quarantined_reconcile_without_opening_release_gates(self):
        write_rows(self.c[4] / 'validated.jsonl', [])
        write_rows(self.c[4] / 'quarantined.jsonl', [
            {'candidate': candidate, 'status': 'quarantined', 'reasons': ['license_unverified']}
            for candidate in self.raw])
        write_rows(self.c[4] / 'record_decisions.jsonl', [
            {'example_id': candidate['id'], 'source_name': self.family, 'status': 'quarantined',
             'reasons': ['license_unverified'], 'schema_passed': True, 'content_checks_passed': True,
             'greek_statistics': {'greek_ratio': .99}}
            for candidate in self.raw])
        contamination = self.c[4] / 'contamination'
        write_rows(contamination / 'clean_candidates.jsonl', [])
        write_rows(contamination / 'contaminated_candidates.jsonl', [])
        # The real checker omits zero-valued Counter entries on empty input.
        write_json(contamination / 'report.json', {
            'complete': False, 'private_scope_confirmed': False, 'counts': {}, 'references': []})
        for stage in STAGES:
            write_rows(self.complete / stage / 'survivors.jsonl', [])
            write_rows(self.complete / stage / 'removals.jsonl', [])
            write_json(self.complete / stage / 'statistics.json', {'entering': 0, 'surviving': 0, 'removed': 0})
        pre_api = self.complete / 'pre_api'
        write_rows(pre_api / 'balancing_removals.jsonl', [])
        for split in ('train', 'validation', 'test'):
            write_rows(pre_api / split / 'canonical.jsonl', [])
            write_rows(pre_api / split / 'messages.jsonl', [])
        write_rows(pre_api / 'near_pairs.jsonl', [])
        write_json(pre_api / 'fertility.json', {
            'status': 'not_applicable', 'reason': 'No candidate words to measure',
            'mean_fertility': None, 'packing_blocked': True})
        self.results['4'].update(candidates_leaving=0)
        self.results['5'].update(input_candidates=0, awaiting_api_review=0, dedup_removed=0, domain_cap_removed=0)
        for number in (4, 5):
            write_json(self.c[number] / 'statistics.json', self.results[str(number)])
        self.review['candidates'] = 0

        result, report = self.audit()
        self.assertTrue(result['accounting_passed'], report['error_counts'])
        self.assertEqual(result['candidate_count'], 0)
        self.assertFalse(result['release_ready'])
        self.assertEqual(report['measured']['raw_candidates'], 7)
        self.assertEqual(report['measured']['deterministic_quarantined'], 7)
        self.assertEqual(report['measured']['deterministic_accepted'], 0)
        self.assertEqual(report['measured']['awaiting_api_review'], 0)
        self.assertEqual(report['measured']['released_records'], 0)
        for name in ('all_api_reviews_accepted', 'verified_licenses', 'sensitive_data', 'release_auditor'):
            self.assertFalse(report['gates'][name]['passed'], name)
        for rates in [report['api'], *(row['api_review'] for row in report['by_source'].values())]:
            for name in ('acceptance_rate', 'revision_rate', 'rejection_rate'):
                self.assertIsNone(rates[name])
        rows = [json.loads(line) for line in (self.run / result['audit_path'] / 'candidate_dispositions.jsonl').read_text().splitlines()]
        self.assertEqual(len(rows), 7)
        self.assertTrue(all(row['status'] == 'quarantined' and row['terminal_stage'] == 'quarantine' for row in rows))

    def test_equal_counts_do_not_hide_foreign_candidate_identity(self):
        survivors = self.complete / STAGES[1] / 'survivors.jsonl'
        rows = [json.loads(line) for line in survivors.read_text().splitlines()]
        rows[0]['id'] = 'foreign-but-same-count'
        write_rows(survivors, rows)
        result, report = self.audit()
        self.assertFalse(result['accounting_passed'])
        self.assertIn('partition_foreign_identity', report['error_counts'])
        self.assertIn('partition_missing_or_multiple', report['error_counts'])

    def test_content_drift_is_rejected_even_when_id_and_count_match(self):
        modified = copy.deepcopy(self.final)
        modified['messages'][2]['content'] = 'Αλλαγμένη απάντηση.'
        write_rows(self.complete / 'pre_api/train/canonical.jsonl', [modified])
        result, report = self.audit()
        self.assertFalse(result['accounting_passed'])
        self.assertIn('partition_content_changed', report['error_counts'])
        self.assertIn('training_export_mismatch', report['error_counts'])

    def test_every_file_disposition_must_match_inventory_boundaries(self):
        path = self.c[2] / 'source_dispositions.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows[1]['record_boundary_complete'] = True
        rows[-1]['source_file'] = 'absent/source.jsonl'
        write_rows(path, rows)
        result, report = self.audit()
        self.assertFalse(result['accounting_passed'])
        self.assertIn('source_disposition_inventory_mismatch', report['error_counts'])
        self.assertIn('foreign_disposition_file', report['error_counts'])
        self.assertIn('missing_source_disposition', report['error_counts'])

    def test_missing_record_and_rejection_are_explicit(self):
        path = self.shard / 'record_dispositions.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        write_rows(path, rows[:-1])
        result, report = self.audit()
        self.assertFalse(result['accounting_passed'])
        self.assertIn('generated_file_record_coverage_mismatch', report['error_counts'])
        self.assertIn('foreign_generation_rejection', report['error_counts'])

    def test_invalid_accepted_schema_and_missing_decision_fail(self):
        changed = copy.deepcopy(self.final)
        del changed['metadata']['language']
        write_rows(self.complete / 'pre_api/train/canonical.jsonl', [changed])
        path = self.c[4] / 'record_decisions.jsonl'
        write_rows(path, [json.loads(line) for line in path.read_text().splitlines()][1:])
        result, report = self.audit()
        self.assertFalse(result['accounting_passed'])
        self.assertIn('candidate_canonical_schema_failed', report['error_counts'])
        self.assertIn('candidate_validation_decision_missing', report['error_counts'])
        self.assertFalse(report['gates']['canonical_schema']['passed'])

    def test_manifest_audit_and_api_estimate_are_identity_checked(self):
        self.inventory_audit['input_identity']['manifest_sha256'] = '0' * 64
        self.review['candidates'] = 0
        result, report = self.audit()
        self.assertFalse(result['accounting_passed'])
        self.assertIn('inventory_audit_manifest_mismatch', report['error_counts'])
        self.assertIn('api_estimate_candidate_count_mismatch', report['error_counts'])

    def test_unsafe_verifier_references_fail_the_source_integrity_gate(self):
        for field, expected_error in (
                ('source_hashes_path', 'invalid_source_verification_artifact_reference'),
                ('integrity_report_path', 'invalid_source_integrity_report_reference')):
            with self.subTest(field=field):
                original = self.verification[field]
                self.verification[field] = '../outside-run.jsonl'
                result, report = self.audit()
                self.verification[field] = original
                self.assertFalse(result['accounting_passed'])
                self.assertIn(expected_error, report['error_counts'])
                self.assertFalse(report['gates']['source_hashes_unchanged']['passed'])

    def test_source_hashes_are_rejoined_not_trusted_as_a_pass_flag(self):
        path = self.run / self.verification['source_hashes_path']
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows[0]['sha256'] = '0' * 64
        rows[1] = copy.deepcopy(rows[2])  # equal file count hides one omitted file
        write_rows(path, rows)
        result, report = self.audit()
        self.assertFalse(result['accounting_passed'])
        self.assertIn('source_verification_hash_or_size_mismatch', report['error_counts'])
        self.assertIn('source_verification_duplicate_file', report['error_counts'])
        self.assertIn('source_verification_missing_file', report['error_counts'])
        self.assertFalse(report['gates']['source_hashes_unchanged']['passed'])

    def test_deterministic_candidate_id_is_reconstructed(self):
        rows = copy.deepcopy(self.raw)
        rows[0]['id'] = 'forged-id'
        write_rows(self.shard / 'candidates.jsonl', rows)
        result, report = self.audit()
        self.assertFalse(result['accounting_passed'])
        self.assertIn('candidate_deterministic_identity_mismatch', report['error_counts'])

    def test_independent_origins_in_one_container_may_use_different_splits(self):
        additional = copy.deepcopy(self.clean[-2])
        additional['metadata'].update(split='validation', dedup_group=additional['id'])
        write_rows(self.complete / 'pre_api/balancing_removals.jsonl', [])
        write_rows(self.complete / 'pre_api/validation/canonical.jsonl', [additional])
        write_rows(self.complete / 'pre_api/validation/messages.jsonl', [{'messages': additional['messages']}])
        self.results['5'].update(domain_cap_removed=0, awaiting_api_review=2)
        write_json(self.c[5] / 'statistics.json', self.results['5'])
        self.review['candidates'] = 2
        result, report = self.audit()
        self.assertTrue(result['accounting_passed'], report['error_counts'])
        self.assertEqual(report['counts']['split'], {'train': 1, 'validation': 1})
        # Now simulate a falsely shared entity in otherwise distinct records.
        additional['metadata']['split_group'] = self.final['metadata']['split_group']
        write_rows(self.complete / 'pre_api/validation/canonical.jsonl', [additional])
        result, report = self.audit()
        self.assertFalse(result['accounting_passed'])
        self.assertIn('cross_split_source_entity', report['error_counts'])

    def test_symlink_output_rejected_before_any_artifact_is_written(self):
        other = self.run.parent / 'other'; other.mkdir()
        (self.run / 'release').symlink_to(other, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'Symlink'):
            self.audit()
        self.assertEqual(list(other.iterdir()), [])


class ReportingDurabilitySmokeTests(unittest.TestCase):
    def test_real_fsync_publication_is_exclusive_and_preserves_prior_output(self):
        from greek_sft.reporting import _write_json
        with tempfile.TemporaryDirectory(dir=ROOT / 'runtime/tmp') as directory:
            path = Path(directory) / 'audit.json'
            _write_json(path, {'accounting_passed': True, 'release_ready': False})
            checksum = sha256_file(path)
            with self.assertRaises(FileExistsError):
                _write_json(path, {'release_ready': True})
            self.assertEqual(sha256_file(path), checksum)
            self.assertFalse(json.loads(path.read_text())['release_ready'])


if __name__ == '__main__':
    unittest.main()
