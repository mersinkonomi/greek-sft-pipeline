"""Scoped reporting authenticates excluded dispositions and their frozen evidence."""
import contextlib
import copy
import json
import os
import sqlite3
import unittest
from unittest.mock import patch

from greek_sft.reporting import _Audit, create_audited_release
from test_source_exclusion_end_to_end import source_exclusion_fixture


class SourceExclusionReportingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The end-to-end test retains real fsync. These regressions exercise joins
        # and evidence authentication using one real synthetic five-pass fixture.
        cls.stack = contextlib.ExitStack()
        cls.addClassCleanup(cls.stack.close)
        cls.stack.enter_context(patch('os.fsync'))
        original_connect = sqlite3.connect
        def fast_connection(*args, **kwargs):
            connection = original_connect(*args, **kwargs)
            connection.execute('PRAGMA synchronous=OFF')
            return connection
        cls.stack.enter_context(patch('greek_sft.reporting.sqlite3.connect', side_effect=fast_connection))
        cls.state = cls.stack.enter_context(source_exclusion_fixture())

    def setUp(self):
        self.run = self.state['run']
        self.results = copy.deepcopy(self.state['results'])
        self.verification = copy.deepcopy(self.state['verified'])
        self.inventory_audit = copy.deepcopy(self.state['inventory_audit'])

    def audit(self, expected_error=None):
        result = create_audited_release(self.run, self.results, self.state['review'],
                                       self.verification, self.inventory_audit)
        report = json.loads((self.run / result['report_path']).read_text())
        self.assertFalse(result['release_ready'])
        self.assertFalse(report['gates']['source_hashes_unchanged']['passed'])
        if expected_error:
            self.assertFalse(result['accounting_passed'], report)
            self.assertIn(expected_error, report['error_counts'])
            self.assertFalse(report['gates']['scoped_source_hashes_unchanged']['passed'], report)
        else:
            self.assertTrue(result['accounting_passed'], report['error_counts'])
            self.assertTrue(report['gates']['scoped_source_hashes_unchanged']['passed'])
        return report

    @contextlib.contextmanager
    def changed_artifact(self, path, change):
        original = path.read_bytes()
        try:
            change(path)
            yield
        finally:
            path.write_bytes(original)

    def change_verification_row(self, excluded, field, value, missing=False):
        path = self.run / self.verification['source_hashes_path']
        def change(target):
            rows = [json.loads(line) for line in target.read_text().splitlines()]
            row = next(row for row in rows if (row['status'] == 'excluded_by_user') == excluded)
            if missing:
                row.pop(field)
            else:
                row[field] = value
            target.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        return self.changed_artifact(path, change)

    def test_valid_scoped_integrity_keeps_original_failure(self):
        report = self.audit()
        self.assertEqual(report['measured']['historical_excluded_files'], 2)
        self.assertEqual(report['measured']['in_scope_files'], 1)
        self.assertFalse(report['gates']['complete_semantic_record_coverage']['passed'])

    def test_excluded_file_cannot_be_forged_as_unchanged(self):
        path = self.run / self.verification['source_hashes_path']
        def change(target):
            rows = [json.loads(line) for line in target.read_text().splitlines()]
            row = next(row for row in rows if row['status'] == 'excluded_by_user')
            row.update(status='unchanged', sha256=row['baseline_sha256'],
                       size_bytes=row['baseline_size_bytes'])
            target.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        with self.changed_artifact(path, change):
            self.audit('source_verification_invalid_excluded_disposition')

    def test_excluded_baseline_and_null_current_evidence_are_required(self):
        for field, wrong in (('baseline_sha256', '0' * 64), ('baseline_size_bytes', -1),
                             ('sha256', '0' * 64), ('size_bytes', 9)):
            for missing in (False, True):
                with self.subTest(field=field, missing=missing):
                    with self.change_verification_row(True, field, wrong, missing):
                        self.audit('source_verification_invalid_excluded_disposition')

    def test_in_scope_current_hash_and_size_are_required(self):
        for field, wrong in (('sha256', '0' * 64), ('size_bytes', -1)):
            for missing in (False, True):
                with self.subTest(field=field, missing=missing):
                    with self.change_verification_row(False, field, wrong, missing):
                        self.audit('source_verification_hash_or_size_mismatch')

    def test_excluded_row_must_bind_the_frozen_amendment(self):
        for missing in (False, True):
            with self.subTest(missing=missing):
                with self.change_verification_row(True, 'source_exclusion_amendment_sha256', '0' * 64, missing):
                    self.audit('source_verification_invalid_excluded_disposition')

    def test_exclusion_ledgers_and_checksums_cannot_be_missing_or_tampered(self):
        refs = self.results['1']['source_exclusion_accounting']['artifacts']
        for name, relative in refs.items():
            path = self.state['checkpoint'] / relative
            error = ('source_exclusion_ledger_checksum_identity_mismatch' if name == 'checksums.json'
                     else 'source_exclusion_ledger_artifact_changed')
            for missing in (False, True):
                with self.subTest(artifact=name, missing=missing):
                    def change(target):
                        if missing:
                            target.unlink()
                        else:
                            target.write_bytes(target.read_bytes() + b'\n')
                    with self.changed_artifact(path, change):
                        self.audit(error)

    def test_supplied_scope_wrappers_must_match_frozen_authorization(self):
        for target, error in ((self.results['1'], 'source_exclusion_inventory_statistics_mismatch'),
                              (self.inventory_audit, 'source_exclusion_inventory_audit_mismatch'),
                              (self.verification, 'source_verification_scope_mismatch')):
            with self.subTest(error=error):
                original = target['source_exclusion_amendment']
                try:
                    target['source_exclusion_amendment'] = None
                    self.audit(error)
                finally:
                    target['source_exclusion_amendment'] = original

    def test_supplied_verification_cannot_claim_original_or_current_excluded_coverage(self):
        for field, wrong in (('full_original_source_integrity', True),
                             ('full_original_source_coverage', True), ('current_excluded_coverage', 'complete'),
                             ('current_excluded_files', 2), ('current_excluded_bytes', 9),
                             ('current_excluded_records', 1), ('verification_scope', 'original_source_tree'),
                             ('source_exclusion_amendment_sha256', '0' * 64)):
            with self.subTest(field=field):
                original = self.verification.get(field)
                try:
                    self.verification[field] = wrong
                    self.audit('source_verification_excluded_scope_claim_invalid')
                finally:
                    self.verification[field] = original

    def test_extra_malformed_verification_row_fails_scoped_integrity(self):
        path = self.run / self.verification['source_hashes_path']
        with self.changed_artifact(path, lambda target: target.write_bytes(target.read_bytes() + b'{bad json}\n')):
            self.audit('malformed_artifact_row')

    def test_verification_artifact_changed_during_read_fails_scoped_integrity(self):
        target = self.run / self.verification['source_hashes_path']
        original_rows = _Audit.rows
        changed = False
        def rows(audit, path):
            nonlocal changed
            for item in original_rows(audit, path):
                yield item
                if path == target and not changed:
                    before = target.stat()
                    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
                    changed = True
        with patch.object(_Audit, 'rows', rows):
            self.audit('artifact_changed_during_audit')
        self.assertTrue(changed)

    def test_missing_verification_artifacts_fail_scoped_integrity(self):
        for key in ('source_hashes_path', 'integrity_report_path'):
            with self.subTest(artifact=key):
                path = self.run / self.verification[key]
                with self.changed_artifact(path, lambda target: target.unlink()):
                    self.audit('missing_artifact')

    def test_persisted_verification_scope_must_match_supplied_scope(self):
        path = self.run / self.verification['integrity_report_path']
        def change(target):
            report = json.loads(target.read_text())
            report['source_exclusion_amendment'] = None
            target.write_text(json.dumps(report))
        with self.changed_artifact(path, change):
            self.audit('supplied_source_verification_scope_mismatch')


if __name__ == '__main__':
    unittest.main()
