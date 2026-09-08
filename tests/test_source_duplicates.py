import contextlib
import fcntl
import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from greek_sft import source_duplicates as duplicate

ROOT = Path(__file__).resolve().parents[1]


def row(path, payload=b'content', family='family', file_format='jsonl'):
    return {'relative_path': path, 'sha256': hashlib.sha256(payload).hexdigest(),
            'size_bytes': len(payload), 'family': family, 'format': file_format}


class SourceDuplicatesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='source_duplicates_', dir=ROOT / 'runtime/tmp')
        self.base = Path(self.temp.name)
        self.manifest = self.base / 'source_manifest.jsonl'
        self.output = self.base / 'audit'
        # Most tests exercise accounting and guards; a separate test retains real fsync.
        self.sync = patch('os.fsync')
        self.sync.start()
        self.sqlite_sync = patch.object(duplicate, 'SQLITE_SYNCHRONOUS', 'OFF')
        self.sqlite_sync.start()
        self.addCleanup(self.sqlite_sync.stop)
        self.addCleanup(self.sync.stop)
        self.addCleanup(self.temp.cleanup)

    def write(self, records):
        self.manifest.write_text(''.join(json.dumps(value) + '\n' for value in records), encoding='utf-8')

    def read(self, report, name):
        return [json.loads(line) for line in (self.output / report['artifacts'][name]).read_text().splitlines()]

    def test_exact_identity_counts_and_streamed_members(self):
        self.write([row('z/two.jsonl', family='z'), row('a/one.jsonl', family='a'),
                    row('b/three.jsonl', family='b'), row('unique.jsonl', b'unique!')])
        original = self.manifest.read_bytes()
        result = duplicate.audit_source_file_duplicates(self.manifest, self.output)
        self.assertEqual(result['counts']['files'], 4)
        self.assertEqual(result['counts']['groups'], 1)
        self.assertEqual(result['counts']['duplicate_member_files'], 3)
        self.assertEqual(result['counts']['redundant_copies'], 2)
        self.assertEqual(result['counts']['redundant_bytes'], 14)
        self.assertEqual(result['data_file_duplicate_counts']['duplicate_member_files_within_kind'], 3)
        groups = self.read(result, 'duplicate_groups.jsonl')
        self.assertEqual(groups[0]['representative'], 'a/one.jsonl')
        self.assertNotIn('members', groups[0])
        members = self.read(result, 'duplicate_members.jsonl')
        self.assertEqual([item['relative_path'] for item in members], ['a/one.jsonl', 'b/three.jsonl', 'z/two.jsonl'])
        self.assertEqual(sum(item['is_representative'] for item in members), 1)
        breakdown = self.read(result, 'breakdowns.jsonl')
        self.assertEqual(next(x for x in breakdown if x['dimension'] == 'family' and x['label'] == 'z')['redundant_bytes'], 7)
        self.assertEqual(self.manifest.read_bytes(), original)
        self.assertEqual(result['source_files_opened'], 0)
        self.assertEqual(result['source_manifest']['sha256'], hashlib.sha256(original).hexdigest())
        with contextlib.closing(sqlite3.connect(self.output / result['artifacts']['file_identity.sqlite'])) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM files').fetchone()[0], 4)
            self.assertIn('content_identity', {value[1] for value in db.execute('PRAGMA index_list(files)')})

    def test_same_size_different_hash_or_same_hash_different_size_do_not_match(self):
        first = row('one.jsonl', b'abc')
        second = row('two.jsonl', b'def')
        third = dict(first, relative_path='three.jsonl', size_bytes=4)
        self.write([first, second, third])
        result = duplicate.audit_source_file_duplicates(self.manifest, self.output)
        self.assertEqual(result['counts']['groups'], 0)
        self.assertEqual(self.read(result, 'duplicate_members.jsonl'), [])

    def test_sidecars_cache_and_code_not_training_document_duplicates(self):
        self.write([row('ET_raw/a.meta'), row('ET_raw/b.meta'), row('greek_training/one.jsonl'),
                    row('greek_training/two.jsonl'), row('folder/.git/config'),
                    row('a.py'), row('one.jsonl')])
        result = duplicate.audit_source_file_duplicates(self.manifest, self.output)
        self.assertEqual(result['counts']['duplicate_member_files'], 7)
        self.assertEqual(result['by_kind']['sidecar_metadata']['duplicate_member_files_within_kind'], 2)
        self.assertEqual(result['by_kind']['cache_or_derived_artifact']['duplicate_member_files_within_kind'], 2)
        self.assertEqual(result['by_kind']['repository_or_bytecode']['files'], 1)
        self.assertEqual(result['by_kind']['documentation_code_or_log']['files'], 1)
        self.assertEqual(result['data_file_duplicate_counts']['groups_with_multiple_files_of_kind'], 0)
        self.assertEqual(result['data_file_duplicate_counts']['duplicate_member_files_within_kind'], 0)
        self.assertTrue(any('not counts of duplicated training documents' in x for x in result['limitations']))

    def test_zero_byte_groups_are_counted_separately(self):
        self.write([row('one.jsonl', b''), row('two.meta', b''), row('three.jsonl', b'')])
        result = duplicate.audit_source_file_duplicates(self.manifest, self.output)
        self.assertEqual(result['counts']['zero_byte_files'], 3)
        self.assertEqual(result['counts']['zero_byte_groups'], 1)
        self.assertEqual(result['counts']['zero_byte_redundant_copies'], 2)
        self.assertEqual(result['counts']['redundant_bytes'], 0)
        self.assertTrue(self.read(result, 'duplicate_groups.jsonl')[0]['zero_byte'])

    def test_empty_manifest_is_a_valid_zero_file_audit(self):
        self.write([])
        result = duplicate.audit_source_file_duplicates(self.manifest, self.output)
        self.assertEqual(result['counts']['files'], 0)
        self.assertEqual(result['counts']['groups'], 0)
        self.assertEqual(self.read(result, 'breakdowns.jsonl'), [])

    def test_resume_validates_artifacts_and_input(self):
        self.write([row('one.jsonl'), row('two.jsonl')])
        result = duplicate.audit_source_file_duplicates(self.manifest, self.output)
        self.assertEqual(result, duplicate.audit_source_file_duplicates(self.manifest, self.output))
        self.assertEqual(len(list((self.output / 'attempts').iterdir())), 1)
        self.write([row('one.jsonl'), row('two.jsonl'), row('three.jsonl')])
        with self.assertRaisesRegex(ValueError, 'resume_input_or_version_changed'):
            duplicate.audit_source_file_duplicates(self.manifest, self.output)
        self.write([row('one.jsonl'), row('two.jsonl')])
        (self.output / result['artifacts']['duplicate_members.jsonl']).write_text('tampered\n')
        with self.assertRaisesRegex(ValueError, 'artifact_changed'):
            duplicate.audit_source_file_duplicates(self.manifest, self.output)

    def test_malformed_manifest_preserved_then_retries_unique_attempt(self):
        self.manifest.write_bytes(b'{"broken":\n')
        with self.assertRaisesRegex(ValueError, 'invalid_manifest_row_at_line_1'):
            duplicate.audit_source_file_duplicates(self.manifest, self.output)
        self.assertFalse((self.output / 'manifest.json').exists())
        failed = next((self.output / 'attempts').iterdir())
        self.assertTrue((failed / 'failure.json').exists())
        self.write([row('one.jsonl')])
        result = duplicate.audit_source_file_duplicates(self.manifest, self.output)
        self.assertTrue(result['completed'])
        self.assertTrue((failed / 'failure.json').exists())
        self.assertEqual(len(list((self.output / 'attempts').iterdir())), 2)

    def test_invalid_row_fields_and_duplicate_paths_rejected(self):
        cases = [dict(row('ok'), relative_path='../outside'), dict(row('ok'), relative_path='/absolute'),
                 dict(row('ok'), relative_path='a/../b'), dict(row('ok'), relative_path='a//b'),
                 dict(row('ok'), size_bytes=True), dict(row('ok'), size_bytes=-1),
                 dict(row('ok'), sha256='wrong'), dict(row('ok'), family=''),
                 dict(row('ok'), format=[]), dict(row('ok'), size_bytes=0), None]
        for index, item in enumerate(cases):
            with self.subTest(index=index):
                self.write([item])
                with self.assertRaises(ValueError):
                    duplicate.audit_source_file_duplicates(self.manifest, self.base / ('case_' + str(index)))
        self.write([row('same'), row('same')])
        with self.assertRaisesRegex(ValueError, 'duplicate_manifest_relative_path'):
            duplicate.audit_source_file_duplicates(self.manifest, self.output)

    def test_blank_invalid_utf8_duplicate_keys_and_oversize_rejected(self):
        cases = [b'\n', b'\xff\n', b'{"a":1,"a":2}\n']
        for index, raw in enumerate(cases):
            self.manifest.write_bytes(raw)
            with self.assertRaises(ValueError):
                duplicate.audit_source_file_duplicates(self.manifest, self.base / ('case_' + str(index)))
        self.manifest.write_bytes(b' ' * 65)
        with patch.object(duplicate, 'MAX_MANIFEST_LINE_BYTES', 64):
            with self.assertRaisesRegex(ValueError, 'exceeds_limit'):
                duplicate.audit_source_file_duplicates(self.manifest, self.output)

    def test_output_symlink_escape_and_source_reference_guards(self):
        self.write([row('one.jsonl')])
        with self.assertRaises(ValueError):
            duplicate.audit_source_file_duplicates(self.manifest, '/tmp/forbidden_duplicate_output')
        with self.assertRaises(ValueError):
            duplicate.audit_source_file_duplicates(self.manifest, self.base)
        self.output.mkdir()
        immutable = self.base / 'immutable'
        immutable.write_text('unchanged')
        (self.output / 'db.sqlite-journal').symlink_to(immutable)
        with self.assertRaises(ValueError):
            duplicate.audit_source_file_duplicates(self.manifest, self.output)
        self.assertEqual(immutable.read_text(), 'unchanged')
        link = self.base / 'linked_manifest'
        link.symlink_to(self.manifest)
        with self.assertRaises(ValueError):
            duplicate.audit_source_file_duplicates(link, self.base / 'different_output')

    def test_simultaneous_writer_is_rejected(self):
        self.write([row('one.jsonl')])
        self.output.mkdir()
        with (self.output / '.audit.lock').open('a+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(RuntimeError, 'already_running'):
                duplicate.audit_source_file_duplicates(self.manifest, self.output)
        self.assertFalse((self.output / 'attempts').exists())

    def test_resume_rejects_removed_checksum_coverage(self):
        self.write([row('one.jsonl')])
        duplicate.audit_source_file_duplicates(self.manifest, self.output)
        marker_path = self.output / 'manifest.json'
        marker = json.loads(marker_path.read_text())
        marker['artifacts'] = [x for x in marker['artifacts'] if not x['path'].endswith('.sqlite')]
        marker_path.write_text(json.dumps(marker))
        with self.assertRaisesRegex(ValueError, 'artifact_coverage_changed'):
            duplicate.audit_source_file_duplicates(self.manifest, self.output)

    def test_resume_rejects_nested_symlink(self):
        self.write([row('one.jsonl'), row('two.jsonl')])
        result = duplicate.audit_source_file_duplicates(self.manifest, self.output)
        nested = self.output / result['artifacts']['duplicate_members.jsonl']
        nested.unlink()
        nested.symlink_to(self.manifest)
        with self.assertRaises(ValueError):
            duplicate.audit_source_file_duplicates(self.manifest, self.output)

    def test_sql_query_plans_and_small_batch_smoke_with_real_fsync(self):
        self.sync.stop()
        self.sqlite_sync.stop()
        self.write([row('one.jsonl'), row('two.jsonl'), row('three.jsonl', b'different')])
        with patch.object(duplicate, 'BATCH_SIZE', 1):
            report = duplicate.audit_source_file_duplicates(self.manifest, self.output)
        marker = json.loads((self.output / 'manifest.json').read_text())
        for item in marker['artifacts']:
            path = self.output / item['path']
            self.assertEqual(item['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(report['counts']['redundant_copies'], 1)


if __name__ == '__main__':
    unittest.main()
