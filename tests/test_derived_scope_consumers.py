"""Consumers independently enforce the effective derived-collection scope."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from greek_sft import tasks, reporting

ROOT = Path(__file__).resolve().parents[1]
FAMILY = 'skroutz_shop_reviews_sentiment_analysis'
SCOPE = {'sha256': 'a' * 64, 'frozen': True,
         'amendment': {'excluded_source_roots': ['greek_training']}}


class DerivedScopeConsumerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT / 'runtime/tmp')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / 'source'; self.source.mkdir()
        self.inventory = self.root / 'inventory'; self.inventory.mkdir()
        self.plans = self.root / 'plans'; self.raw = self.root / 'raw'
        self.config = {}
        data = (json.dumps({'text': 'Το κατάστημα παρέδωσε έγκαιρα την παραγγελία και η εξυπηρέτηση ήταν εξαιρετική.',
                            'label': 'Positive'}, ensure_ascii=False) + '\n').encode()
        rows = []
        for relative in ('greek_training/mixed.jsonl', FAMILY + '/dataset.jsonl', 'greek_training_temp/dataset.jsonl'):
            path = self.source / relative; path.parent.mkdir(parents=True); path.write_bytes(data)
            rows.append({'relative_path': relative, 'family': FAMILY,
                'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data),
                'record_count': 1, 'record_boundary_complete': True, 'encoding': 'utf-8',
                'format': 'jsonl', 'status': 'quarantined', 'reason': 'license_unverified'})
        (self.inventory / 'source_manifest.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
        scope_patch = patch.object(tasks, 'validate_source_exclusion', return_value=SCOPE)
        self.scope = scope_patch.start(); self.addCleanup(scope_patch.stop)
        sync_patch = patch('os.fsync')
        sync_patch.start(); self.addCleanup(sync_patch.stop)
        original_connect = reporting.sqlite3.connect
        def fast_connection(*args, **kwargs):
            connection = original_connect(*args, **kwargs)
            connection.execute('PRAGMA synchronous=OFF')
            return connection
        sqlite_patch = patch.object(reporting.sqlite3, 'connect', side_effect=fast_connection)
        sqlite_patch.start(); self.addCleanup(sqlite_patch.stop)

    def plan(self):
        return tasks.run_plans(self.source, self.inventory, self.plans, self.config)

    def build(self):
        return tasks.run_generation(self.source, self.inventory, self.plans, self.raw, self.config)

    def test_no_excluded_reads_even_with_supported_family_and_originals_work(self):
        original_open = tasks.open_source_readonly
        opened = []
        def guard(path, *args, **kwargs):
            if self.source not in Path(path).parents:
                return original_open(path, *args, **kwargs)
            relative = Path(path).relative_to(self.source).as_posix()
            self.assertFalse(relative == 'greek_training' or relative.startswith('greek_training/'))
            opened.append(relative)
            return original_open(path, *args, **kwargs)
        with patch.object(tasks, 'open_source_readonly', side_effect=guard):
            plans = self.plan(); built = self.build()
        self.assertEqual(plans['source_scope_counts']['historical_excluded_identified_records'], 1)
        self.assertEqual(built['historical_excluded_identified_records'], 1)
        self.assertEqual(built['in_scope_identified_records'], 2)
        self.assertEqual(built['candidates'], 2)
        self.assertTrue(opened)
        for folder in (self.plans, self.raw):
            excluded = next(tasks._rows(folder / 'source_dispositions.jsonl'))
            self.assertEqual(excluded['status'], 'quarantined')
            self.assertEqual(excluded['reason'], tasks.EXCLUDED_SOURCE_REASON)
        candidates = [row for path in self.raw.glob('shards/*/candidates.jsonl') for row in tasks._rows(path)]
        self.assertTrue(all(not row['metadata']['source_file'].startswith('greek_training/') for row in candidates))

    def test_stale_plan_resume_and_generation_rejected(self):
        self.scope.return_value = None
        self.plan()
        self.scope.return_value = SCOPE
        with self.assertRaisesRegex(ValueError, 'checkpoint_identity_changed'):
            self.plan()
        with self.assertRaisesRegex(ValueError, 'plan_source_exclusion_identity_changed'):
            self.build()

    def test_stale_generation_rejected_after_new_scope_plan(self):
        self.plan(); self.build()
        self.scope.return_value = {**SCOPE, 'sha256': 'b' * 64}
        self.plans = self.root / 'new_plans'; self.plan()
        with self.assertRaisesRegex(ValueError, 'checkpoint_identity_changed'):
            self.build()

    def test_generation_does_not_trust_accepted_plan_for_excluded_path(self):
        self.plan()
        path = self.plans / 'source_dispositions.jsonl'
        rows = list(tasks._rows(path)); rows[0]['status'] = 'accepted'
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        marker = json.loads((self.plans / 'tasks_completion.json').read_text())
        marker['artifacts']['source_dispositions.jsonl'] = tasks._file_hash(path)
        (self.plans / 'tasks_completion.json').write_text(json.dumps(marker))
        self.assertEqual(self.build()['candidates'], 2)

    def test_reporting_rejects_excluded_accepted_disposition_and_candidate(self):
        output = self.root / 'audit'; output.mkdir()
        audit = reporting._Audit(self.root, output)
        try:
            audit.source_exclusion = SCOPE
            audit.db.execute('INSERT INTO files(path,family,n,boundary,bytes,excluded) VALUES(?,?,?,?,?,?)',
                             ('greek_training/mixed.jsonl', FAMILY, 1, 1, 20, 1))
            checkpoint = self.root / 'bad_plan'; checkpoint.mkdir()
            (checkpoint / 'source_dispositions.jsonl').write_text(json.dumps({
                'source_file': 'greek_training/mixed.jsonl', 'family': FAMILY, 'record_count': 1,
                'record_start': 1, 'record_end': 1, 'record_boundary_complete': True,
                'status': 'accepted', 'reason': 'supported'}) + '\n')
            reporting._source_dispositions(audit, checkpoint, 2)
            self.assertEqual(audit.error_counts['source_exclusion_accepted_disposition'], 1)
            path = self.root / 'bad_candidates.jsonl'
            path.write_text(json.dumps({'id': 'fake', 'metadata': {'source_file': 'greek_training/mixed.jsonl'}}) + '\n')
            validator = Mock()
            for stage in ('raw', 'validated', 'clean', 'pre_api'):
                reporting._load_candidates(audit, [path], stage, validator)
            self.assertEqual(audit.error_counts['source_exclusion_candidate_present'], 4)
            validator.is_valid.assert_not_called()
            self.assertEqual(audit.db.execute('SELECT COUNT(*) FROM members').fetchone()[0], 0)
        finally:
            audit.close()

    def test_markdown_reports_effective_root_and_preserves_legacy_history(self):
        from collections import defaultdict
        output = self.root / 'reports'; output.mkdir()
        summary = {'measured': defaultdict(int), 'gates': {'source_hashes_unchanged': {'passed': False}},
                   'accounting_passed': True, 'contamination': {}, 'inventory_scope_amendment': {},
                   'source_exclusion_amendment': {**SCOPE, 'predecessor': {
                       'amendment': {'excluded_source_roots': ['greek_training/.git']}}}}
        reporting._markdown_reports(output, summary, {}, 'fixture')
        text = (output / 'provenance_report.md').read_text()
        self.assertIn('user-authorized `greek_training/` exclusion', text)
        self.assertIn('earlier `greek_training/.git/` authorization', text)
        self.assertIn('must not produce SFT', text)
        self.assertIn('unknown and unassessed', text)
        self.assertIn('full-original-tree integrity remains failed', text)

    def test_legacy_git_scope_keeps_non_git_source_eligible(self):
        legacy = {'amendment': {'excluded_source_roots': ['greek_training/.git']}}
        row = next(tasks._rows(self.inventory / 'source_manifest.jsonl'))
        self.assertTrue(tasks._eligible_file(row, tasks.make_plan(FAMILY), legacy))
        self.assertEqual(tasks._source_exclusion_reason(legacy), 'excluded_from_current_source_coverage')

    def test_interrupted_generation_scope_change_rejects_leftover_shards(self):
        self.plan(); self.build()
        (self.raw / 'tasks_completion.json').unlink()
        self.scope.return_value = {**SCOPE, 'sha256': 'b' * 64}
        self.plans = self.root / 'new_plans'; self.plan()
        with self.assertRaisesRegex(ValueError, 'generation_attempt_identity_changed'):
            self.build()

    def test_unidentified_legacy_partial_generation_is_rejected(self):
        self.plan()
        leftover = self.raw / 'shards/old/candidates.jsonl'
        leftover.parent.mkdir(parents=True)
        leftover.write_text('{}\n')
        with self.assertRaisesRegex(ValueError, 'generation_partial_output_identity_missing'):
            self.build()

    def test_interrupted_attempt_identity_publication_retries_before_shards(self):
        self.plan()
        original_replace = tasks.os.replace
        def interrupted(source, target):
            if Path(target) == self.raw / 'generation_identity.json':
                raise OSError('identity publication interrupted')
            return original_replace(source, target)
        with patch.object(tasks.os, 'replace', side_effect=interrupted):
            with self.assertRaisesRegex(OSError, 'identity publication interrupted'):
                self.build()
        self.assertEqual([path.name for path in self.raw.iterdir()], ['generation_identity.json.partial'])
        self.assertEqual(self.build()['candidates'], 2)

    def test_attempt_identity_is_directory_synced_before_generation(self):
        import os
        import stat
        self.plan()
        directory_synced = []
        def sync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                directory_synced.append(True)
        original_generate = tasks._generate_family
        def generate(*args, **kwargs):
            self.assertTrue(directory_synced)
            return original_generate(*args, **kwargs)
        with patch.object(tasks.os, 'fsync', side_effect=sync), patch.object(tasks, '_generate_family', side_effect=generate):
            self.assertEqual(self.build()['candidates'], 2)
