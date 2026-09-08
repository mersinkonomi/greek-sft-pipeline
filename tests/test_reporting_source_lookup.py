"""Per-source reporting must preserve outcomes without rescanning unrelated candidates."""
import json
from pathlib import Path
import tempfile
import unittest

from greek_sft.reporting import _Audit, _terminal_reports

ROOT = Path(__file__).resolve().parents[1]


class LookupConnection:
    """Observe only the production per-source count query, using its real schema."""
    def __init__(self, db, *, legacy=False, bound=None):
        self.db, self.legacy, self.bound = db, legacy, bound
        self.empty_lookups = 0

    def __getattr__(self, name):
        return getattr(self.db, name)

    def execute(self, sql, parameters=()):
        if 'SELECT m.stage,COUNT(*) FROM candidates c' not in sql or 'WHERE c.source=?' not in sql:
            return self.db.execute(sql, parameters)
        if self.legacy:
            sql = sql.replace('CROSS JOIN', 'JOIN')
        if self.bound is None or not parameters[0].startswith('empty/'):
            return self.db.execute(sql, parameters)
        steps = 0

        def progress():
            nonlocal steps
            steps += 1
            return steps > self.bound

        self.db.set_progress_handler(progress, 1)
        try:
            rows = self.db.execute(sql, parameters).fetchall()
        finally:
            self.db.set_progress_handler(None, 0)
        self.empty_lookups += 1
        return iter(rows)


class ReportingSourceLookupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='reporting_lookup_', dir=ROOT / 'runtime/tmp')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)

    def audit(self, name):
        output = self.base / name
        output.mkdir()
        audit = _Audit(self.base, output)
        self.addCleanup(audit.close)
        return audit

    @staticmethod
    def file(audit, path, status='accepted'):
        audit.db.execute('''INSERT INTO files
            (path,family,n,boundary,sha,status,reason,build_status,build_reason,bytes,sha_after)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
            (path, 'fixture', 3, 1, 'before', 'accepted', 'inventory_reason',
             status, 'generation_reason', 42, 'after'))

    @staticmethod
    def candidate(audit, identity, source, stages):
        audit.db.execute('INSERT INTO candidates VALUES(?,?,?,?,?,?,?,?)',
                         (identity, source, 1, 'row', 'stable', 'fixture', 'domain', 'task'))
        for stage in stages:
            audit.db.execute('INSERT INTO members VALUES(?,?,?,?,?)',
                             (stage, identity, 'hash', 'reason_' + stage, None))

    def seed_semantics(self, audit):
        for path in ('a/data', 'b/data', 'empty/data'):
            self.file(audit, path)
        self.file(audit, 'empty/missing', status=None)
        self.candidate(audit, 'a1', 'a/data', ('validated', 'quarantine'))
        self.candidate(audit, 'a2', 'a/data', ('pre_api',))
        self.candidate(audit, 'b1', 'b/data', ('contaminated', 'capped'))
        self.candidate(audit, 'b2', 'b/data', ('validated',))
        audit.db.executemany('INSERT INTO generated VALUES(?,?,?,?,?,?)', [
            ('a/data', 1, 'accepted', None, 'a1', 'row'),
            ('a/data', 2, 'accepted', None, 'a2', 'row'),
            ('b/data', 1, 'rejected', 'blocked', None, 'row')])

    def test_reports_and_accounting_errors_match_previous_join(self):
        actual = self.audit('actual')
        self.seed_semantics(actual)
        _terminal_reports(actual)
        actual.error_stream.flush()
        expected = self.audit('expected')
        self.seed_semantics(expected)
        expected.db = LookupConnection(expected.db, legacy=True)
        _terminal_reports(expected)
        expected.error_stream.flush()
        for name in ('candidate_dispositions.jsonl', 'source_dispositions.jsonl',
                     'blocked_sources.jsonl', 'errors.jsonl'):
            self.assertEqual((actual.output / name).read_bytes(), (expected.output / name).read_bytes(), name)
        self.assertEqual(actual.error_counts['candidate_terminal_outcome_missing_or_multiple'], 2)
        sources = {r['source_file']: r for r in map(json.loads,
                   (actual.output / 'source_dispositions.jsonl').read_text().splitlines())}
        self.assertEqual(sources['a/data']['candidate_terminal_counts'], {'quarantine': 1, 'pre_api': 1})
        self.assertEqual(sources['b/data']['candidate_terminal_counts'], {'contaminated': 1, 'capped': 1})
        self.assertEqual(sources['empty/data']['candidate_terminal_counts'], {})
        self.assertEqual(sources['a/data']['generation_record_status_counts'], {'accepted': 2})
        self.assertEqual(sources['a/data']['final_reason'], 'api_review_and_release_approval_pending')
        self.assertEqual(sources['empty/missing']['final_status'], 'processing_error')

    def test_many_empty_sources_use_bounded_index_lookups(self):
        audit = self.audit('bounded')
        self.file(audit, 'populated/data')
        for i in range(2000):
            self.candidate(audit, str(i), 'populated/data', ('validated', 'quarantine'))
        for i in range(100):
            self.file(audit, f'empty/{i:03}')
        # A candidate-first index miss needs only a few dozen SQLite VM steps.
        # The old reordered join takes thousands, regardless of machine speed.
        audit.db = LookupConnection(audit.db, bound=500)
        _terminal_reports(audit)
        self.assertEqual(audit.db.empty_lookups, 100)
        self.assertFalse(audit.error_counts)
        rows = list(map(json.loads, (audit.output / 'source_dispositions.jsonl').read_text().splitlines()))
        self.assertEqual(len(rows), 101)
        self.assertTrue(all(row['candidate_terminal_counts'] == {} for row in rows[:-1]))
        self.assertEqual(rows[-1]['candidate_terminal_counts'], {'quarantine': 2000})


if __name__ == '__main__':
    unittest.main()
