"""The actual driver resumes four immutable old-scope passes under new scope."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from greek_sft import integrity, scope_reconciliation
from greek_sft.inventory import SourceChangedError
from greek_sft.reporting import create_audited_release
from test_temporary_scope_reconciliation import TemporaryFixture, ROOT


class TemporaryScopeEndToEndTests(TemporaryFixture, unittest.TestCase):
    def test_actual_driver_preserves_four_checkpoints_and_audits_effective_scope(self):
        self.build_four()
        before = self.checkpoint_bytes()
        historical_statistics = dict(self.results)
        self.authorize_temporary()
        spec = importlib.util.spec_from_file_location('temporary_scope_driver', ROOT / 'scripts/run_pipeline.py')
        driver = importlib.util.module_from_spec(spec); spec.loader.exec_module(driver)
        excluded = (self.source / 'greek_training', self.source / 'greek_training_temp')
        original_open, original_scandir = Path.open, os.scandir
        def check(path):
            path = Path(path)
            if any(path == root or root in path.parents for root in excluded):
                raise AssertionError('current excluded root accessed: ' + str(path))
        def guarded_open(path, *args, **kwargs):
            check(path); return original_open(path, *args, **kwargs)
        def guarded_scandir(path):
            check(path); return original_scandir(path)
        events = []
        original_capture = driver.capture_execution_attempt
        original_prepare = scope_reconciliation.prepare_scope_reconciliation
        def capture(*args, **kwargs):
            events.append('capture'); return original_capture(*args, **kwargs)
        def prepare(*args, **kwargs):
            self.assertEqual(events, ['capture'])
            events.append('prepare'); return original_prepare(*args, **kwargs)
        with patch.object(driver, 'ROOT', self.pipeline), \
                patch.object(driver, 'capture_execution_attempt', side_effect=capture), \
                patch.object(scope_reconciliation, 'prepare_scope_reconciliation', side_effect=prepare), \
                patch.object(Path, 'open', guarded_open), patch('os.scandir', guarded_scandir), \
                contextlib.redirect_stdout(io.StringIO()):
            result = driver.run_pipeline(SimpleNamespace(run_id=self.run.name, through=5))
        self.assertEqual(result, self.run)
        self.assertEqual(events, ['capture', 'prepare'])
        self.assertEqual(before, self.checkpoint_bytes())
        state = json.loads((self.run / 'state.json').read_text())
        self.assertEqual(state['excluded_source_roots'], ['greek_training', 'greek_training_temp'])
        self.assertEqual(state['scoped_source_integrity'], 'verified')
        self.assertFalse(state['full_original_source_integrity'])
        view = scope_reconciliation.validate_scope_reconciliation(self.run, self.config, state['scope_reconciliation'])
        latest = json.loads((self.run / 'release/LATEST_AUDIT.json').read_text())
        self.assertTrue(latest['accounting_passed'], latest)
        self.assertFalse(latest['release_ready'])
        report = json.loads((self.run / latest['report_path']).read_text())
        self.assertTrue(report['gates']['scoped_source_hashes_unchanged']['passed'])
        self.assertFalse(report['gates']['source_hashes_unchanged']['passed'])
        self.assertEqual(report['current_excluded_coverage'], 'unknown')
        self.assertEqual(report['measured']['historical_excluded_files'], 3)
        self.assertEqual(report['measured']['raw_candidates'], 1)
        self.assertEqual(report['scope_reconciliation'], view['reference'])
        self.assertEqual(view['inputs']['checkpoint_statistics'], historical_statistics)
        self.assertEqual(view['reuse_proof']['excluded_raw_candidates'], 0)
        for number in (1, 2, 3, 4):
            self.assertEqual(json.loads((self.checkpoints[number] / 'statistics.json').read_text()), historical_statistics[str(number)])
        # A stable saved publication is reused, while a completed pass five
        # still performs a fresh independent source verification.
        with patch.object(driver, 'ROOT', self.pipeline), contextlib.redirect_stdout(io.StringIO()):
            driver.run_pipeline(SimpleNamespace(run_id=self.run.name, through=5))
        resumed_state = json.loads((self.run / 'state.json').read_text())
        self.assertEqual(resumed_state['scope_reconciliation'], state['scope_reconciliation'])
        self.assertEqual(len(list((self.run / 'source_verifications').glob('resume_*'))), 1)
        self.assertEqual(before, self.checkpoint_bytes())
        effective_results = dict(historical_statistics, scope_reconciliation=view['reference'])
        effective_results['1'] = view['statistics']
        effective_results['5'] = json.loads((self.run / 'checkpoint_05_dedup_splits/statistics.json').read_text())
        verification = effective_results['5']['source_verification']
        review = json.loads((self.run / 'api_review_plan.json').read_text())
        # A caller cannot present frozen old figures as effective scope figures.
        wrong = dict(effective_results); wrong['1'] = historical_statistics['1']
        failed = create_audited_release(self.run, wrong, review, verification, view['audit'])
        self.assertFalse(failed['accounting_passed'])
        changed_pass = dict(effective_results)
        changed_pass['2'] = dict(effective_results['2'], source_verification={'injected': True})
        failed = create_audited_release(self.run, changed_pass, review, verification, view['audit'])
        self.assertFalse(failed['accounting_passed'])
        # Even a coherently rewritten publication pair cannot replace the hash
        # already recorded in driver state on a subsequent resume.
        completion = self.run / view['reference']['path']
        intent = completion.with_name('publication_intent.json')
        completion_bytes, intent_bytes = completion.read_bytes(), intent.read_bytes()
        completion.write_bytes(completion_bytes + b' '); intent.write_bytes(intent_bytes + b' ')
        saved_state = (self.run / 'state.json').read_bytes()
        with patch.object(driver, 'ROOT', self.pipeline), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, 'scope_reconciliation_reference_changed'):
                driver.run_pipeline(SimpleNamespace(run_id=self.run.name, through=5))
        self.assertEqual((self.run / 'state.json').read_bytes(), saved_state)
        completion.write_bytes(completion_bytes); intent.write_bytes(intent_bytes)
        # Tampering a separately published reuse view also closes reporting.
        view_path = self.run / view['reference']['view_path']; view_path.write_bytes(view_path.read_bytes() + b' ')
        with self.assertRaisesRegex(RuntimeError, 'scope_reconciliation_artifact_changed'):
            create_audited_release(self.run, effective_results, review, verification, view['audit'])

    def test_similarly_named_neighbor_change_still_stops_fresh_verification(self):
        self.build_four(); self.authorize_temporary()
        scope_reconciliation.prepare_scope_reconciliation(self.run, self.config)
        self.neighbor.write_bytes(b'{"changed":true}\n')
        with self.assertRaises(SourceChangedError):
            integrity.verify_source_hashes(self.source, self.checkpoint, self.run / 'verification', self.config)
