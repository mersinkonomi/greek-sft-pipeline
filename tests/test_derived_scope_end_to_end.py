"""All five real stages honor the whole derived collection exclusion chain."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import patch

from greek_sft import inventory, integrity, tasks
from greek_sft.audit import audit_inventory
from greek_sft.contamination import check_contamination
from greek_sft.core import atomic_json, checkpoint_complete
from greek_sft.dedup import run_dedup
from greek_sft.reporting import CHECKPOINTS, create_audited_release
from greek_sft.review import estimate_review
from greek_sft.source_io import open_source_readonly
import test_source_exclusion as legacy_fixture
from test_derived_collection_scope import create_derived_amendment

ROOT = Path(__file__).resolve().parents[1]


class DerivedScopeEndToEndTests(unittest.TestCase):
    file = legacy_fixture.SourceExclusionTests.file
    seed = legacy_fixture.SourceExclusionTests.seed
    amendment = legacy_fixture.SourceExclusionTests.amendment

    def setUp(self):
        fsync = patch('os.fsync'); fsync.start(); self.addCleanup(fsync.stop)
        original_connect = sqlite3.connect
        def fast_connection(*args, **kwargs):
            db = original_connect(*args, **kwargs)
            db.execute('PRAGMA synchronous=OFF')
            return db
        sqlite = patch('sqlite3.connect', side_effect=fast_connection)
        sqlite.start(); self.addCleanup(sqlite.stop)
        original_inventory_connect = inventory._connect
        def inventory_connect(path):
            db = original_inventory_connect(path)
            db.execute('PRAGMA synchronous=OFF')
            return db
        connector = patch.object(inventory, '_connect', inventory_connect)
        connector.start(); self.addCleanup(connector.stop)
        legacy_fixture.SourceExclusionTests.setUp(self)

    def test_whole_scope_five_passes_preserve_history_and_pin_both_incidents(self):
        self.config.update(batch_size=1, seed=1729, max_record_bytes=1024 * 1024,
            validation={'schema_path': str(ROOT / 'schemas/canonical-sft.schema.json')},
            dedup={'seed': 1729}, tokenizer={'local_path': None}, evaluation={})
        row = {'text': 'Το κατάστημα παρέδωσε έγκαιρα την παραγγελία και η εξυπηρέτηση ήταν εξαιρετική.',
               'label': 'Positive'}
        payload = (json.dumps(row, ensure_ascii=False) + '\n').encode()
        mixture = self.file('greek_training/mixed.jsonl', payload)
        self.seed(mixture)
        original = self.file('skroutz_shop_reviews_sentiment_analysis/reviews.jsonl', payload)
        original_hash = hashlib.sha256(payload).hexdigest()
        self.file('greek_training/.gitignore', b'changed metadata outside prior Git exclusion')
        self.amendment()
        extension = create_derived_amendment(self)
        atomic_json(self.run / 'configuration.json', self.config)
        checkpoints = {n: self.run / name for n, name in CHECKPOINTS.items()}
        shard = self.checkpoint / 'inventory_shard_00.sqlite'
        with contextlib.closing(sqlite3.connect(shard)) as db:
            saved_files = list(db.execute('SELECT * FROM files ORDER BY relative_path'))
            saved_ranges = list(db.execute('SELECT * FROM record_ranges ORDER BY relative_path,first_record'))
        excluded = self.source / 'greek_training'
        real_scandir = os.scandir
        def guard(path):
            path = Path(path)
            if path == excluded or excluded in path.parents:
                raise AssertionError('excluded mixture accessed: ' + str(path))
        def guarded_read(path, *args, **kwargs):
            guard(path)
            return open_source_readonly(path, *args, **kwargs)
        def guarded_scandir(path):
            guard(path)
            return real_scandir(path)
        with patch.object(inventory, 'open_source_readonly', guarded_read), \
                patch.object(integrity, 'open_source_readonly', guarded_read), \
                patch.object(tasks, 'open_source_readonly', guarded_read), \
                patch('os.scandir', guarded_scandir):
            results = {'1': inventory.run_inventory(self.source, self.checkpoint, self.config)}
            checkpoint_complete(ROOT, self.checkpoint, results['1'], self.config)
            audited = audit_inventory(self.checkpoint, self.run / 'audits/inventory')
            results['2'] = tasks.run_plans(self.source, self.checkpoint, checkpoints[2], self.config)
            checkpoint_complete(ROOT, checkpoints[2], results['2'], self.config)
            results['3'] = tasks.run_generation(self.source, self.checkpoint, checkpoints[2], checkpoints[3], self.config)
            checkpoint_complete(ROOT, checkpoints[3], results['3'], self.config)
            results['4'] = tasks.run_validation(checkpoints[3], checkpoints[4], self.config)
            results['4']['contamination'] = check_contamination(checkpoints[4] / 'validated.jsonl', ROOT,
                checkpoints[4] / 'contamination', self.config)
            checkpoint_complete(ROOT, checkpoints[4], results['4'], self.config)
            results['5'] = run_dedup([checkpoints[4] / 'contamination/clean_candidates.jsonl'], checkpoints[5], self.config)
            verified = integrity.verify_source_hashes(self.source, self.checkpoint, checkpoints[5] / 'source_verification', self.config)
            results['5']['source_verification'] = verified
            checkpoint_complete(ROOT, checkpoints[5], results['5'], self.config)
            review_paths = sorted((checkpoints[5] / 'completed/pre_api').glob('*/canonical.jsonl'))
            final = create_audited_release(self.run, results, estimate_review(review_paths, {'enabled': False}), verified, audited)
        self.assertTrue(final['accounting_passed'], final)
        self.assertFalse(final['release_ready'])
        self.assertEqual(results['3']['candidates'], 1)
        raw = [row for path in checkpoints[3].glob('shards/*/candidates.jsonl') for row in tasks._rows(path)]
        self.assertEqual([row['metadata']['source_file'] for row in raw], [original.relative_to(self.source).as_posix()])
        report = json.loads((self.run / final['report_path']).read_text())
        self.assertEqual(report['measured']['source_files'], 3)
        self.assertEqual(report['measured']['identified_source_records'], 2)
        self.assertFalse(report['gates']['source_hashes_unchanged']['passed'])
        self.assertTrue(report['gates']['scoped_source_hashes_unchanged']['passed'])
        self.assertEqual(verified['current_excluded_coverage'], 'unknown')
        self.assertIsNone(report['source_exclusion_accounting']['current_excluded_files'])
        scope = report['source_exclusion_amendment']
        self.assertEqual(scope['amendment']['excluded_source_roots'], ['greek_training'])
        self.assertEqual(scope['predecessor']['amendment']['excluded_source_roots'], ['greek_training/.git'])
        evidence = audited['input_identity']['source_exclusion_evidence_sha256']
        release_inputs = json.loads((self.run / final['report_path']).with_name('input_artifacts.json').read_text())
        for reference in (scope, scope['predecessor']):
            for relative in (reference['artifact'], CHECKPOINTS[1] + '/' + reference['artifact'],
                             CHECKPOINTS[1] + '/' + reference['checksum_artifact'], reference['amendment']['integrity_incident_path']):
                self.assertEqual(evidence[relative], hashlib.sha256((self.run / relative).read_bytes()).hexdigest())
                self.assertIn(relative, release_inputs)
        self.assertEqual(scope['amendment']['integrity_incident_path'], extension['integrity_incident_path'])
        report_dir = (self.run / final['report_path']).parent
        original_reference = json.loads((report_dir / 'original_integrity_incident_reference.json').read_text())
        effective_reference = json.loads((report_dir / 'effective_integrity_incident_reference.json').read_text())
        self.assertEqual(original_reference['path'], self.incident_path.relative_to(self.run).as_posix())
        self.assertEqual(effective_reference['path'], extension['integrity_incident_path'])
        with contextlib.closing(sqlite3.connect(shard)) as db:
            self.assertEqual(list(db.execute("SELECT * FROM files WHERE relative_path LIKE 'greek_training/%' ORDER BY relative_path")), saved_files)
            self.assertEqual(list(db.execute("SELECT * FROM record_ranges WHERE relative_path LIKE 'greek_training/%' ORDER BY relative_path,first_record")), saved_ranges)
        self.assertEqual(hashlib.sha256(original.read_bytes()).hexdigest(), original_hash)

    def test_driver_keeps_original_and_effective_incidents_distinct(self):
        import importlib.util
        from types import SimpleNamespace
        spec = importlib.util.spec_from_file_location('derived_scope_driver_test', ROOT / 'scripts/run_pipeline.py')
        driver = importlib.util.module_from_spec(spec); spec.loader.exec_module(driver)
        fixture_root = self.base / 'driver'; fixture_root.mkdir()
        (fixture_root / 'runs').mkdir(); (fixture_root / 'configs').mkdir()
        (fixture_root / 'configs/pipeline.yaml').write_text(json.dumps({
            'source_root': str(self.source), 'pipeline_root': str(fixture_root)}))
        scope = {'sha256': 'a' * 64, 'amendment': {'excluded_source_roots': ['greek_training'],
                 'integrity_incident_path': 'integrity_incidents/latest/incident.json'},
                 'predecessor': {'amendment': {'integrity_incident_path': 'integrity_incidents/original/incident.json'}}}
        with patch.object(driver, 'ROOT', fixture_root), \
                patch.object(driver, 'validate_roots', return_value=(self.source, fixture_root)), \
                patch.object(driver, 'freeze_config'), patch.object(driver, 'capture_execution_attempt', return_value='synthetic'), \
                patch('greek_sft.inventory.validate_inventory_scope', return_value=None), \
                patch('greek_sft.source_scope.validate_source_exclusion', return_value=scope):
            run = driver.run_pipeline(SimpleNamespace(run_id=None, through=0))
        state = json.loads((run / 'state.json').read_text())
        self.assertEqual(state['source_integrity_scope'], 'approved_source_scope')
        self.assertEqual(state['excluded_source_roots'], ['greek_training'])
        self.assertEqual(state['original_integrity_incident'], 'integrity_incidents/original/incident.json')
        self.assertEqual(state['effective_integrity_incident'], 'integrity_incidents/latest/incident.json')
        self.assertEqual(state['integrity_incident_chain'],
            ['integrity_incidents/latest/incident.json', 'integrity_incidents/original/incident.json'])
