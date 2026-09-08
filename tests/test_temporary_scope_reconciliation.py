"""Historical checkpoint reuse needs exact artifacts and source-path proof."""
import contextlib
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from greek_sft import inventory, tasks, scope_reconciliation as reconciliation
from greek_sft.audit import audit_inventory
from greek_sft.contamination import check_contamination
from greek_sft.core import atomic_json, checkpoint_complete, sha256_file
from greek_sft.source_scope import validate_source_exclusion, TEMPORARY_NAME
import test_source_exclusion as legacy_fixture
from test_derived_collection_scope import create_derived_amendment
from test_temporary_collection_scope import create_temporary_amendment

ROOT = Path(__file__).resolve().parents[1]


class TemporaryFixture:
    file = legacy_fixture.SourceExclusionTests.file
    seed = legacy_fixture.SourceExclusionTests.seed
    amendment = legacy_fixture.SourceExclusionTests.amendment

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='temporary_reconciliation_', dir=ROOT / 'runtime/tmp')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.source = self.base / 'source'; self.source.mkdir()
        self.pipeline = self.base / 'pipeline'; self.pipeline.mkdir()
        self.run = self.pipeline / 'runs/fixture_run'; self.run.mkdir(parents=True)
        self.checkpoints = {n: self.run / name for n, name in reconciliation.CHECKPOINTS.items()}
        self.checkpoint = self.checkpoints[1]; self.checkpoint.mkdir()
        self.config = {'source_root': str(self.source), 'pipeline_root': str(self.pipeline),
            'workers': 1, 'inventory_commit_files': 1, 'max_record_bytes': 1024 * 1024,
            'batch_size': 1, 'seed': 1729, 'dedup': {'seed': 1729}, 'evaluation': {},
            'tokenizer': {'local_path': None}, 'validation': {'schema_path': str(ROOT / 'schemas/canonical-sft.schema.json')}}
        atomic_json(self.pipeline / 'configs/pipeline.yaml', self.config)
        atomic_json(self.pipeline / 'configs/reviewer.yaml', {'enabled': False, 'canary_size': 1})
        (self.pipeline / 'schemas').mkdir()
        shutil.copyfile(ROOT / 'schemas/canonical-sft.schema.json', self.pipeline / 'schemas/canonical-sft.schema.json')
        fsync = patch('os.fsync'); fsync.start(); self.addCleanup(fsync.stop)
        original_connect = sqlite3.connect
        def fast_connection(*args, **kwargs):
            db = original_connect(*args, **kwargs); db.execute('PRAGMA synchronous=OFF'); return db
        sqlite = patch('sqlite3.connect', side_effect=fast_connection)
        sqlite.start(); self.addCleanup(sqlite.stop)
        original_inventory_connect = inventory._connect
        def inventory_connect(path):
            db = original_inventory_connect(path); db.execute('PRAGMA synchronous=OFF'); return db
        connector = patch.object(inventory, '_connect', inventory_connect)
        connector.start(); self.addCleanup(connector.stop)
        self.index = self.file('greek_training/.git/index', b'old index'); self.seed(self.index)
        self.index.write_bytes(b'changed index')
        self.incident = {'run_id': self.run.name, 'status': 'halted_source_integrity_failure',
            'source_file': 'greek_training/.git/index', 'sha256_matches': False,
            'baseline_sha256': hashlib.sha256(b'old index').hexdigest(),
            'observed_sha256': hashlib.sha256(b'changed index').hexdigest()}
        self.incident_path = self.run / 'integrity_incidents/original/incident.json'
        atomic_json(self.incident_path, self.incident)
        payload = (json.dumps({'text': 'Το κατάστημα παρέδωσε έγκαιρα την παραγγελία και η εξυπηρέτηση ήταν εξαιρετική.',
                              'label': 'Positive'}, ensure_ascii=False) + '\n').encode()
        self.mixture = self.file('greek_training/mixed.jsonl', payload); self.seed(self.mixture)
        self.temporary_source = self.file('greek_training_temp/data.jsonl', '{"text":"Προσωρινό τεκμήριο."}\n'.encode())
        self.original = self.file('skroutz_shop_reviews_sentiment_analysis/reviews.jsonl', payload)
        self.neighbor = self.file('greek_training_temp_extra/data.jsonl', b'{}\n')
        self.amendment(); create_derived_amendment(self)
        atomic_json(self.run / 'configuration.json', self.config)

    def build_four(self, keep_wal=False):
        if keep_wal:
            self.keeper = inventory._connect(self.checkpoint / 'inventory_shard_00.sqlite')
            self.addCleanup(self.keeper.close)
        self.results = {'1': inventory.run_inventory(self.source, self.checkpoint, self.config)}
        checkpoint_complete(self.pipeline, self.checkpoint, self.results['1'], self.config)
        self.historical_audit = audit_inventory(self.checkpoint, self.run / 'audits/inventory')
        self.results['2'] = tasks.run_plans(self.source, self.checkpoint, self.checkpoints[2], self.config)
        checkpoint_complete(self.pipeline, self.checkpoints[2], self.results['2'], self.config)
        self.results['3'] = tasks.run_generation(self.source, self.checkpoint, self.checkpoints[2], self.checkpoints[3], self.config)
        checkpoint_complete(self.pipeline, self.checkpoints[3], self.results['3'], self.config)
        self.results['4'] = tasks.run_validation(self.checkpoints[3], self.checkpoints[4], self.config)
        self.results['4']['contamination'] = check_contamination(self.checkpoints[4] / 'validated.jsonl', self.pipeline,
            self.checkpoints[4] / 'contamination', self.config)
        checkpoint_complete(self.pipeline, self.checkpoints[4], self.results['4'], self.config)

    def authorize_temporary(self):
        self.temporary_source.write_bytes(b'{"changed":true}\n')
        return create_temporary_amendment(self)

    def checkpoint_bytes(self):
        return {str(path.relative_to(self.run)): sha256_file(path)
                for checkpoint in self.checkpoints.values() for path in checkpoint.rglob('*')
                if path.is_file() and not path.name.endswith('-shm')}


class TemporaryScopeReconciliationTests(TemporaryFixture, unittest.TestCase):
    def test_wal_backed_reuse_pins_frozen_data_not_readmarks(self):
        self.build_four(keep_wal=True)
        wal = self.checkpoint / 'inventory_shard_00.sqlite-wal'
        self.assertGreater(wal.stat().st_size, 0)
        before = self.checkpoint_bytes(); old_stats = json.loads((self.checkpoint / 'statistics.json').read_text())
        self.authorize_temporary()
        view = reconciliation.prepare_scope_reconciliation(self.run, self.config)
        self.assertEqual(view, reconciliation.validate_scope_reconciliation(self.run, self.config, view['reference']))
        self.assertEqual(self.checkpoint_bytes(), before)
        self.assertEqual(old_stats, view['inputs']['checkpoint_statistics']['1'])
        self.assertEqual(view['statistics']['statistics']['historical_excluded_files'], 3)
        self.assertEqual(view['reuse_proof']['raw_candidates'], 1)
        pins = view['inputs']['artifacts']
        self.assertIn('checkpoint_01_inventory/inventory_shard_00.sqlite-wal', pins)
        self.assertFalse(any(name.endswith('-shm') for name in pins))
        # Actual WAL-backed SQLite shared-memory readmarks are advisory. Mutate
        # one unused readmark slot, validate without opening SQLite, then restore.
        shm = self.checkpoint / 'inventory_shard_00.sqlite-shm'
        with shm.open('r+b') as stream:
            stream.seek(116); original_readmark = stream.read(4)
            stream.seek(116); stream.write(bytes([original_readmark[0] ^ 1]) + original_readmark[1:])
        try:
            self.assertEqual(view, reconciliation.validate_scope_reconciliation(self.run, self.config))
        finally:
            with shm.open('r+b') as stream:
                stream.seek(116); stream.write(original_readmark)
        with wal.open('r+b') as stream:
            stream.seek(-1, 2); original_tail = stream.read(1)
            stream.seek(-1, 2); stream.write(bytes([original_tail[0] ^ 1]))
        try:
            with self.assertRaisesRegex(RuntimeError, 'historical_inventory_audit_database_or_wal_changed'):
                reconciliation.validate_scope_reconciliation(self.run, self.config)
        finally:
            with wal.open('r+b') as stream:
                stream.seek(-1, 2); stream.write(original_tail)
        atomic_json(self.checkpoint / 'progress.json', {'advisory': 'changed after reconciliation'})
        self.assertEqual(view, reconciliation.validate_scope_reconciliation(self.run, self.config))

    def test_tampered_view_checkpoint_authorization_and_missing_marker_fail(self):
        self.build_four(); self.authorize_temporary()
        view = reconciliation.prepare_scope_reconciliation(self.run, self.config)
        paths = [self.run / view['reference']['view_path'], self.checkpoints[4] / 'validated.jsonl',
                 self.run / TEMPORARY_NAME, self.run / view['reference']['path']]
        for path in paths:
            original = path.read_bytes()
            with self.subTest(path=path):
                path.write_bytes(original + b' ')
                with self.assertRaises((ValueError, RuntimeError)):
                    reconciliation.validate_scope_reconciliation(self.run, self.config)
                path.write_bytes(original)
        marker = self.run / view['reference']['path']; original = marker.read_bytes(); marker.unlink()
        with self.assertRaises(FileNotFoundError):
            reconciliation.validate_scope_reconciliation(self.run, self.config)
        marker.write_bytes(original)
        foreign = self.checkpoints[3] / 'unexpected.jsonl'; foreign.write_text('{}\n')
        with self.assertRaisesRegex(RuntimeError, 'unexpected_unfrozen'):
            reconciliation.validate_scope_reconciliation(self.run, self.config)

    def test_accepted_temporary_dispositions_and_all_raw_candidates_block_reuse(self):
        self.build_four(); self.authorize_temporary()
        for number in (2, 3):
            path = self.checkpoints[number] / 'source_dispositions.jsonl'; original = path.read_bytes()
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            next(row for row in rows if row['source_file'].startswith('greek_training_temp/'))['status'] = 'accepted'
            path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
            with self.assertRaisesRegex(RuntimeError, 'excluded_source_accepted'):
                reconciliation._reuse_proof(self.run, validate_source_exclusion(self.checkpoint, self.config))
            path.write_bytes(original)
        path = next(self.checkpoints[3].glob('shards/*/candidates.jsonl'))
        candidate = json.loads(path.read_text()); candidate['metadata']['source_file'] = 'greek_training_temp/data.jsonl'
        path.write_text(json.dumps(candidate) + '\n')
        with self.assertRaisesRegex(RuntimeError, 'excluded_source_present_in_raw_candidates'):
            reconciliation._reuse_proof(self.run, validate_source_exclusion(self.checkpoint, self.config))

    def test_pass_four_provenance_and_partition_must_match_raw(self):
        self.build_four(); self.authorize_temporary()
        scope = validate_source_exclusion(self.checkpoint, self.config)
        path = self.checkpoints[4] / 'quarantined.jsonl'
        original = path.read_bytes()
        row = json.loads(original)
        for change in ('excluded', 'identity', 'content', 'duplicate', 'missing'):
            changed = json.loads(original)
            if change == 'excluded':
                changed['candidate']['metadata']['source_file'] = 'greek_training_temp/data.jsonl'
            elif change == 'identity':
                changed['candidate']['id'] = 'not-a-raw-candidate'
            elif change == 'content':
                changed['candidate']['messages'][-1]['content'] = 'changed answer'
            payload = json.dumps(changed) + '\n'
            if change == 'duplicate': payload += payload
            if change == 'missing': payload = ''
            path.write_text(payload)
            with self.subTest(change=change), self.assertRaisesRegex(RuntimeError, 'pass_four'):
                reconciliation._reuse_proof(self.run, scope)
        path.write_bytes(original)
        self.assertEqual(reconciliation._reuse_proof(self.run, scope)['quarantined_candidates'], 1)

    def test_interrupted_final_publication_recovers_only_pinned_complete_view(self):
        self.build_four(); self.authorize_temporary()
        real_atomic = reconciliation.atomic_json
        def interrupted(path, value):
            if Path(path).name == 'completion.json':
                raise OSError('injected publication interruption')
            return real_atomic(path, value)
        with patch.object(reconciliation, 'atomic_json', side_effect=interrupted):
            with self.assertRaisesRegex(OSError, 'injected publication'):
                reconciliation.prepare_scope_reconciliation(self.run, self.config)
        with self.assertRaises(FileNotFoundError):
            reconciliation.validate_scope_reconciliation(self.run, self.config)
        with patch('greek_sft.audit.reconcile_inventory_scope', side_effect=AssertionError('must reuse pinned view')):
            view = reconciliation.prepare_scope_reconciliation(self.run, self.config)
        self.assertEqual(view, reconciliation.validate_scope_reconciliation(self.run, self.config))

    def test_interrupted_inventory_view_is_preserved_but_never_reused(self):
        self.build_four(); self.authorize_temporary()
        def interrupted(checkpoint, output, config, audit):
            output.mkdir(parents=True); (output / 'unfinished.json').write_text('{}')
            raise OSError('injected ledger interruption')
        with patch('greek_sft.audit.reconcile_inventory_scope', side_effect=interrupted):
            with self.assertRaisesRegex(OSError, 'ledger interruption'):
                reconciliation.prepare_scope_reconciliation(self.run, self.config)
        with self.assertRaises(FileNotFoundError):
            reconciliation.validate_scope_reconciliation(self.run, self.config)
        view = reconciliation.prepare_scope_reconciliation(self.run, self.config)
        self.assertEqual(view['reuse_proof']['excluded_raw_candidates'], 0)
        self.assertEqual(len(list((self.run / 'scope_reconciliations').rglob('unfinished.json'))), 1)
