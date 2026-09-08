"""Historical inventory stays immutable when a second exact source root is excluded."""
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from greek_sft import inventory, audit
from greek_sft.core import atomic_json, sha256_file

ROOT = Path(__file__).resolve().parents[1]
OLD = {'sha256': 'a'*64, 'frozen': True, 'amendment': {'excluded_source_roots': ['greek_training']}}
NEW = {'sha256': 'b'*64, 'frozen': True, 'predecessor': OLD,
       'amendment': {'excluded_source_roots': ['greek_training', 'greek_training_temp']}}


class TemporaryScopeInventoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT/'runtime/tmp')
        self.addCleanup(temporary.cleanup)
        self.run = Path(temporary.name)
        self.cp = self.run/'checkpoint_01_inventory'; self.cp.mkdir()
        self.output = self.run/'derived'
        self.rows = []
        for n, relative in enumerate(('greek_training/a', 'greek_training_temp/a',
                                       'greek_training_temp_extra/a', 'greek_training_temporary/a', 'other/a'), 1):
            self.rows.append({'relative_path': relative, 'size_bytes': n*10, 'record_count': n,
                              'record_boundary_complete': n != 2, 'sha256': str(n)*64,
                              'status': 'unsupported', 'reason': 'fixture', 'stats': {}, 'family': 'fixture'})
        db = sqlite3.connect(self.cp/'inventory_shard_00.sqlite')
        db.executescript('CREATE TABLE files(relative_path TEXT PRIMARY KEY,report TEXT,completed INTEGER);'
                         'CREATE TABLE record_ranges(relative_path TEXT,first_record INTEGER,last_record INTEGER,status TEXT,reason TEXT,row_hash_chain TEXT);')
        for row in self.rows:
            db.execute('INSERT INTO files VALUES(?,?,1)', (row['relative_path'], json.dumps(row)))
            db.execute('INSERT INTO record_ranges VALUES(?,?,?,?,?,?)',
                       (row['relative_path'],1,row['record_count'],'unsupported','fixture','f'*64))
        db.commit(); db.close()
        manifest = self.cp/'source_manifest.jsonl'
        manifest.write_text(''.join(json.dumps(row)+'\n' for row in self.rows))
        self.summary = {'workers': 1, 'source_exclusion_amendment': OLD,
                        'statistics': {'files':5,'bytes':150,'records':15,'files_with_unresolved_record_boundaries':1},
                        'families': {'fixture': {}}, 'manifest_sha256': sha256_file(manifest)}
        atomic_json(self.cp/'statistics.json', self.summary)
        atomic_json(self.cp/'manifest.json', {'complete':True,'source_manifest_sha256':sha256_file(manifest),
                                             'source_exclusion_amendment_sha256':OLD['sha256']})
        identity = {'manifest_sha256':sha256_file(manifest),'summary_sha256':sha256_file(self.cp/'statistics.json'),
                    'completion_sha256':sha256_file(self.cp/'manifest.json'),
                    'shards':{'inventory_shard_00.sqlite':sha256_file(self.cp/'inventory_shard_00.sqlite')}}
        self.historical = {'identified_accounting_passed':True,'source_exclusion_amendment':OLD,
                           'input_identity':identity,'totals':{'files':5,'bytes':150,'records':15},
                           'limitations':[], 'source_file_duplicate_artifacts_base_relative_to_run':'audits/inventory/source_file_duplicates'}
        self.historical_path = self.run/'audits/inventory/inventory_reconciliation.json'
        atomic_json(self.historical_path,self.historical)
        self.before = {str(p.relative_to(self.cp)):sha256_file(p) for p in self.cp.iterdir()}
        for target, kwargs in (
            ('greek_sft.audit.validate_source_exclusion', {'return_value':NEW}),
            ('greek_sft.audit.historical_source_exclusion', {'return_value':OLD}),
            ('greek_sft.audit.source_exclusion_artifact_paths', {'return_value':{}}),
            ('greek_sft.audit.validate_source_exclusion_binding', {'return_value':None}),
            ('os.fsync', {'return_value':None})):
            patcher=patch(target,**kwargs); patcher.start(); self.addCleanup(patcher.stop)

    def reconcile(self):
        with patch.object(audit,'audit_inventory',return_value=self.historical):
            return audit.reconcile_inventory_scope(self.cp,self.output,{},self.historical_path)

    def test_both_roots_neighbors_ranges_and_immutable_originals(self):
        result=self.reconcile()
        stats=result['statistics']['statistics']
        self.assertEqual(stats['historical_excluded_files'],2)
        self.assertEqual(stats['historical_excluded_bytes'],30)
        self.assertEqual(stats['historical_excluded_identified_records'],3)
        self.assertEqual(stats['historical_excluded_unresolved_boundary_files'],1)
        self.assertEqual(stats['in_scope_files'],3)
        ledger=result['statistics']['source_exclusion_accounting']
        rows=[json.loads(line) for line in (self.output/ledger['artifacts']['files.jsonl']).read_text().splitlines()]
        self.assertEqual([r['source_file'] for r in rows],['greek_training/a','greek_training_temp/a'])
        self.assertTrue(all(r['current_sha256'] is None for r in rows))
        self.assertEqual(ledger['counts']['historical_excluded_records_in_ranges'],3)
        self.assertEqual(self.before,{str(p.relative_to(self.cp)):sha256_file(p) for p in self.cp.iterdir()})
        self.assertFalse(result['audit']['full_original_source_integrity'])
        self.assertFalse(result['audit']['complete_semantic_record_coverage'])
        marker=json.loads((self.output/'manifest.json').read_text())
        self.assertTrue(marker['complete'])
        for name,digest in marker['artifacts'].items():
            self.assertEqual(sha256_file(self.output/name),digest)
        self.assertEqual(result['audit']['source_file_duplicate_artifacts_base_relative_to_run'],
                         self.historical['source_file_duplicate_artifacts_base_relative_to_run'])

    def test_overlapping_duplicate_roots_are_not_double_counted(self):
        scope={**NEW,'amendment':{'excluded_source_roots':['greek_training','greek_training','greek_training/a','greek_training_temp']}}
        ledger=inventory._write_source_exclusion_ledger(self.cp,1,scope,'c'*64,ledger_checkpoint=self.output)
        self.assertEqual(ledger['counts']['historical_excluded_files'],2)
        self.assertEqual(ledger['counts']['historical_excluded_records_in_ranges'],3)

    def test_sql_metacharacters_are_literal(self):
        db=sqlite3.connect(':memory:'); self.addCleanup(db.close)
        db.execute('CREATE TABLE files(relative_path TEXT)')
        db.executemany('INSERT INTO files VALUES(?)',[(p,) for p in ('root*/a','rootx/a','root*neighbor/a')])
        condition,parameters=inventory._exclusion_sql({'amendment':{'excluded_source_roots':['root*']}})
        self.assertEqual(db.execute('SELECT relative_path FROM files WHERE '+condition,parameters).fetchall(),[('root*/a',)])

    def test_interrupted_or_completed_output_cannot_be_reused(self):
        self.output.mkdir(); (self.output/'partial').write_text('incomplete')
        with self.assertRaisesRegex(audit.AuditFailure,'already_exists_or_interrupted'): self.reconcile()

    def test_manifest_and_shard_tampering_rejected(self):
        path=self.cp/'source_manifest.jsonl'; original=path.read_bytes(); path.write_bytes(original+b'\n')
        with self.assertRaises((audit.AuditFailure,ValueError)): self.reconcile()
        path.write_bytes(original)
        db=sqlite3.connect(self.cp/'inventory_shard_00.sqlite'); db.execute("UPDATE files SET report=report||' '"); db.commit();db.close()
        with self.assertRaisesRegex(audit.AuditFailure,'historical_shard_changed'): self.reconcile()
        self.assertFalse((self.output/'manifest.json').exists())

    def test_supplied_historical_audit_is_bound_to_verified_artifact(self):
        altered={**self.historical,'totals':{}}
        with patch.object(audit,'audit_inventory',return_value=altered):
            with self.assertRaisesRegex(audit.AuditFailure,'binding_mismatch'):
                audit.reconcile_inventory_scope(self.cp,self.output,{},self.historical_path)

    def test_historical_audit_cache_survives_effective_scope_extension(self):
        db=sqlite3.connect(self.cp/'inventory_shard_00.sqlite')
        for row in self.rows:
            row['stats']={'status_unsupported':row['record_count'],'reason_fixture':row['record_count']}
            db.execute('UPDATE files SET report=? WHERE relative_path=?',(json.dumps(row),row['relative_path']))
        db.commit(); db.close()
        with patch.object(inventory,'validate_source_exclusion_binding',return_value=None):
            inventory._summarize(self.cp,1,{},source_exclusion=OLD)
        output=self.run/'real_historical_audit'
        with patch('greek_sft.source_duplicates.audit_source_file_duplicates',return_value={'fixture':True}), \
                patch.object(audit,'validate_source_exclusion',return_value=OLD):
            original=audit.audit_inventory(self.cp,output,{})
        before={str(p.relative_to(self.cp)):sha256_file(p) for p in self.cp.rglob('*') if p.is_file()}
        audit_sha=sha256_file(output/'inventory_reconciliation.json')
        with patch('greek_sft.source_duplicates.audit_source_file_duplicates',return_value={'fixture':True}):
            reused=audit.audit_inventory(self.cp,output,{})
        self.assertEqual(original,reused)
        self.assertEqual(reused['source_exclusion_amendment'],OLD)
        self.assertEqual(audit_sha,sha256_file(output/'inventory_reconciliation.json'))
        self.assertEqual(before,{str(p.relative_to(self.cp)):sha256_file(p) for p in self.cp.rglob('*') if p.is_file()})

    def test_completed_inventory_requires_explicit_reconciliation(self):
        source=self.run/'source'; source.mkdir()
        with patch.object(inventory,'validate_source_exclusion',return_value=NEW), patch.object(inventory,'validate_inventory_scope',return_value=None):
            with self.assertRaisesRegex(inventory.InventoryScopeConflict,'requires_scope_reconciliation'):
                inventory.run_inventory(source,self.cp,{})


class RealTemporaryScopeInventoryTests(unittest.TestCase):
    def test_real_authorization_chain_reuses_historical_audit_and_derives_new_scope(self):
        import test_temporary_collection_scope as fixture
        case = fixture.TemporaryCollectionScopeTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        audit_path = case.run/'audits/inventory/inventory_reconciliation.json'
        relative_checkpoint = case.checkpoint.relative_to(Path.cwd())
        historic = audit.audit_inventory(relative_checkpoint, audit_path.parent, case.config)
        checkpoint_before = case.snapshot()
        audit_before = audit_path.read_bytes()
        fixture.create_temporary_amendment(case)
        from greek_sft.source_scope import validate_source_exclusion
        effective = validate_source_exclusion(case.checkpoint, case.config, freeze=True)
        self.assertEqual(audit.audit_inventory(relative_checkpoint,audit_path.parent,case.config),historic)
        original_open = inventory.open_source_readonly
        def guarded_open(path, *args, **kwargs):
            if Path(path) == case.source or case.source in Path(path).parents:
                raise AssertionError('no source reads')
            return original_open(path, *args, **kwargs)
        with patch.object(inventory,'open_source_readonly',side_effect=guarded_open):
            result = audit.reconcile_inventory_scope(case.checkpoint,case.run/'effective_inventory',case.config,audit_path)
        self.assertEqual(result['statistics']['source_exclusion_amendment'],effective)
        self.assertEqual(result['statistics']['statistics']['in_scope_files'],1)
        self.assertEqual(checkpoint_before,case.snapshot())
        self.assertEqual(audit_before,audit_path.read_bytes())


if __name__ == '__main__': unittest.main()
