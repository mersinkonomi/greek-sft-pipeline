import hashlib, json, sqlite3, tempfile, unittest
from unittest.mock import patch
from pathlib import Path
from greek_sft.audit import AuditFailure, audit_inventory
ROOT=Path(__file__).resolve().parents[1]
class InventoryAccountingTests(unittest.TestCase):
    def setUp(self):
        # Range/accounting unit tests use explicit ledgers; inventory durability
        # and crash recovery are exercised separately in test_inventory.py.
        self.temp=tempfile.TemporaryDirectory(dir=ROOT/'runtime/tmp')
        self.work=Path(self.temp.name); self.checkpoint=self.work/'checkpoint'; self.checkpoint.mkdir()
        h='a'*64
        records=[{'relative_path':'opaque.bin','family':'fixture','size_bytes':2,'sha256':h,'record_count':0,'record_boundary_complete':False,'status':'unsupported','reason':'opaque','stats':{}},
          {'relative_path':'sample.jsonl','family':'fixture','size_bytes':42,'sha256':h,'record_count':3,'record_boundary_complete':True,'status':'quarantined','reason':'malformed_rows',
            'stats':{'status_license_blocked':1,'status_malformed':2,'reason_license_unknown':1,'reason_invalid_json':2}}]
        with sqlite3.connect(self.checkpoint/'inventory_shard_00.sqlite') as db:
            db.execute('PRAGMA journal_mode=OFF'); db.execute('PRAGMA synchronous=OFF')
            db.execute('CREATE TABLE files(relative_path TEXT PRIMARY KEY,report TEXT,completed INTEGER)')
            db.execute('CREATE TABLE record_ranges(relative_path TEXT,first_record INTEGER,last_record INTEGER,status TEXT,reason TEXT,row_hash_chain TEXT)')
            db.executemany('INSERT INTO files VALUES(?,?,1)',[(x['relative_path'],json.dumps(x)) for x in records])
            db.executemany('INSERT INTO record_ranges VALUES(?,?,?,?,?,?)',[('sample.jsonl',1,1,'license_blocked','license_unknown',h),('sample.jsonl',2,3,'malformed','invalid_json',h)])
        db.close()
        raw=''.join(json.dumps(x)+'\n' for x in records).encode(); (self.checkpoint/'source_manifest.jsonl').write_bytes(raw)
        (self.checkpoint/'manifest.json').write_text(json.dumps({'complete':True,'source_manifest_sha256':hashlib.sha256(raw).hexdigest()}))
        stats={'files':2,'records':3,'bytes':44,'file_status_unsupported':1,'file_status_quarantined':1,'files_with_unresolved_record_boundaries':1,'status_license_blocked':1,'status_malformed':2,'reason_license_unknown':1,'reason_invalid_json':2}
        family={k:v for k,v in stats.items() if k!='files_with_unresolved_record_boundaries'}
        (self.checkpoint/'statistics.json').write_text(json.dumps({'workers':1,'statistics':stats,'families':{'fixture':family}}))
        self.writer=patch('greek_sft.audit.atomic_json',lambda p,v:Path(p).write_text(json.dumps(v)))
        self.writer.start()
        self.duplicates=patch("greek_sft.source_duplicates.audit_source_file_duplicates",return_value={"unit_fixture":True})
        self.duplicates.start()
    def tearDown(self):
        self.duplicates.stop(); self.writer.stop(); self.temp.cleanup()
    def mutate(self,statement):
        with sqlite3.connect(self.checkpoint/'inventory_shard_00.sqlite') as db:
            db.execute('PRAGMA synchronous=OFF'); db.execute(statement)
        db.close()
    def test_identified_records_reconcile_opaque_boundaries_remain_unresolved(self):
        result=audit_inventory(self.checkpoint,self.work/'audit')
        self.assertTrue(result['identified_accounting_passed'])
        self.assertFalse(result['complete_semantic_record_coverage'])
        self.assertEqual(result['totals']['records'],3)
        self.assertEqual(result['totals']['files'],2)
        self.assertEqual(result['record_status_counts']['malformed'],2)
        self.assertEqual(audit_inventory(self.checkpoint,self.work/'audit'),result)
    def test_missing_range_cannot_be_hidden_by_file_totals(self):
        self.mutate("DELETE FROM record_ranges WHERE first_record=1")
        with self.assertRaises(AuditFailure): audit_inventory(self.checkpoint,self.work/'audit')
        report=json.loads((self.work/'audit/inventory_reconciliation.json').read_text())
        self.assertGreater(report['totals']['accounting_errors'],0)
        self.assertFalse(report['identified_accounting_passed'])
    def test_wrong_status_is_detected_even_when_counts_match(self):
        self.mutate("UPDATE record_ranges SET status='accepted' WHERE first_record=1")
        with self.assertRaises(AuditFailure): audit_inventory(self.checkpoint,self.work/'audit')
    def test_extra_orphan_range_is_detected(self):
        self.mutate("INSERT INTO record_ranges VALUES('zz_orphan',1,1,'accepted','fixture','"+'a'*64+"')")
        with self.assertRaises(AuditFailure): audit_inventory(self.checkpoint,self.work/'audit')
    def test_changed_shard_invalidates_existing_audit(self):
        audit_inventory(self.checkpoint,self.work/'audit')
        self.mutate("DELETE FROM record_ranges WHERE first_record=1")
        with self.assertRaisesRegex(AuditFailure,'audit_inputs_changed'): audit_inventory(self.checkpoint,self.work/'audit')
    def test_corrupt_family_summary_is_rejected(self):
        path=self.checkpoint/'statistics.json'; summary=json.loads(path.read_text())
        family=next(iter(summary['families'])); summary['families'][family]['records']+=1
        path.write_text(json.dumps(summary))
        with self.assertRaises(AuditFailure): audit_inventory(self.checkpoint,self.work/'audit')
    def test_corrupt_global_reason_summary_is_rejected(self):
        path=self.checkpoint/'statistics.json'; summary=json.loads(path.read_text())
        summary['statistics']['reason_fixture_unknown']=3; path.write_text(json.dumps(summary))
        with self.assertRaises(AuditFailure): audit_inventory(self.checkpoint,self.work/'audit')
    def test_changed_summary_invalidates_existing_audit(self):
        audit_inventory(self.checkpoint,self.work/'audit')
        path=self.checkpoint/'statistics.json'; summary=json.loads(path.read_text())
        summary['statistics']['records']+=1; path.write_text(json.dumps(summary))
        with self.assertRaisesRegex(AuditFailure,'audit_inputs_changed'): audit_inventory(self.checkpoint,self.work/'audit')
    def test_wal_only_mutation_invalidates_existing_audit(self):
        db=sqlite3.connect(self.checkpoint/'inventory_shard_00.sqlite')
        try:
            db.execute('PRAGMA journal_mode=WAL'); db.execute('PRAGMA synchronous=OFF')
            db.execute("UPDATE files SET completed=1"); db.commit()
            audit_inventory(self.checkpoint,self.work/'audit')
            before=hashlib.sha256((self.checkpoint/'inventory_shard_00.sqlite').read_bytes()).hexdigest()
            db.execute('DELETE FROM record_ranges WHERE first_record=1'); db.commit()
            self.assertEqual(before,hashlib.sha256((self.checkpoint/'inventory_shard_00.sqlite').read_bytes()).hexdigest())
            with self.assertRaisesRegex(AuditFailure,'audit_inputs_changed'): audit_inventory(self.checkpoint,self.work/'audit')
        finally: db.close()
    def test_checkpoint_cannot_be_used_as_output(self):
        with self.assertRaises(AuditFailure): audit_inventory(self.checkpoint,self.checkpoint/'audit')
if __name__=='__main__': unittest.main()
