"""A full five-pass run on immutable synthetic sources, with independent rehash."""
import hashlib,json,tempfile,unittest
from pathlib import Path
from greek_sft.inventory import run_inventory,verify_source_hashes
from greek_sft.tasks import run_plans,run_generation,run_validation
from greek_sft.contamination import check_contamination
from greek_sft.dedup import run_dedup
ROOT=Path(__file__).resolve().parents[1]
class PipelineIntegrationTests(unittest.TestCase):
    def test_all_five_passes_account_sources_and_block_unapproved_release(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'runtime/tmp') as temporary:
            work=Path(temporary); source=work/'immutable_source'; source.mkdir()
            family='skroutz_shop_reviews_sentiment_analysis'; (source/family).mkdir()
            row={'text':'Το κατάστημα παρέδωσε έγκαιρα την παραγγελία και η εξυπηρέτηση ήταν εξαιρετική.','label':'Positive'}
            data=source/family/'records.jsonl'; data.write_text(json.dumps(row,ensure_ascii=False)+'\n\n{invalid\n')
            (source/'opaque.bin').write_bytes(b'\x00\xff\x00')
            initial={str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest() for p in source.rglob('*') if p.is_file()}
            cfg={'workers':2,'max_record_bytes':1024*1024,'batch_size':1,'seed':1729,'validation':{'schema_path':str(ROOT/'schemas/canonical-sft.schema.json')},'dedup':{'seed':1729},'tokenizer':{'local_path':None},'evaluation':{}}
            c1,c2,c3,c4,c5=[work/f'checkpoint_{n}' for n in range(1,6)]
            inventory=run_inventory(source,c1,cfg)
            self.assertEqual(inventory['statistics']['files'],2)
            self.assertEqual(inventory['statistics']['records'],3)
            self.assertEqual(inventory['statistics']['status_malformed'],2)
            run_plans(source,c1,c2,cfg)
            generated=run_generation(source,c1,c2,c3,cfg)
            self.assertEqual(generated['source_files'],2)
            self.assertEqual(generated['classified_records'],3)
            self.assertEqual(generated['candidates'],1)
            validated=run_validation(c3,c4,cfg)
            self.assertEqual(validated['awaiting_api_review'],0)
            self.assertEqual(validated['quarantined'],1)
            contamination=check_contamination(c4/'validated.jsonl',ROOT,c4/'contamination',cfg)
            self.assertFalse(contamination['complete'])
            dedup=run_dedup([c4/'contamination/clean_candidates.jsonl'],c5,cfg)
            self.assertEqual(dedup['input_candidates'],0)
            self.assertEqual(dedup['required_stage_order'],['ExactSubstrings','MinhashDedup','SentenceDedup'])
            self.assertTrue(dedup['counts_reconciled'])
            self.assertFalse(dedup['release_ready'])
            verified=verify_source_hashes(source,c1,c5/'source_verification',cfg)
            self.assertTrue(verified['passed'])
            final={str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest() for p in source.rglob('*') if p.is_file()}
            self.assertEqual(initial,final)
            self.assertEqual(run_inventory(source,c1,cfg),inventory)
if __name__=='__main__': unittest.main()
