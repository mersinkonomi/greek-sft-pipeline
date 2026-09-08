"""Actual stage implementations must agree with independent release accounting."""
import hashlib,json,tempfile,unittest
from pathlib import Path
from greek_sft.audit import audit_inventory
from greek_sft.core import atomic_json,checkpoint_complete
from greek_sft.inventory import run_inventory
from greek_sft.integrity import verify_source_hashes
from greek_sft.tasks import run_plans,run_generation,run_validation
from greek_sft.contamination import check_contamination
from greek_sft.dedup import run_dedup
from greek_sft.review import estimate_review,prepare_canary
from greek_sft.reporting import CHECKPOINTS,create_audited_release
ROOT=Path(__file__).resolve().parents[1]
class FullAuditIntegrationTests(unittest.TestCase):
    def test_real_stage_artifacts_reconcile_without_release_approval(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'runtime/tmp') as temporary:
            work=Path(temporary); source=work/'source'; source.mkdir(); run=work/'run'; run.mkdir()
            family=source/'skroutz_shop_reviews_sentiment_analysis'; family.mkdir()
            row={'text':'Το κατάστημα παρέδωσε έγκαιρα την παραγγελία και η εξυπηρέτηση ήταν εξαιρετική.','label':'Positive'}
            (family/'records.jsonl').write_text(json.dumps(row,ensure_ascii=False)+'\n\n{invalid\n')
            (source/'opaque.bin').write_bytes(b'\x00\xff')
            before={str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest() for p in source.rglob('*') if p.is_file()}
            cfg={'workers':1,'batch_size':1,'seed':1729,'max_record_bytes':1024*1024,'validation':{'schema_path':str(ROOT/'schemas/canonical-sft.schema.json')},'dedup':{'seed':1729},'tokenizer':{'local_path':None},'evaluation':{}}
            atomic_json(run/'configuration.json',cfg)
            c={n:run/name for n,name in CHECKPOINTS.items()}; result={}
            result['1']=run_inventory(source,c[1],cfg)
            checkpoint_complete(ROOT,c[1],result['1'],cfg)
            audited=audit_inventory(c[1],run/'audits/inventory')
            result['2']=run_plans(source,c[1],c[2],cfg)
            checkpoint_complete(ROOT,c[2],result['2'],cfg)
            result['3']=run_generation(source,c[1],c[2],c[3],cfg)
            checkpoint_complete(ROOT,c[3],result['3'],cfg)
            result['4']=run_validation(c[3],c[4],cfg)
            result['4']['contamination']=check_contamination(c[4]/'validated.jsonl',ROOT,c[4]/'contamination',cfg)
            checkpoint_complete(ROOT,c[4],result['4'],cfg)
            result['5']=run_dedup([c[4]/'contamination/clean_candidates.jsonl'],c[5],cfg)
            verified=verify_source_hashes(source,c[1],c[5]/'source_verification',cfg)
            result['5']['source_verification']=verified
            checkpoint_complete(ROOT,c[5],result['5'],cfg)
            paths=sorted((c[5]/'completed/pre_api').glob('*/canonical.jsonl'))
            estimate=estimate_review(paths,{'enabled':False})
            final=create_audited_release(run,result,estimate,verified,audited)
            self.assertTrue(final['accounting_passed'],json.dumps(final,ensure_ascii=False))
            self.assertEqual(final['candidate_count'],0)
            self.assertFalse(final['release_ready'])
            self.assertEqual(result['3']['candidates'],1)
            self.assertEqual(result['4']['quarantined'],1)
            self.assertTrue(verified['passed'])
            self.assertEqual(prepare_canary(paths,run/'review/proposal')['canary_candidates'],0)
            after={str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest() for p in source.rglob('*') if p.is_file()}
            self.assertEqual(before,after)
if __name__=='__main__': unittest.main()
