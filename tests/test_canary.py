import json,tempfile,unittest
from pathlib import Path
from greek_sft.review import prepare_canary
ROOT=Path(__file__).resolve().parents[1]
class CanaryTests(unittest.TestCase):
    def test_stratified_deterministic_proposal_never_approves(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'runtime/tmp') as d:
            p=Path(d); source=p/'input.jsonl'
            rows=[{'id':str(i),'messages':[],'metadata':{'source_name':'a' if i<8 else 'b','domain':'test','task_type':'classification'}} for i in range(10)]
            source.write_text(''.join(json.dumps(x)+'\n' for x in rows))
            result=prepare_canary([source],p/'first',size=4)
            self.assertEqual(result['canary_candidates'],4); self.assertEqual(result['strata_represented'],2); self.assertFalse(result['approved'])
            source.write_text(''.join(json.dumps(x)+'\n' for x in reversed(rows)))
            other=prepare_canary([source],p/'second',size=4)
            self.assertEqual(result,other)
            self.assertTrue(all(not x['manually_inspected'] for x in map(json.loads,(p/'first/manual_gold_pending.jsonl').read_text().splitlines())))
    def test_changed_proposal_is_not_overwritten(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'runtime/tmp') as d:
            p=Path(d); source=p/'input.jsonl'; source.write_text('')
            prepare_canary([source],p/'proposal',size=1)
            target=p/'proposal/manifest.json'; target.write_text('previous reviewed proposal')
            with self.assertRaises(ValueError): prepare_canary([source],p/'proposal',size=1)
            self.assertEqual(target.read_text(),'previous reviewed proposal')
if __name__=='__main__': unittest.main()
