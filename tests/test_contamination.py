import json,tempfile,unittest
from pathlib import Path
from greek_sft.contamination import check_contamination
ROOT=Path(__file__).resolve().parents[1]
class ContaminationTests(unittest.TestCase):
    def test_detects_embedded_question_and_preserves_raw(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'runtime/tmp') as d:
            p=Path(d); ev=p/'eval.jsonl'; inp=p/'candidates.jsonl'
            question='Ποια είναι η επίσημη ονομασία του συγκεκριμένου εκπαιδευτικού προγράμματος;'
            ev.write_text(json.dumps({'question':question})+'\n')
            candidate={'id':'1','messages':[{'role':'system','content':'system'},{'role':'user','content':'Πρόλογος '+question+' επίλογος'},{'role':'assistant','content':'x'}],'metadata':{'source_name':'test'}}
            raw=json.dumps(candidate)+'\n'; inp.write_text(raw)
            result=check_contamination(inp,ROOT,p/'out',{'evaluation':{'greekmmlu_path':str(ev)}})
            self.assertEqual(result['counts']['quarantined'],1)
            self.assertEqual(inp.read_text(),raw)
            self.assertFalse(result['complete'])
    def test_assistant_contamination_and_resume_integrity(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'runtime/tmp') as d:
            p=Path(d); ev=p/'eval.jsonl'; inp=p/'candidates.jsonl'
            question='Ποια είναι η επίσημη ονομασία του συγκεκριμένου εκπαιδευτικού προγράμματος;'
            ev.write_text(json.dumps({'question':question})+'\n')
            candidate={'id':'1','messages':[{'role':'system','content':'system'},{'role':'user','content':'Άσχετο κείμενο.'},{'role':'assistant','content':question}],'metadata':{'source_name':'test','grounding_span':{'message_index':1,'start':0,'end':14}}}
            inp.write_text(json.dumps(candidate)+'\n'); config={'evaluation':{'greekmmlu_path':str(ev)}}
            report=check_contamination(inp,ROOT,p/'out',config)
            self.assertEqual(report['counts']['quarantined'],1)
            self.assertEqual(check_contamination(inp,ROOT,p/'out',config),report)
            (p/'out/clean_candidates.jsonl').write_text('tampered')
            with self.assertRaises(ValueError): check_contamination(inp,ROOT,p/'out',config)
    def test_partial_symlink_cannot_modify_source(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'runtime/tmp') as d:
            p=Path(d); original=p/'original'; original.write_text('immutable')
            inp=p/'candidates.jsonl'; inp.write_text(''); out=p/'out'; out.mkdir()
            (out/'clean_candidates.jsonl.partial').symlink_to(original)
            with self.assertRaises(ValueError): check_contamination(inp,ROOT,out,{})
            self.assertEqual(original.read_text(),'immutable')
    def test_private_only_cannot_claim_full_coverage(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'runtime/tmp') as d:
            p=Path(d); inp=p/'candidates.jsonl'; inp.write_text(''); ev=p/'eval.jsonl'; ev.write_text(json.dumps({'question':'Δοκιμή'})+'\n')
            report=check_contamination(inp,ROOT,p/'out',{'evaluation':{'private_paths':[str(ev)],'coverage_confirmed_by_user':True}})
            self.assertFalse(report['complete'])
    def test_missing_eval_is_not_a_clean_claim(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'runtime/tmp') as d:
            p=Path(d); inp=p/'c.jsonl'; inp.write_text('')
            result=check_contamination(inp,ROOT,p/'out',{'evaluation':{'greekmmlu_path':str(p/'missing')}})
            self.assertFalse(result['complete']); self.assertEqual(result['missing_datasets'],['GreekMMLU'])
if __name__=='__main__': unittest.main()
