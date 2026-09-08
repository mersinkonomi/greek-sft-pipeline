import copy, json, os, tempfile, unittest
from pathlib import Path
from greek_sft.core import atomic_json, checked_output, digest, validate_roots
from greek_sft.review import ReviewEngine, ApprovalRequired, BudgetExceeded, gold_reliability, preserve_revision
ROOT=Path(__file__).resolve().parents[1]
class CoreReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=ROOT/'runtime/tmp'); self.addCleanup(self.temp.cleanup); self.base=Path(self.temp.name)
    def test_unsafe_output_paths(self):
        with self.assertRaises(ValueError): checked_output(self.base/'../../../../outside',self.base)
        source=self.base/'source'; source.mkdir()
        child=source/'output'; child.mkdir()
        with self.assertRaises(ValueError): validate_roots(source,child)
        link=self.base/'link'; link.symlink_to(source)
        with self.assertRaises(ValueError): checked_output(link,self.base/'source'/'output')
    def test_disabled_api_never_calls_transport(self):
        calls=[]
        engine=ReviewEngine(ROOT,self.base,{'enabled':False},lambda *a:calls.append(a))
        with self.assertRaises(ApprovalRequired): engine.review_one({}, {})
        self.assertEqual(calls,[])
    def configuration(self):
        return {'enabled':True,'provider':'fake','protocol':'test','base_url':'https://example.invalid','model':'test','api_key_env':'GREEK_SFT_TEST_SECRET','requests_per_minute':60000,'max_concurrency':1,'timeout_seconds':1,'max_retries':0,'max_tokens_total':100000,'max_output_tokens_per_call':100,'allow_external_candidate_text':True,'allow_external_source_evidence':True,'canary_approved':True,'rubric_version':'test','canary_size':1,'approved_canary_hashes':[digest({'id':'a'})]}
    def test_invalid_response_quarantined_without_secret(self):
        os.environ['GREEK_SFT_TEST_SECRET']='test-do-not-persist'; self.addCleanup(os.environ.pop,'GREEK_SFT_TEST_SECRET',None)
        def bad(*args): raise TimeoutError('test-do-not-persist')
        result=ReviewEngine(ROOT,self.base,self.configuration(),bad).review_one({'id':'a'}, {})
        self.assertEqual(result['review_status'],'quarantined')
        for path in self.base.rglob('*.json'): self.assertNotIn('test-do-not-persist',path.read_text())
    def test_invalid_mode_is_rejected(self):
        engine=ReviewEngine(ROOT,self.base,self.configuration(),lambda *a: {})
        with self.assertRaises(ApprovalRequired): engine.authorize('FULL')
    def test_unapproved_canary_member_never_calls_transport(self):
        os.environ['GREEK_SFT_TEST_SECRET']='test'; self.addCleanup(os.environ.pop,'GREEK_SFT_TEST_SECRET',None)
        calls=[]; engine=ReviewEngine(ROOT,self.base,self.configuration(),lambda *a:calls.append(a))
        with self.assertRaises(ApprovalRequired): engine.review_one({'id':'outside'}, {})
        with self.assertRaises(ApprovalRequired): engine.review_batch(iter([{'id':'a'},{'id':'b'}]),lambda x: {})
        self.assertEqual(calls,[])
    def test_atomic_write_rejects_source_symlink(self):
        from greek_sft.core import atomic_text
        source=self.base/'original'; source.mkdir(); original=source/'file'; original.write_text('immutable')
        link=self.base/'output'; link.symlink_to(source)
        with self.assertRaises(ValueError): atomic_text(link/'file','changed')
        self.assertEqual(original.read_text(),'immutable')
    def test_corrupt_cached_acceptance_is_quarantined_and_preserved(self):
        os.environ['GREEK_SFT_TEST_SECRET']='test'; self.addCleanup(os.environ.pop,'GREEK_SFT_TEST_SECRET',None)
        calls=[]
        def transport(*args):
            calls.append(1)
            return {'example_id':'a','decision':'accept','scores':{k:4 for k in ['correctness','grounding','instruction_compliance','greek_naturalness','completeness','safety_privacy','training_value']},'issue_codes':[],'short_reason':'Κατάλληλο.','proposed_revision':None}
        engine=ReviewEngine(ROOT,self.base,self.configuration(),transport)
        self.assertEqual(engine.review_one({'id':'a'},{})['review_status'],'accepted')
        path=next((self.base/'cache').glob('*.json')); cached=json.loads(path.read_text()); cached['response']['scores']['grounding']=0
        bad=json.dumps(cached); path.write_text(bad)
        result=engine.review_one({'id':'a'},{})
        self.assertEqual(result['review_status'],'quarantined'); self.assertEqual(result['reason'],'invalid_cached_api_response')
        self.assertEqual(path.read_text(),bad); self.assertEqual(len(calls),1)
        self.assertEqual(len(list((self.base/'failures').glob('*.json'))),1)
    def test_driver_event_leaf_cannot_modify_source(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('pipeline_test_driver',ROOT/'scripts/run_pipeline.py'); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        original=self.base/'original'; original.write_text('immutable'); (self.base/'events.jsonl').symlink_to(original)
        with self.assertRaises(ValueError): module.event(self.base,'test')
        self.assertEqual(original.read_text(),'immutable')
    def test_validation_failure_gate_applies_to_saved_statistics(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('pipeline_test_driver_gate',ROOT/'scripts/run_pipeline.py'); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        stats={'candidates_entering':100,'deterministic_content_checks_passed':90}
        with self.assertRaises(RuntimeError): module.enforce_validation_gate(self.base,stats,{'validation':{'maximum_processing_error_rate':.01}},{})
        self.assertEqual(json.loads((self.base/'state.json').read_text())['status'],'halted_excessive_deterministic_failure_rate')
    def test_full_review_requires_separate_approval(self):
        engine=ReviewEngine(ROOT,self.base,self.configuration(),lambda *a: {})
        with self.assertRaises(ApprovalRequired): engine.authorize('full')
    def test_budget_stops_before_transport(self):
        os.environ['GREEK_SFT_TEST_SECRET']='test'; self.addCleanup(os.environ.pop,'GREEK_SFT_TEST_SECRET',None)
        calls=[]; conf=self.configuration(); conf['max_tokens_total']=1
        engine=ReviewEngine(ROOT,self.base,conf,lambda *a:calls.append(a))
        with self.assertRaises(BudgetExceeded): engine.review_one({'id':'a'}, {})
        self.assertEqual(calls,[])
    def test_missing_gold_review_fails(self):
        self.assertFalse(gold_reliability([{'example_id':'a','decision':'accept'}],[])['passed'])
    def test_revision_is_independently_pending(self):
        original={'id':'old','messages':[{'content':'old'}],'metadata':{'review_status':'accepted'}}
        proposed=copy.deepcopy(original); proposed['messages'][0]['content']='new'
        revised=preserve_revision(original,proposed,self.base,[])
        self.assertNotEqual(revised['id'],'old'); self.assertEqual(revised['metadata']['review_status'],'pending')
        self.assertEqual(original['metadata']['review_status'],'accepted')
if __name__=='__main__': unittest.main()
