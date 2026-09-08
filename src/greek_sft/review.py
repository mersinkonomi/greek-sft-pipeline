"""Review orchestration. No live provider is selected or contacted by default.

Transport is injected only after explicit provider/protocol approval. It must accept
(payload, key, timeout_seconds, idempotency_key) and return a parsed JSON object.
"""
from __future__ import annotations
import json, os, threading, time
from collections import Counter
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from .core import atomic_json, canonical_json, digest, read_jsonl, sha256_file

REQUIRED = ('provider','protocol','base_url','model','api_key_env','requests_per_minute','max_concurrency','timeout_seconds','max_retries')

def candidate_hash(candidate):
    return digest(candidate)

def estimate_review(paths, config):
    count = chars = utf8_bytes = 0
    sources = Counter()
    for path in paths:
        for candidate in read_jsonl(path):
            value = canonical_json(candidate)
            count += 1; chars += len(value); utf8_bytes += len(value.encode())
            sources[candidate['metadata']['source_name']] += 1
    estimated_input = (chars + 3) // 4 + count * 1500
    output_max = count * int(config.get('max_output_tokens_per_call', 1000))
    cost = None
    ip, op = config.get('input_price_per_million_tokens'), config.get('output_price_per_million_tokens')
    if ip is not None and op is not None: cost = (estimated_input * ip + output_max * op) / 1_000_000
    return {'candidates':count,'expected_calls_without_retries':count,'maximum_calls_with_retries':count*(1+int(config.get('max_retries') or 0)), 'by_source':dict(sources), 'estimated_input_tokens':estimated_input,'maximum_output_tokens':output_max, 'estimated_cost_usd':cost,'estimate_method':'character/4 estimate plus 1500 tokens per candidate for evidence/rubric; measure evidence before approval','exact_token_count':False,'canary_size':min(count,int(config.get('canary_size',30))), 'approved_for_network':False}

class ApprovalRequired(RuntimeError): pass
class BudgetExceeded(RuntimeError): pass

class ReviewEngine:
    def __init__(self, root, run_dir, config, transport=None, *, clock=time.monotonic, sleeper=time.sleep):
        self.root, self.run = Path(root), Path(run_dir)
        self.config, self.transport = config, transport
        self.clock, self.sleep = clock, sleeper
        self.lock = threading.Lock()
        self.next_call = 0.
        self.tokens_reserved = 0
        self.cost_reserved = 0.
        self.schema = json.loads((self.root/'schemas/api-review.schema.json').read_text())
        self.rubric = (self.root/'prompts/review/rubric_v1.txt').read_text()

    def authorize(self, mode):
        c = self.config
        if mode not in ('canary','full'): raise ApprovalRequired('Invalid review mode')
        if not c.get('enabled'): raise ApprovalRequired('API reviewer is disabled')
        missing = [x for x in REQUIRED if c.get(x) is None or c.get(x) == '']
        if missing: raise ApprovalRequired('Missing review settings: ' + ', '.join(missing))
        if not c.get('allow_external_candidate_text') or not c.get('allow_external_source_evidence'):
            raise ApprovalRequired('External candidate and minimal-evidence permissions are required')
        if not c.get('canary_approved'): raise ApprovalRequired('Canary approval is required after presenting the estimate')
        if mode=='canary':
            hashes=c.get('approved_canary_hashes')
            if not isinstance(hashes,list) or not hashes or len(set(hashes))!=len(hashes) or len(hashes)>int(c.get('canary_size',30)):
                raise ApprovalRequired('A bounded approved canary candidate-hash manifest is required')
        if mode == 'full' and not (c.get('full_review_approved') and c.get('manual_gold_approved') and c.get('canary_reliability_passed')):
            raise ApprovalRequired('Full review requires reliable canary, approved manual gold, and separate full approval')
        if c.get('max_tokens_total') is None and c.get('max_cost_usd') is None:
            raise ApprovalRequired('An explicit token or monetary budget is required')
        if c.get('max_cost_usd') is not None and (c.get('input_price_per_million_tokens') is None or c.get('output_price_per_million_tokens') is None):
            raise ApprovalRequired('Known pricing is required to enforce monetary budget')
        for k in ('requests_per_minute','max_concurrency','timeout_seconds'):
            if not isinstance(c[k],(float,int)) or c[k] <= 0: raise ApprovalRequired('Invalid configured rate/concurrency/timeout')
        if int(c['max_retries']) < 0: raise ApprovalRequired('Invalid retry count')
        if self.transport is None: raise ApprovalRequired('No approved provider transport has been connected')
        if not os.environ.get(c['api_key_env']): raise ApprovalRequired('Configured API-key environment variable is not set')

    def _reserve(self, payload):
        # UTF-8 byte count is a conservative text token bound; explicit margin for
        # protocol overhead. Unknown provider billing cannot be treated as exact.
        tokens = len(canonical_json(payload).encode()) + int(self.config.get('max_output_tokens_per_call',1000)) + 1024
        cost = 0.
        c = self.config
        if c.get('input_price_per_million_tokens') is not None and c.get('output_price_per_million_tokens') is not None:
            cost = (tokens * max(c['input_price_per_million_tokens'],c['output_price_per_million_tokens'])) / 1_000_000
        with self.lock:
            ledger = self.run/'budget.json'
            if ledger.exists():
                old=json.loads(ledger.read_text()); self.tokens_reserved=old['tokens_reserved']; self.cost_reserved=old['cost_reserved_usd']
            if c.get('max_tokens_total') is not None and self.tokens_reserved+tokens > c['max_tokens_total']: raise BudgetExceeded('Approved token budget would be exceeded')
            if c.get('max_cost_usd') is not None and self.cost_reserved+cost > c['max_cost_usd']: raise BudgetExceeded('Approved monetary budget would be exceeded')
            self.tokens_reserved+=tokens; self.cost_reserved+=cost
            atomic_json(ledger,{'tokens_reserved':self.tokens_reserved,'cost_reserved_usd':self.cost_reserved,'method':'conservative reservation before every attempted call; reservations never refunded on failures'})
            now=self.clock(); delay=max(0.,self.next_call-now)
            self.next_call=max(now,self.next_call)+60./c['requests_per_minute']
        if delay: self.sleep(delay)

    def review_one(self, candidate, evidence, mode='canary'):
        self.authorize(mode)
        if mode=='canary' and candidate_hash(candidate) not in self.config['approved_canary_hashes']:
            raise ApprovalRequired('Candidate is not in the approved canary manifest')
        from jsonschema import Draft202012Validator
        key=digest({'candidate_hash':candidate_hash(candidate),'evidence_hash':digest(evidence),'rubric_version':self.config['rubric_version'],'rubric_hash':digest(self.rubric),'model':self.config['model'],'provider':self.config['provider'],'protocol':self.config['protocol'],'endpoint_fingerprint':digest(self.config['base_url'])})
        target=self.run/'cache'/f'{key}.json'
        if target.exists():
            try:
                cached=json.loads(target.read_text())
                if (cached.get('candidate_hash') != candidate_hash(candidate) or cached.get('cache_key')!=key or cached.get('reviewer_model')!=self.config['model'] or cached.get('rubric_version')!=self.config['rubric_version']):
                    raise RuntimeError('Review cache identity mismatch')
                self._validate_response(cached.get('response'),candidate)
                expected={'accept':'accepted','revise':'revision_required','reject':'rejected'}[cached['response']['decision']]
                if cached.get('review_status')!=expected: raise RuntimeError('Review cache status mismatch')
                return cached
            except Exception as error:
                result={'candidate_hash':candidate_hash(candidate),'cache_key':key,'review_status':'quarantined','reason':'invalid_cached_api_response','error_type':type(error).__name__}
                atomic_json(self.run/'failures'/f'{key}.json',result)
                return result
        payload={'system_rubric':self.rubric,'untrusted_data':{'candidate':candidate,'minimum_source_evidence':evidence},'response_schema':self.schema,'max_output_tokens':self.config.get('max_output_tokens_per_call',1000)}
        last_error='missing_response'
        for attempt in range(1+int(self.config['max_retries'])):
            self._reserve(payload)
            try:
                response=self.transport(payload,os.environ[self.config['api_key_env']],float(self.config['timeout_seconds']),key)
                if isinstance(response,str): response=json.loads(response)
                self._validate_response(response,candidate)
                result={'candidate_hash':candidate_hash(candidate),'cache_key':key,'reviewer_model':self.config['model'],'rubric_version':self.config['rubric_version'],'response':response,'review_status':{'accept':'accepted','revise':'revision_required','reject':'rejected'}[response['decision']]}
                atomic_json(target,result)
                return result
            except Exception as exc:
                # Never log response bodies, headers, URLs, keys or exception text.
                last_error=type(exc).__name__
                if attempt < int(self.config['max_retries']): self.sleep(min(60.,2.**attempt))
        result={'candidate_hash':candidate_hash(candidate),'cache_key':key,'review_status':'quarantined','reason':'api_response_failed','error_type':last_error}
        atomic_json(self.run/'failures'/f'{key}.json',result)
        return result

    def _validate_response(self,response,candidate):
        from jsonschema import Draft202012Validator
        Draft202012Validator(self.schema).validate(response)
        if response['example_id'] != candidate['id']: raise ValueError('Wrong example id')
        if response['decision']=='accept' and (response['proposed_revision'] is not None or response['issue_codes'] or min(response['scores'].values())<3): raise ValueError('Inconsistent acceptance')
        if response['decision']=='revise' and not response['proposed_revision']: raise ValueError('Revision missing')
        if response['decision']=='reject' and response['proposed_revision'] is not None: raise ValueError('Reject cannot propose an approved revision')

    def review_batch(self, candidates, evidence_lookup, mode='canary'):
        self.authorize(mode)
        if mode=='canary':
            # Materialize at most the approved small canary, never the full corpus.
            import itertools
            selected=list(itertools.islice(candidates,int(self.config.get('canary_size',30))+1))
            hashes=[candidate_hash(x) for x in selected]
            if len(hashes)>int(self.config.get('canary_size',30)) or len(hashes)!=len(set(hashes)) or set(hashes)!=set(self.config['approved_canary_hashes']):
                raise ApprovalRequired('Canary batch differs from approved candidate hashes')
            candidates=selected
        # Bounded submission: avoids retaining the entire candidate dataset in RAM.
        counts=Counter()
        with ThreadPoolExecutor(max_workers=int(self.config['max_concurrency'])) as pool:
            batch=[]
            for item in candidates:
                batch.append(pool.submit(self.review_one,item,evidence_lookup(item),mode))
                if len(batch)>=int(self.config['max_concurrency']):
                    for f in batch: counts[f.result()['review_status']]+=1
                    batch=[]
            for f in batch: counts[f.result()['review_status']]+=1
        return dict(counts)

def gold_reliability(gold, reviews, minimum=0.90):
    expected={x['example_id']:x['decision'] for x in gold}
    observed={x['response']['example_id']:x['response']['decision'] for x in reviews if 'response' in x}
    matches=sum(observed.get(k)==v for k,v in expected.items())
    agreement=matches/len(expected) if expected else None
    return {'gold_count':len(expected),'reviewed_count':sum(k in observed for k in expected),'agreement':agreement,'passed':bool(expected) and len(expected)==sum(k in observed for k in expected) and agreement>=minimum,'manual_gold_approval_required':True}

def preserve_revision(original, proposed, output_dir, review_history):
    if proposed==original: raise ValueError('Revision must change candidate content')
    if isinstance(proposed,str):
        child=json.loads(canonical_json(original))
        if not proposed.strip() or child['messages'][-1].get('role')!='assistant': raise ValueError('Revision must replace the assistant answer')
        child['messages'][-1]['content']=proposed
    elif isinstance(proposed,dict):
        child=json.loads(canonical_json(proposed))
    else: raise ValueError('Unsupported revision type')
    child['metadata']['parent_example_id']=original['id']
    child['metadata']['review_status']='pending'
    child['metadata']['validation_status']='pending'
    child['id']=digest({'parent':candidate_hash(original),'revision':child})
    from .core import safe_output
    path=safe_output(Path(output_dir)/child['id'])
    if path.exists(): raise FileExistsError('Revision already exists; do not overwrite')
    path.mkdir(parents=True)
    atomic_json(path/'original.json',original)
    atomic_json(path/'revision.json',child)
    atomic_json(path/'review_history.json',review_history)
    return child

def prepare_canary(paths, output_dir, size=30, seed=1729):
    """Create a deterministic stratified proposal; this never grants approval."""
    from .core import safe_output
    if type(size) is not int or size<=0: raise ValueError('Canary size must be positive')
    output=safe_output(output_dir)
    output.mkdir(parents=True,exist_ok=True)
    pools={}; total=0
    for path in paths:
        for candidate in read_jsonl(path):
            total+=1
            meta=candidate['metadata']
            stratum=(meta['source_name'],meta.get('domain','unknown'),meta['task_type'])
            rank=digest({'seed':seed,'candidate_hash':candidate_hash(candidate)})
            pool=pools.setdefault(stratum,[])
            pool.append((rank,canonical_json(candidate)))
            pool.sort()
            del pool[size:]
    chosen=[]; selected_hashes=set(); round_number=0
    strata=sorted(pools)
    while len(chosen)<size:
        changed=False
        for stratum in strata:
            if len(chosen)>=size: break
            if round_number<len(pools[stratum]):
                candidate=json.loads(pools[stratum][round_number][1]); h=candidate_hash(candidate)
                if h not in selected_hashes:
                    chosen.append(candidate); selected_hashes.add(h); changed=True
        round_number+=1
        if not changed: break
    manifest={'input_candidates':total,'canary_candidates':len(chosen),'seed':seed,'candidate_hashes':sorted(selected_hashes),'candidate_ids':[x['id'] for x in chosen],'strata_total':len(strata),'strata_represented':len({(x['metadata']['source_name'],x['metadata'].get('domain','unknown'),x['metadata']['task_type']) for x in chosen}),'approved':False,'manual_gold_approved':False,'selection_method':'round-robin across source/domain/task strata; stable seeded hash ordering within strata'}
    files={'canary_proposal.jsonl':''.join(canonical_json(x)+'\n' for x in chosen),'manual_gold_pending.jsonl':''.join(canonical_json({'example_id':x['id'],'candidate_hash':candidate_hash(x),'decision':None,'manually_inspected':False})+'\n' for x in chosen),'manifest.json':json.dumps(manifest,ensure_ascii=False,indent=2)+'\n'}
    for name,text in files.items():
        target=safe_output(output/name)
        if target.exists():
            if target.read_text()!=text: raise ValueError('Canary proposal changed; use a new review attempt')
        else:
            # Exclusive creation avoids overwriting a proposal already reviewed.
            with target.open('x',encoding='utf-8') as f:
                f.write(text); f.flush(); os.fsync(f.fileno())
    return manifest
