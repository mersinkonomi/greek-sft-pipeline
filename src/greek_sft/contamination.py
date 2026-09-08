"""Read-only evaluation comparisons; original candidates remain immutable."""
from __future__ import annotations
import hashlib, json, re, unicodedata, os, uuid
from collections import Counter, defaultdict
from pathlib import Path
from .core import atomic_json, atomic_text, digest, read_jsonl, sha256_file, safe_output

def normalize(text):
    return ' '.join(re.findall(r'[^\W_]+',unicodedata.normalize('NFC',text).casefold(),re.UNICODE))
def shingles(text,n=5):
    words=text.split(); return {' '.join(words[i:i+n]) for i in range(max(0,len(words)-n+1))}

def check_contamination(candidate_path,root,output_dir,config):
    root, output_dir=Path(root).resolve(),safe_output(output_dir)
    if root not in output_dir.parents: raise ValueError('Contamination output outside pipeline')
    output_dir.mkdir(parents=True,exist_ok=True)
    ev=config.get('evaluation',{})
    requested=[]
    if ev.get('greekmmlu_path'): requested.append(('GreekMMLU',Path(ev['greekmmlu_path'])))
    requested.extend(('private',Path(p)) for p in ev.get('private_paths',[]))
    for existing in output_dir.rglob('*'):
        if existing.is_symlink(): raise ValueError('Symlink contamination artifact')
    questions={}; index=defaultdict(set); reports=[]; missing=[]
    exact_questions=defaultdict(set)
    for name,path in requested:
        if not path.is_absolute(): path=root/path
        if not path.is_file(): missing.append(name); continue
        count=0
        for item in read_jsonl(path):
            text=item.get('question',item.get('text'))
            if not isinstance(text,str) or not text.strip(): raise ValueError('Evaluation schema missing question/text')
            value=normalize(text); key=digest({'dataset':name,'id':item.get('evaluation_id',item.get('id',count)),'text':value})
            sh=shingles(value)
            questions[key]=(value,sh,name)
            exact_questions[value].add(key)
            for s in sh: index[s].add(key)
            count+=1
        reports.append({'name':name,'sha256':sha256_file(path),'records':count,'input_name':path.name})
    fingerprint=digest({'version':'contamination-1.1.0','candidate_sha256':sha256_file(candidate_path),'references':reports,'evaluation_config':ev})
    marker=safe_output(output_dir/'manifest.json')
    if marker.exists():
        manifest=json.loads(marker.read_text())
        if manifest['fingerprint']!=fingerprint: raise ValueError('Contamination resume input/config changed')
        for item in manifest['artifacts']:
            path=safe_output(output_dir/item['path'])
            if sha256_file(path)!=item['sha256']: raise ValueError('Contamination artifact changed')
        return json.loads((output_dir/'report.json').read_text())
    attempt=safe_output(output_dir/('attempt_'+uuid.uuid4().hex)); attempt.mkdir()
    counts=Counter(); by_source=Counter()
    clean_tmp=safe_output(attempt/'clean_candidates.jsonl'); bad_tmp=safe_output(attempt/'contaminated_candidates.jsonl')
    with clean_tmp.open('x',encoding='utf-8') as clean,bad_tmp.open('x',encoding='utf-8') as bad:
        for candidate in read_jsonl(candidate_path):
            counts['input']+=1
            span=candidate['metadata'].get('grounding_span')
            if span:
                if (not isinstance(span,dict) or span.get('message_index')!=1 or type(span.get('start')) is not int or type(span.get('end')) is not int or not 0<=span['start']<span['end']<=len(candidate['messages'][1]['content'])):
                    raise ValueError('Invalid candidate grounding span')
                body=candidate['messages'][span['message_index']]['content'][span['start']:span['end']]+'\n'+candidate['messages'][-1]['content']
            else: body='\n'.join(m['content'] for m in candidate['messages'] if m['role']!='system')
            normalized=normalize(body); candidate_shingles=shingles(normalized)
            overlaps=Counter(k for sh in candidate_shingles for k in index.get(sh,()))
            # Exact field fingerprints cover short questions without relying on
            # ambiguous short substring matches inside unrelated prose.
            exact_matches=set()
            for message in candidate['messages']:
                if message['role']!='system': exact_matches.update(exact_questions.get(normalize(message['content']),()))
            if span:
                exact_matches.update(exact_questions.get(normalize(candidate['messages'][span['message_index']]['content'][span['start']:span['end']]),()))
            short_matches={key for key,(question,_,_) in questions.items() if (len(question)<40 or len(question.split())<6) and (' '+question+' ') in (' '+normalized+' ')}
            exact_matches.update(short_matches)
            hits=[{'benchmark':questions[key][2],'question_fingerprint':key,'method':'short_exact_word_sequence_requires_manual_audit' if key in short_matches else 'exact_field_fingerprint','overlap':1.0} for key in sorted(exact_matches)]
            for key,overlap in overlaps.items():
                question,expected,name=questions[key]
                if len(question)>=40 and len(question.split())>=6 and (question in normalized or (len(expected)>=4 and overlap/len(expected)>=.80)):
                    hits.append({'benchmark':name,'question_fingerprint':key,'method':'normalized_exact_substring' if question in normalized else 'five_word_shingle_containment','overlap':overlap/len(expected)})
            if hits:
                counts['quarantined']+=1; by_source[candidate['metadata']['source_name']]+=1
                bad.write(json.dumps({'candidate':candidate,'status':'quarantined','reason':'benchmark_contamination','hits':hits},ensure_ascii=False)+'\n')
            else:
                counts['clean_against_available_evaluations']+=1
                clean.write(json.dumps(candidate,ensure_ascii=False)+'\n')

    report={'counts':dict(counts),'by_source':dict(by_source),'references':reports,'missing_datasets':missing,'private_scope_confirmed':bool(ev.get('coverage_confirmed_by_user')),'public_greekmmlu_checked':any(x['name']=='GreekMMLU' for x in reports),'complete':any(x['name']=='GreekMMLU' and x['records']>0 for x in reports) and all(x['records']>0 for x in reports) and not missing and bool(ev.get('coverage_confirmed_by_user')),'distinct_reference_records':len(questions),'distinct_normalized_questions':len(exact_questions),'method':'NFC+casefold word normalization; exact question substring or >=80% five-word-shingle containment; short generic questions excluded from lexical matching','limitations':['Lexical checks do not prove absence of semantic paraphrase contamination.','Private evaluation scope must be provided or explicitly confirmed empty.','Short exact word-sequence matches are conservatively quarantined and require manual false-positive audit.']}
    atomic_json(attempt/'report.json',report)
    artifacts=[]
    for source in (clean_tmp,bad_tmp,attempt/'report.json'):
        target=safe_output(output_dir/source.name)
        checksum=sha256_file(source)
        if target.exists():
            if sha256_file(target)!=checksum: raise ValueError('Incomplete contamination output conflicts; preserve and use a new run')
        else: os.link(source,target)
        artifacts.append({'path':source.name,'sha256':checksum})
    atomic_json(marker,{'fingerprint':fingerprint,'artifacts':artifacts})
    return report
