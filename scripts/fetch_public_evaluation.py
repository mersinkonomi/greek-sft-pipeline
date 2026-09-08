#!/usr/bin/env python3
"""Download only public GreekMMLU, pin revision, fingerprint files; no credentials."""
import concurrent.futures, hashlib, json, os, sys, urllib.parse, urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'src'))
from greek_sft.core import atomic_json, atomic_text, sha256_file, safe_output
OUTPUT=ROOT/'runtime/evaluations/GreekMMLU'
REPO='dascim/GreekMMLU'
MAX_TOTAL=100*1024*1024

def get(url,limit):
    request=urllib.request.Request(url,headers={'User-Agent':'GreekSFT-ContaminationAudit/1.0'})
    with urllib.request.urlopen(request,timeout=60) as response:
        data=response.read(limit+1)
        if len(data)>limit: raise RuntimeError('Public evaluation exceeds approved download bound')
        return data

def main():
    safe_output(OUTPUT).mkdir(parents=True,exist_ok=True)
    for path in OUTPUT.rglob('*'):
        if path.is_symlink(): raise RuntimeError('Symlink evaluation output artifact')
    completed=OUTPUT/'manifest.json'
    if completed.exists():
        m=json.loads(completed.read_text())
        for item in m['files']:
            if sha256_file(OUTPUT/item['path'])!=item['sha256']: raise RuntimeError('Evaluation cache changed')
        print(json.dumps({'status':'cached','revision':m['revision'],'records':m['records']})); return
    metadata=json.loads(get('https://huggingface.co/api/datasets/'+REPO,8*1024*1024))
    revision=metadata['sha']
    paths=[x['rfilename'] for x in metadata['siblings'] if x['rfilename'].endswith('.parquet')]
    if not paths: raise RuntimeError('Public dataset has no Parquet assets; schema review required')
    if len(paths)>200: raise RuntimeError('Unexpected public evaluation asset count')
    atomic_json(OUTPUT/'upstream_metadata.json',{'repository':REPO,'revision':revision,'files':paths,'license_declaration':metadata.get('cardData',{}).get('license'),'source':'https://huggingface.co/datasets/'+REPO})
    def fetch(relative):
        if relative.startswith('/') or '..' in Path(relative).parts: raise RuntimeError('Unsafe remote filename')
        target=safe_output(OUTPUT/'downloads'/relative)
        if not target.exists():
            data=get('https://huggingface.co/datasets/'+REPO+'/resolve/'+revision+'/'+urllib.parse.quote(relative,safe='/'),MAX_TOTAL)
            target.parent.mkdir(parents=True,exist_ok=True)
            temporary=safe_output(target.with_name(target.name+'.partial'))
            with temporary.open('wb') as f: f.write(data); f.flush(); os.fsync(f.fileno())
            os.replace(temporary,target)
        return {'path':str(target.relative_to(OUTPUT)),'sha256':sha256_file(target),'bytes':target.stat().st_size}
    files=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for item in pool.map(fetch,sorted(paths)):
            files.append(item)
            if sum(x['bytes'] for x in files)>MAX_TOTAL: raise RuntimeError('Evaluation total exceeds download bound')
    import pyarrow.parquet as pq
    target=OUTPUT/'evaluation.jsonl'; temp=target.with_suffix('.jsonl.partial')
    count=0
    with temp.open('w',encoding='utf-8') as output:
        for item in files:
            for batch in pq.ParquetFile(OUTPUT/item['path']).iter_batches(batch_size=1000):
                for row in batch.to_pylist():
                    if not isinstance(row.get('question'),str) or not isinstance(row.get('choices'),list): raise RuntimeError('Unexpected GreekMMLU schema')
                    q={'evaluation_id':hashlib.sha256(json.dumps(row,sort_keys=True,ensure_ascii=False).encode()).hexdigest(),'question':row['question'],'choices':row['choices'],'subject':row.get('subject'),'split_file':item['path']}
                    output.write(json.dumps(q,ensure_ascii=False)+'\n'); count+=1
        output.flush(); os.fsync(output.fileno())
    os.replace(temp,target)
    files.append({'path':'evaluation.jsonl','sha256':sha256_file(target),'bytes':target.stat().st_size})
    atomic_json(completed,{'repository':REPO,'revision':revision,'source':'https://huggingface.co/datasets/'+REPO,'records':count,'files':files,'purpose':'contamination comparison only; never a training source','private_evaluation_scope':'unavailable'})
    print(json.dumps({'status':'downloaded_and_fingerprinted','revision':revision,'records':count,'files':len(paths),'bytes':sum(x['bytes'] for x in files)}))
if __name__=='__main__': main()
