#!/usr/bin/env python3
"""Read-only status of a resumable run; never accesses source text."""
import argparse,json,sqlite3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(); p.add_argument('--run-id',required=True); p.add_argument('--compact',action='store_true'); args=p.parse_args()
if Path(args.run_id).name!=args.run_id or args.run_id in ('.','..'): raise SystemExit('Invalid run ID')
run=(ROOT/'runs'/args.run_id).resolve()
if ROOT not in run.parents: raise SystemExit('Unsafe run path')
result={'run_id':args.run_id}
for name in ('state.json','api_review_plan.json'):
    path=run/name
    if path.exists(): result[name]=json.loads(path.read_text())
checkpoint=run/'checkpoint_01_inventory'
workers=[]; total=0
for path in sorted(checkpoint.glob('inventory_shard_*.sqlite')):
    try:
        db=sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True,timeout=1)
        files=db.execute('SELECT COUNT(*) FROM files WHERE completed=1').fetchone()[0]
        db.close(); total+=files; workers.append({'shard':path.name,'completed_files':files})
    except sqlite3.Error: workers.append({'shard':path.name,'status':'initializing_or_busy'})
result['inventory']={'durably_completed_files':total,'shards':workers}
for path in sorted(checkpoint.glob('*progress*.json'))+sorted(checkpoint.glob('*heartbeat*.json')):
    try: result['inventory'][path.name]=json.loads(path.read_text())
    except (OSError,ValueError): pass
if args.compact:
    state=result.get('state.json',{})
    heartbeats=[v for k,v in result['inventory'].items() if k.endswith('_heartbeat.json')]
    result={'run_id':args.run_id,'status':state.get('status'),'active_pass':state.get('active_pass'),'completed_files':total,'heartbeats':[{'at':h.get('at'),'phase':h.get('phase'),'source_family':h.get('relative_path','').split('/')[0],'current_file_bytes_hashed':h.get('raw_bytes_hashed_current_file'),'current_file_records':h.get('records_seen_current_file')} for h in heartbeats]}
print(json.dumps(result,ensure_ascii=False,indent=None if args.compact else 2))
