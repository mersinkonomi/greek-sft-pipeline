#!/usr/bin/env python3
"""Run six auditable passes, stopping after pass five until API approvals exist."""
from __future__ import annotations
import argparse, json, os, sys, traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def safe_directory(path):
    path=Path(path).absolute()
    if path.resolve()!=ROOT and ROOT not in path.resolve().parents:
        raise ValueError('Output directory escapes pipeline root')
    node=path
    while node!=node.parent:
        if node.is_symlink(): raise ValueError('Symlink output directory is forbidden')
        node=node.parent
    return path
for name,relative in {'TMPDIR':'runtime/tmp','XDG_CACHE_HOME':'runtime/cache','HF_HOME':'runtime/cache/huggingface','HF_DATASETS_CACHE':'runtime/cache/datasets','TRANSFORMERS_CACHE':'runtime/cache/transformers','MPLCONFIGDIR':'runtime/cache/matplotlib'}.items():
    target=safe_directory(ROOT/relative); target.mkdir(parents=True,exist_ok=True); os.environ[name]=str(target)
os.environ['PYTHONDONTWRITEBYTECODE']='1'
os.environ['HF_HUB_OFFLINE']='1'
os.environ['TOKENIZERS_PARALLELISM']='false'
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'src'))
import yaml
from greek_sft.core import atomic_json, atomic_text, checkpoint_complete, check_checkpoint, freeze_config, run_lock, validate_roots, utcnow, read_jsonl, capture_execution_attempt

CHECKPOINTS={1:'checkpoint_01_inventory',2:'checkpoint_02_source_plans',3:'checkpoint_03_raw_candidates',4:'checkpoint_04_validated_candidates',5:'checkpoint_05_dedup_splits'}

class Pass6ApprovalRequired(RuntimeError):
    pass

def json_safe(value):
    return json.loads(json.dumps(value,default=str))

def event(run,kind,**values):
    record={'time':utcnow(),'event':kind,**values}
    from greek_sft.core import safe_output
    with safe_output(run/'events.jsonl').open('a',encoding='utf-8') as f:
        f.write(json.dumps(record,ensure_ascii=False,default=str)+'\n'); f.flush(); os.fsync(f.fileno())
    print(json.dumps(record,ensure_ascii=False,default=str),flush=True)

def record_failure(run_id,error):
    """Keep failed state observable and preserve its predecessor for review."""
    if not run_id or Path(run_id).name!=run_id or run_id in ('.','..'):
        return
    run=safe_directory(ROOT/'runs'/run_id)
    if not run.is_dir():
        return
    from greek_sft.inventory import SourceChangedError
    import uuid
    with run_lock(run):
        state_path=safe_directory(run/'state.json')
        previous=json.loads(state_path.read_text()) if state_path.exists() else {'run_id':run_id,'passes':{}}
        failure=safe_directory(run/'execution_failures'/uuid.uuid4().hex)
        atomic_json(failure/'previous_state.json',previous)
        integrity=isinstance(error,SourceChangedError)
        state=dict(previous)
        previous_status=previous.get('status')
        retained_halt=previous_status if isinstance(previous_status,str) and previous_status.startswith('halted_') else 'failed'
        state.update(status='halted_source_integrity_failure' if integrity else retained_halt,
                     stopped_at=utcnow(),error_type=type(error).__name__,release_ready=False,
                     failure_artifact=str((failure/'failure.json').relative_to(run)))
        if integrity:
            state.update(source_immutable=False,scoped_source_integrity='failed',full_original_source_integrity=False)
        atomic_json(failure/'failure.json',state)
        from greek_sft.core import sha256_file
        atomic_json(failure/'checksums.json',{name:sha256_file(failure/name) for name in ('previous_state.json','failure.json')})
        atomic_json(state_path,state)

def safe_failure_reason(error,through):
    from greek_sft.inventory import SourceChangedError
    if isinstance(error,SourceChangedError):
        return 'source_integrity_failure'
    if isinstance(error,Pass6ApprovalRequired):
        return 'pass_6_approval_gate_not_satisfied'
    return 'pipeline_execution_failed'

def enforce_validation_gate(run,stats,config,state):
    entered=int(stats.get('candidates_entering',0))
    passed=int(stats.get('deterministic_content_checks_passed',0))
    maximum=float(config.get('validation',{}).get('maximum_processing_error_rate',.01))
    if entered and (entered-passed)/entered>maximum:
        state['status']='halted_excessive_deterministic_failure_rate'; atomic_json(run/'state.json',state)
        event(run,'required_user_clarification',reason='excessive_deterministic_validation_failure_rate',rate=(entered-passed)/entered)
        raise RuntimeError('Excessive deterministic validation failure rate; inspect checkpoint and obtain user decision')

def create_blocked_release(run, results, review_plan, verification):
    release=safe_directory(run/'release')
    if (release/'manifests/release_gates.json').exists(): return
    for sub in ('canonical','train','validation','test','quarantined','manifests','checksums','statistics'):
        safe_directory(release/sub).mkdir(parents=True,exist_ok=True)
    gates={
        'file_coverage':{'passed':False,'reason':'Requires independent reconciliation of manifest and source tree.'},
        'record_coverage':{'passed':False,'reason':'Unknown record boundaries in unsupported artifacts must be resolved or explicitly excluded by an approved scope policy.'},
        'canonical_schema':{'passed':False,'reason':'No final release records yet.'},
        'deterministic_validation':{'passed':False,'reason':'Final release set not established.'},
        'all_api_reviews_accepted':{'passed':False,'reason':'API review is disabled pending configuration, canary, reliability checks and full approval.'},
        'verified_licenses':{'passed':False,'reason':'No source-license evidence has received approval.'},
        'sensitive_data':{'passed':False,'reason':'Heuristics do not resolve all personal-data and safety risks.'},
        'exact_deduplication':{'passed':False,'reason':'Requires final release-set audit.'},
        'split_leakage':{'passed':False,'reason':'Requires final release-set audit.'},
        'benchmark_contamination':{'passed':False,'reason':'Public benchmark checks and private benchmark scope must be complete.'},
        'source_hashes_unchanged':{'passed':bool(verification.get('passed',verification.get('unchanged',False))) and results.get('1',{}).get('source_exclusion_amendment') is None,'scope':'original_source_tree','details':verification},
        'scoped_source_hashes_unchanged':{'passed':bool(verification.get('passed',verification.get('unchanged',False))),'scope':'approved_current_source_scope','details':verification},
        'counts_reconciled':{'passed':False,'reason':'Pending independent release audit.'},
        'release_auditor':{'passed':False,'reason':'Final independent audit not yet passed.'},
    }
    atomic_json(release/'manifests/release_gates.json',{'release_ready':False,'status':'blocked','gates':gates})
    atomic_json(release/'statistics/passes_01_to_05.json',results)
    atomic_json(release/'statistics/api_review_estimate.json',review_plan)
    atomic_json(release/'manifests/source_verification.json',verification)
    exclusion=results.get('1',{}).get('source_exclusion_amendment')
    if exclusion is not None:
        atomic_json(release/'manifests/source_exclusion_amendment_reference.json',exclusion)
    atomic_json(release/'manifests/checkpoint_references.json',{'checkpoints':{str(k):'../../'+v+'/checkpoint_manifest.json' for k,v in CHECKPOINTS.items()}})
    text={
      'dataset_card.md':'# Greek SFT build — blocked, not released\n\nThis directory contains audit reports, not an approved training dataset. Internal raw candidates are separate from validated and API-accepted examples. No examples have been authorized for release. After every technical gate passes, the result may be called a **release-grade Greek SFT candidate**; final human and legal approval remains required.\n',
      'provenance_report.md':'# Provenance\n\nEvery inventoried file is represented in checkpoint_01_inventory/source_manifest.jsonl. Its SQLite record ranges account for physical JSONL rows without storing source text. Checkpoint 03 contains stable IDs, record hashes, source-relative file references and per-file generation dispositions. Binary/unsupported records remain explicitly unresolved; counts must not be described as full semantic record coverage.\n',
      'license_report.md':'# License status\n\nProcessing authorization does not establish training or redistribution rights. Catalog notes and record-level license strings are declarations requiring verification. No unknown/incompatible license can pass release validation. Source-specific policies and reasons are in checkpoint_02_source_plans. No legal certification is implied.\n',
      'quality_report.md':'# Quality status\n\nDeterministic structural and grounding checks are distinct from Greek grammar, naturalness, and semantic quality assessment. Language and PII patterns are heuristics. Review statistics are pending; no LLM review alone certifies quality. See statistics/passes_01_to_05.json for actual counts and limitations.\n',
      'contamination_report.md':'# Contamination status\n\nSee checkpoint_04_validated_candidates/contamination_report.json for actual public benchmark comparison and fingerprints when present. Missing private evaluation data/scope prevents a complete contamination claim. Source-document grouping and duplicate joins are checked during Pass 5; final release must be independently rechecked.\n',
      'reproduction_instructions.md':f'# Reproduction\n\nRun `python3 -B scripts/run_pipeline.py --run-id {run.name} --through 5` from PIPELINE_ROOT to resume the existing run. Configuration changes require a new run. Each checkpoint includes configuration and source-code snapshots, statistics, errors and SHA-256 artifacts. Random seed: 1729. Source files are read-only inputs and must never be edited. Pass 6 needs separately approved API configuration and external-data permissions.\n',
    }
    if exclusion is not None:
        text['provenance_report.md'] += '\nThe user authorized excluding ' + ', '.join(exclusion['amendment']['excluded_source_roots']) + ' from current source coverage. The amendment reference retains any predecessor authorization and incident. Historical inventory entries and the original integrity failure remain preserved. Current contents and file counts inside that directory are unassessed. Verification success applies only to the approved source scope; full-original-tree immutability is false. The checksummed authorization and incident reference are in `manifests/source_exclusion_amendment_reference.json`.\n'
    for name,body in text.items(): atomic_text(release/name,body)
    from greek_sft.core import sha256_file
    sums=[]
    for path in sorted(release.rglob('*')):
        if path.is_file() and path.name!='SHA256SUMS': sums.append(sha256_file(path)+'  '+str(path.relative_to(release)))
    atomic_text(release/'checksums/SHA256SUMS','\n'.join(sums)+'\n')

def run_pipeline(args):
    config=yaml.safe_load((ROOT/'configs/pipeline.yaml').read_text())
    source,root=validate_roots(config['source_root'],config['pipeline_root'])
    if root != ROOT: raise RuntimeError('Configured pipeline root differs from executable root')
    if args.run_id:
        if Path(args.run_id).name!=args.run_id or args.run_id in ('.','..'): raise ValueError('Invalid run ID')
        run=safe_directory(root/'runs'/args.run_id)
        if not run.is_dir(): raise ValueError('Run directory does not exist; use --new-run')
    else:
        import datetime,uuid
        name=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:8]
        run=safe_directory(root/'runs'/name); run.mkdir()
    if root not in run.resolve().parents: raise ValueError('Run symlink escapes output root')
    args._active_run_id=run.name
    with run_lock(run):
        freeze_config(root,run,config)
        from greek_sft.inventory import validate_inventory_scope
        scope=validate_inventory_scope(run/CHECKPOINTS[1],config)
        if scope is not None:
            event(run,'inventory_scope_authorization_verified',sha256=scope['sha256'])
        from greek_sft.source_scope import validate_source_exclusion, historical_source_exclusion
        exclusion=validate_source_exclusion(run/CHECKPOINTS[1],config)
        if exclusion is not None:
            event(run,'source_exclusion_authorization_verified',sha256=exclusion['sha256'],
                  excluded_source_roots=exclusion['amendment']['excluded_source_roots'])
        attempt=capture_execution_attempt(root,run)
        event(run,'execution_snapshot_created',path=attempt)
        reconciliation = None
        if exclusion is not None and historical_source_exclusion(exclusion) != exclusion:
            from greek_sft.scope_reconciliation import prepare_scope_reconciliation, validate_scope_reconciliation
            previous_state = json.loads((run/'state.json').read_text()) if (run/'state.json').exists() else {}
            previous_reference = previous_state.get('scope_reconciliation')
            reconciliation = (validate_scope_reconciliation(run, config, previous_reference)
                if previous_reference is not None else prepare_scope_reconciliation(run, config))
            exclusion = validate_source_exclusion(run/CHECKPOINTS[1], config)
            event(run, 'historical_checkpoints_scope_reconciled', reference=reconciliation['reference'])
        results={}
        if reconciliation is not None:
            results['scope_reconciliation'] = reconciliation['reference']
        state={'run_id':run.name,'status':'running','started_at':utcnow(),'source_immutable':exclusion is None,'passes':{}}
        if exclusion is not None:
            incident_chain = []
            reference = exclusion
            while reference is not None:
                incident_chain.append(reference['amendment']['integrity_incident_path'])
                reference = reference.get('predecessor')
            state.update(source_integrity_scope='approved_source_scope',
                         excluded_source_roots=exclusion['amendment']['excluded_source_roots'],
                         scoped_source_integrity='pending',full_original_source_integrity=False,
                         source_exclusion_amendment_sha256=exclusion['sha256'],
                         original_integrity_incident=incident_chain[-1],
                         effective_integrity_incident=incident_chain[0],
                         integrity_incident_chain=incident_chain)
        if reconciliation is not None:
            state['scope_reconciliation'] = reconciliation['reference']
        for number in range(1,min(args.through,5)+1):
            checkpoint=safe_directory(run/CHECKPOINTS[number])
            if check_checkpoint(checkpoint,config):
                results[str(number)]=json.loads((checkpoint/'statistics.json').read_text())
                event(run,'checkpoint_resumed',pass_number=number)
                state['passes'][str(number)]='complete'
                if number==1:
                    from greek_sft.audit import audit_inventory
                    audit_inventory(checkpoint,run/'audits/inventory')
                    if reconciliation is not None:
                        results['1'] = reconciliation['statistics']
                if number==4: enforce_validation_gate(run,results[str(number)],config,state)
                if number==5:
                    from greek_sft.integrity import verify_source_hashes
                    import uuid
                    fresh_dir=safe_directory(run/'source_verifications'/('resume_'+uuid.uuid4().hex))
                    event(run,'fresh_resume_source_reverification_started')
                    results[str(number)]['source_verification']=verify_source_hashes(source,run/CHECKPOINTS[1],fresh_dir,config)
                continue
            checkpoint.mkdir(parents=True,exist_ok=True)
            state['active_pass']=number; atomic_json(run/'state.json',state)
            event(run,'pass_started',pass_number=number,checkpoint=CHECKPOINTS[number])
            if number==1:
                from greek_sft.inventory import run_inventory
                stats=run_inventory(source,checkpoint,config)
            elif number==2:
                from greek_sft.tasks import run_plans
                stats=run_plans(source,run/CHECKPOINTS[1],checkpoint,config)
            elif number==3:
                from greek_sft.tasks import run_generation
                stats=run_generation(source,run/CHECKPOINTS[1],run/CHECKPOINTS[2],checkpoint,config)
            elif number==4:
                from greek_sft.tasks import run_validation
                stats=run_validation(run/CHECKPOINTS[3],checkpoint,config)
                from greek_sft.contamination import check_contamination
                contamination=check_contamination(checkpoint/'validated.jsonl',root,checkpoint/'contamination',config)
                atomic_json(checkpoint/'contamination_report.json',contamination)
                stats['contamination']=contamination
            else:
                from greek_sft.dedup import run_dedup
                stats=run_dedup([run/CHECKPOINTS[4]/'contamination'/'clean_candidates.jsonl'],checkpoint,config)
                from greek_sft.integrity import verify_source_hashes
                event(run,'source_reverification_started')
                verification=verify_source_hashes(source,run/CHECKPOINTS[1],checkpoint/'source_verification',config)
                stats['source_verification']=verification
                if not verification.get('passed',verification.get('unchanged',False)):
                    raise RuntimeError('Source hash verification did not pass; STOP and investigate')
            stats=json_safe(stats)
            checkpoint_complete(root,checkpoint,stats,config)
            if number==1:
                from greek_sft.audit import audit_inventory
                audit_inventory(checkpoint,run/'audits/inventory')
            if number==4: enforce_validation_gate(run,stats,config,state)
            results[str(number)]=stats; state['passes'][str(number)]='complete'
            event(run,'pass_completed',pass_number=number,statistics=stats)
        if args.through>=5:
            from greek_sft.review import estimate_review, prepare_canary
            paths=sorted((run/CHECKPOINTS[5]/'completed/pre_api').glob('*/canonical.jsonl'))
            reviewer=yaml.safe_load((root/'configs/reviewer.yaml').read_text())
            review_plan=estimate_review(paths,reviewer)
            atomic_json(run/'api_review_plan.json',review_plan)
            verification=results.get('5',{}).get('source_verification',{})
            state['scoped_source_integrity']='verified' if verification.get('passed') is True else 'failed'
            create_blocked_release(run,results,review_plan,verification)
            from greek_sft.reporting import create_audited_release
            inventory_audit=(reconciliation['audit'] if reconciliation is not None else
                json.loads((run/'audits/inventory/inventory_reconciliation.json').read_text()))
            audited=create_audited_release(run,results,review_plan,verification,inventory_audit)
            atomic_json(run/'release/LATEST_AUDIT.json',audited)
            event(run,'independent_accounting_completed',audit=audited)
            if not audited.get('accounting_passed'): raise RuntimeError('Independent accounting audit failed; release blocked')
            canary=prepare_canary(paths,run/'review/preparation',int(reviewer.get('canary_size',30)),int(config.get('seed',1729)))
            atomic_json(run/'canary_preparation.json',canary)
            state['status']='awaiting_api_configuration_and_release_blockers'
            state['candidates_awaiting_api_review']=review_plan['candidates']
        else: state['status']='stopped_at_requested_checkpoint'
        atomic_json(run/'state.json',state)
        if args.through==6:
            raise Pass6ApprovalRequired('Pass 6 is locked: configure and approve API, estimate, canary/manual gold and separate full review first')
        event(run,'requested_passes_completed',status=state['status'],run_id=run.name)
    return run

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--run-id'); group.add_argument('--new-run',action='store_true')
    parser.add_argument('--through',type=int,choices=range(1,7),default=5)
    args=parser.parse_args(argv)
    try: run_pipeline(args)
    except Exception as error:
        # No API credentials or response bodies in logs; source processing errors
        # are recorded by their stages with bounded sanitized reason codes.
        try:
            record_failure(getattr(args,'_active_run_id',args.run_id),error)
        except Exception as state_error:
            print(json.dumps({'event':'failure_state_write_failed','error_type':type(state_error).__name__}),file=sys.stderr,flush=True)
        print(json.dumps({'status':'failed','error_type':type(error).__name__,'reason':safe_failure_reason(error,args.through)}),file=sys.stderr,flush=True)
        return 1
    return 0

if __name__=='__main__':
    raise SystemExit(main())
