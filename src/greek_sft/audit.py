"""Independent read-only reconciliation of inventory artifacts.

Only new audit artifacts are written; source inputs and checkpoints are immutable.
"""
from __future__ import annotations
import contextlib, heapq, json, re, sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from .core import STATUSES, atomic_json, read_jsonl, safe_output, sha256_file, utcnow
from .source_scope import validate_source_exclusion, is_source_excluded, validate_source_exclusion_binding, historical_source_exclusion, source_exclusion_artifact_paths

class AuditFailure(RuntimeError):
    pass

def _nonzero(mapping):
    return {k:v for k,v in mapping.items() if v}

def audit_inventory(checkpoint, output_dir, config=None):
    checkpoint=safe_output(checkpoint)
    if config is None:
        config_path=checkpoint.parent/'configuration.json'
        config=json.loads(config_path.read_text()) if config_path.exists() else {}
    effective_exclusion=validate_source_exclusion(checkpoint,config,freeze=False)
    source_exclusion=historical_source_exclusion(effective_exclusion)
    if effective_exclusion is not None and not effective_exclusion['frozen']:
        raise AuditFailure('source_exclusion_not_frozen')
    output=safe_output(output_dir)
    if checkpoint.resolve()==output or checkpoint.resolve() in output.parents:
        raise AuditFailure('audit_output_must_be_outside_immutable_checkpoint')
    output.mkdir(parents=True,exist_ok=True)
    manifest=checkpoint/'source_manifest.jsonl'
    summary=json.loads((checkpoint/'statistics.json').read_text())
    declared=json.loads((checkpoint/'manifest.json').read_text())
    shards=sorted(checkpoint.glob('inventory_shard_*.sqlite'))
    identity={'summary_sha256':sha256_file(checkpoint/'statistics.json'),'completion_sha256':sha256_file(checkpoint/'manifest.json'),'manifest_sha256':sha256_file(manifest),'shards':{p.name:sha256_file(p) for p in shards},'wal_inputs':{p.name:sha256_file(p) for shard in shards for p in [Path(str(shard)+'-wal')] if p.exists() and p.stat().st_size},'audit_version':'inventory-accounting-2.1','source_exclusion_amendment_sha256':source_exclusion['sha256'] if source_exclusion else None}
    if source_exclusion:
        references = {}
        reference = source_exclusion
        while reference is not None:
            for path in source_exclusion_artifact_paths(checkpoint, reference).values():
                references[str(path.relative_to(checkpoint.parent))] = sha256_file(path)
            reference = reference.get('predecessor')
        identity['source_exclusion_evidence_sha256'] = references
    if not declared.get('complete') or len(shards)!=summary['workers'] or identity['manifest_sha256']!=declared['source_manifest_sha256']:
        raise AuditFailure('inventory_artifact_identity_mismatch')
    target=safe_output(output/'inventory_reconciliation.json')
    if target.exists():
        prior=json.loads(target.read_text())
        if prior.get('input_identity')!=identity: raise AuditFailure('audit_inputs_changed')
        if not prior.get('identified_accounting_passed'): raise AuditFailure('prior_inventory_accounting_failed')
        from .source_duplicates import audit_source_file_duplicates
        duplicates=audit_source_file_duplicates(manifest,output/'source_file_duplicates')
        if duplicates!=prior.get('source_file_duplicates'): raise AuditFailure('duplicate_audit_changed')
        return prior
    if summary.get('source_exclusion_amendment') != source_exclusion:
        raise AuditFailure('inventory_source_exclusion_reference_mismatch')
    errors=[]; totals=Counter(); statuses=Counter(); reasons=Counter(); families=defaultdict(Counter)
    def fail(code, relative=None):
        totals['accounting_errors']+=1
        if len(errors)<100: errors.append({'code':code,'source_file':relative})
    with contextlib.ExitStack() as stack:
        dbs=[stack.enter_context(contextlib.closing(sqlite3.connect('file:'+str(p.resolve())+'?mode=ro',uri=True))) for p in shards]
        for db in dbs:
            if db.execute('SELECT COUNT(*) FROM files WHERE completed!=1').fetchone()[0]: fail('incomplete_files_in_completed_inventory')
        file_rows=heapq.merge(*(db.execute('SELECT relative_path,report FROM files WHERE completed=1 ORDER BY relative_path') for db in dbs))
        range_rows=iter(heapq.merge(*(db.execute('SELECT relative_path,first_record,last_record,status,reason,row_hash_chain FROM record_ranges ORDER BY relative_path,first_record') for db in dbs)))
        stack.callback(file_rows.close)
        stack.callback(range_rows.close)
        current_range=next(range_rows,None)
        previous=None
        for item in read_jsonl(manifest):
            relative=item['relative_path']; totals['files']+=1
            validate_source_exclusion_binding(item,source_exclusion)
            if relative.startswith('/') or '..' in Path(relative).parts: fail('unsafe_source_reference',relative)
            if previous is not None and relative<=previous: fail('manifest_not_unique_sorted',relative)
            previous=relative
            db_item=next(file_rows,None)
            if db_item is None or db_item[0]!=relative or json.loads(db_item[1])!=item: fail('manifest_database_disagreement',relative)
            if item['status'] not in STATUSES: fail('unknown_file_status',relative)
            if not re.fullmatch('[0-9a-f]{64}',item['sha256']): fail('invalid_file_hash',relative)
            count=item['record_count']
            if type(count) is not int or count<0: fail('invalid_record_count',relative); count=0
            totals['records']+=count; totals['bytes']+=item['size_bytes']
            if source_exclusion:
                prefix='historical_excluded_' if is_source_excluded(relative,source_exclusion) else 'in_scope_'
                totals[prefix+'files']+=1; totals[prefix+'bytes']+=item['size_bytes']; totals[prefix+'identified_records']+=count
                totals[prefix+'unresolved_boundary_files']+=not item['record_boundary_complete']
            totals['file_status_'+item['status']]+=1
            totals['unresolved_boundary_files']+=not item['record_boundary_complete']
            family=families[item['family']]
            family.update(files=1,records=count,bytes=item['size_bytes'])
            family['file_status_'+item['status']]+=1
            family['unresolved_boundary_files']+=not item['record_boundary_complete']
            local_status=Counter(); local_reason=Counter(); next_record=1
            while current_range is not None and current_range[0]<relative:
                fail('orphan_record_range',current_range[0]); current_range=next(range_rows,None)
            while current_range is not None and current_range[0]==relative:
                _,first,last,status,reason,chain=current_range
                if first!=next_record or last<first: fail('noncontiguous_or_overlapping_range',relative)
                length=max(0,last-first+1)
                if status not in STATUSES: fail('unknown_record_status',relative)
                if not reason or not re.fullmatch('[0-9a-f]{64}',chain): fail('invalid_range_reason_or_commitment',relative)
                local_status[status]+=length; local_reason[reason]+=length
                next_record=last+1; totals['record_ranges']+=1
                current_range=next(range_rows,None)
            if next_record-1!=count or sum(local_status.values())!=count: fail('record_range_count_mismatch',relative)
            expected_status={k[7:]:v for k,v in item['stats'].items() if k.startswith('status_')}
            expected_reason={k[7:]:v for k,v in item['stats'].items() if k.startswith('reason_')}
            if _nonzero(local_status)!=_nonzero(expected_status): fail('record_status_count_mismatch',relative)
            if _nonzero(local_reason)!=_nonzero(expected_reason): fail('record_reason_count_mismatch',relative)
            statuses.update(local_status); reasons.update(local_reason)
            family.update({'record_status_'+k:v for k,v in local_status.items()})
        if next(file_rows,None) is not None: fail('extra_database_files')
        if current_range is not None: fail('extra_database_record_ranges',current_range[0])
    if source_exclusion:
        for prefix in ('historical_excluded_','in_scope_'):
            for metric in ('files','bytes','identified_records'):
                key=prefix+metric
                if totals[key]!=summary['statistics'].get(key,0): fail('inventory_scoped_summary_mismatch',key)
        ledger=summary.get('source_exclusion_accounting',{})
        if (ledger.get('current_excluded_coverage')!='unknown' or ledger.get('full_original_source_integrity') is not False
                or ledger.get('historical_baselines_preserved') is not True
                or any(ledger.get(key,'missing') is not None for key in ('current_excluded_files','current_excluded_bytes','current_excluded_records'))):
            fail('inventory_source_exclusion_coverage_claim_invalid')
        for metric in ('files','bytes','identified_records'):
            key='historical_excluded_'+metric
            if ledger.get('counts',{}).get(key,0)!=totals[key]: fail('inventory_excluded_ledger_count_mismatch',key)
        references=ledger.get('artifacts',{})
        if set(references)!={'files.jsonl','record_ranges.jsonl','checksums.json'}:
            fail('inventory_excluded_ledger_artifacts_missing')
        else:
            paths={}
            for name,relative in references.items():
                if not isinstance(relative,str) or Path(relative).is_absolute() or '..' in Path(relative).parts:
                    raise AuditFailure('unsafe_inventory_excluded_ledger_path')
                path=safe_output(checkpoint/relative)
                if checkpoint.resolve() not in path.parents: raise AuditFailure('unsafe_inventory_excluded_ledger_path')
                paths[name]=path
            if sha256_file(paths['checksums.json'])!=ledger.get('checksums_sha256'):
                fail('inventory_excluded_ledger_checksum_manifest_changed')
            checksums=json.loads(paths['checksums.json'].read_text())
            if (checksums.get('source_exclusion_amendment_sha256')!=source_exclusion['sha256']
                    or checksums.get('source_manifest_sha256')!=identity['manifest_sha256']
                    or checksums.get('counts')!=ledger.get('counts')):
                fail('inventory_excluded_ledger_identity_mismatch')
            for name in ('files.jsonl','record_ranges.jsonl'):
                if checksums.get('artifacts',{}).get(name)!={'sha256':sha256_file(paths[name]),'size_bytes':paths[name].stat().st_size}:
                    fail('inventory_excluded_ledger_artifact_changed',name)
        if validate_source_exclusion(checkpoint,config,freeze=False)!=effective_exclusion:
            raise AuditFailure('source_exclusion_changed_during_inventory_audit')
    declared_totals=summary['statistics']
    for key in ('files','records','bytes'):
        if totals[key]!=declared_totals.get(key,0): fail('inventory_summary_'+key+'_mismatch')
    if totals['unresolved_boundary_files']!=declared_totals.get('files_with_unresolved_record_boundaries',0): fail('inventory_boundary_summary_mismatch')
    for status in STATUSES:
        if totals['file_status_'+status]!=declared_totals.get('file_status_'+status,0): fail('inventory_file_status_summary_mismatch')
        if statuses[status]!=declared_totals.get('status_'+status,0): fail('inventory_status_summary_mismatch')
    declared_reasons={k[7:]:v for k,v in declared_totals.items() if k.startswith('reason_')}
    if _nonzero(reasons)!=_nonzero(declared_reasons): fail('inventory_reason_summary_mismatch')
    if set(families)!=set(summary['families']): fail('inventory_family_set_mismatch')
    for family,counts in families.items():
        expected=summary['families'].get(family,{})
        for key,value in counts.items():
            if key=='unresolved_boundary_files': continue
            expected_key=key.replace('record_status_','status_',1)
            if value!=expected.get(expected_key,0): fail('inventory_family_summary_mismatch',family)
        for key,value in expected.items():
            if key.startswith('file_status_') or key.startswith('status_'):
                actual_key=('record_'+key) if key.startswith('status_') else key
                if value!=counts.get(actual_key,0): fail('inventory_family_status_summary_mismatch',family)
    report={'input_identity':identity,'created_at':utcnow(),'identified_accounting_passed':not totals['accounting_errors'],
        'complete_semantic_record_coverage':not totals['accounting_errors'] and not totals['unresolved_boundary_files'] and source_exclusion is None,
        'source_exclusion_amendment':source_exclusion,
        'source_exclusion_accounting':summary.get('source_exclusion_accounting'),
        'full_original_source_coverage':not totals['accounting_errors'] and source_exclusion is None,
        'full_original_source_integrity':False,
        'current_excluded_coverage':'unknown' if source_exclusion else 'not_applicable',
        'totals':dict(totals),'record_status_counts':dict(statuses),'record_reason_counts':dict(reasons),
        'by_source':{k:dict(v) for k,v in sorted(families.items())},'errors':errors,
        'limitations':['Opaque or unsupported record boundaries remain unresolved.',
            'Range commitments are structurally validated; this audit does not recompute individual source row hashes.',
            'Final in-scope source file set and raw-byte integrity require a separate complete source verification.'] + (['The authorized source roots ' + ', '.join(source_exclusion['amendment']['excluded_source_roots']) + ' are excluded from current coverage. Its historical files and ranges remain accounted for; current excluded counts and bytes are unknown, and full-original coverage/integrity are not established.'] if source_exclusion else [])}
    if not totals['accounting_errors']:
        from .source_duplicates import audit_source_file_duplicates
        report['source_file_duplicates']=audit_source_file_duplicates(manifest,output/'source_file_duplicates')
        report['source_file_duplicate_artifacts_base_relative_to_run']=str((output/'source_file_duplicates').relative_to(checkpoint.parent.resolve()))
    atomic_json(target,report)
    if totals['accounting_errors']: raise AuditFailure('inventory_accounting_failed_see_audit_artifact')
    return report


def reconcile_inventory_scope(checkpoint, output_dir, config, historical_audit):
    """Derive effective partitions without changing the completed historical inventory."""
    from .inventory import _write_source_exclusion_ledger
    checkpoint = Path(checkpoint).resolve(strict=True)
    output = safe_output(output_dir)
    if checkpoint == output or checkpoint in output.parents or checkpoint.parent not in output.parents:
        raise AuditFailure('scope_view_output_must_be_outside_checkpoint_inside_run')
    if output.exists() and any(output.iterdir()):
        raise AuditFailure('scope_view_output_already_exists_or_interrupted')
    effective = validate_source_exclusion(checkpoint, config, freeze=False)
    historical = historical_source_exclusion(effective)
    if not effective or not effective['frozen'] or historical == effective:
        raise AuditFailure('scope_view_requires_frozen_scope_extension')
    if isinstance(historical_audit, (str, Path)):
        historical_path = Path(historical_audit).resolve(strict=True)
        supplied = json.loads(historical_path.read_text())
    else:
        historical_path = checkpoint.parent / 'audits/inventory/inventory_reconciliation.json'
        supplied = historical_audit
    # This validates the complete effective authorization chain, then the historical
    # audit cache's manifest, shards, ledger, duplicate audit and historical identity.
    verified = audit_inventory(checkpoint, historical_path.parent, config)
    if verified != supplied or json.loads(historical_path.read_text()) != verified:
        raise AuditFailure('historical_inventory_audit_binding_mismatch')
    if not verified.get('identified_accounting_passed') or verified.get('source_exclusion_amendment') != historical:
        raise AuditFailure('historical_inventory_audit_not_verified')
    historical_audit_sha = sha256_file(historical_path)
    summary = json.loads((checkpoint / 'statistics.json').read_text())
    completion = json.loads((checkpoint / 'manifest.json').read_text())
    if not completion.get('complete') or summary.get('source_exclusion_amendment') != historical:
        raise AuditFailure('historical_inventory_completion_scope_mismatch')
    identity = verified['input_identity']
    import hashlib
    partitions = Counter({prefix + metric: 0 for prefix in ('historical_excluded_', 'in_scope_')
                          for metric in ('files', 'bytes', 'identified_records', 'unresolved_boundary_files')})
    totals = Counter()
    manifest_digest = hashlib.sha256()
    previous = None
    with (checkpoint / 'source_manifest.jsonl').open('rb') as stream:
        for line in stream:
            manifest_digest.update(line)
            item = json.loads(line)
            relative = item['relative_path']
            if previous is not None and relative <= previous:
                raise AuditFailure('scope_view_manifest_not_unique_sorted')
            previous = relative
            validate_source_exclusion_binding(item, historical)
            prefix = 'historical_excluded_' if is_source_excluded(relative, effective) else 'in_scope_'
            for metric, value in (('files', 1), ('bytes', item['size_bytes']),
                                  ('identified_records', item['record_count']),
                                  ('unresolved_boundary_files', int(not item['record_boundary_complete']))):
                partitions[prefix + metric] += value
                totals[metric] += value
    if manifest_digest.hexdigest() != identity['manifest_sha256'] or identity['manifest_sha256'] != completion['source_manifest_sha256']:
        raise AuditFailure('scope_view_historical_manifest_changed')
    for metric, original in (('files', 'files'), ('bytes', 'bytes'), ('identified_records', 'records'),
                             ('unresolved_boundary_files', 'files_with_unresolved_record_boundaries')):
        if totals[metric] != summary['statistics'].get(original, 0):
            raise AuditFailure('scope_view_original_totals_changed')
    output.mkdir(parents=True, exist_ok=True)
    ledger = _write_source_exclusion_ledger(checkpoint, summary['workers'], effective,
                                           identity['manifest_sha256'], ledger_checkpoint=output)
    for metric in ('files', 'bytes', 'identified_records'):
        if ledger['counts']['historical_excluded_' + metric] != partitions['historical_excluded_' + metric]:
            raise AuditFailure('scope_view_ledger_partition_mismatch')
    ledger.update(current_excluded_coverage='unknown', current_excluded_files=None,
                  current_excluded_bytes=None, current_excluded_records=None,
                  full_original_source_integrity=False, historical_baselines_preserved=True)
    evidence = {}
    reference = effective
    while reference is not None:
        for path in source_exclusion_artifact_paths(checkpoint, reference).values():
            evidence[str(path.relative_to(checkpoint.parent))] = sha256_file(path)
        reference = reference.get('predecessor')
    provenance = {'historical_source_exclusion_amendment_sha256': historical['sha256'] if historical else None,
                  'effective_source_exclusion_amendment_sha256': effective['sha256'],
                  'historical_inventory_audit_path': str(historical_path.relative_to(checkpoint.parent)),
                  'historical_inventory_audit_sha256': historical_audit_sha,
                  'historical_input_identity': identity,
                  'effective_source_exclusion_evidence_sha256': evidence,
                  'historical_baselines_preserved': True,
                  'artifacts_base_relative_to_run': str(output.relative_to(checkpoint.parent))}
    statistics = {**summary, 'statistics': {**summary['statistics'], **dict(partitions)},
                  'source_exclusion_amendment': effective, 'source_exclusion_accounting': ledger,
                  'full_original_source_integrity': False, 'scope_reconciliation': provenance}
    audit = {**verified, 'created_at': utcnow(), 'source_exclusion_amendment': effective,
             'source_exclusion_accounting': ledger, 'totals': {**verified['totals'], **dict(partitions)},
             'complete_semantic_record_coverage': False, 'full_original_source_coverage': False,
             'full_original_source_integrity': False, 'current_excluded_coverage': 'unknown',
             'scope_reconciliation': provenance,
             'input_identity': {**identity, 'source_exclusion_amendment_sha256': effective['sha256'],
                                'source_exclusion_evidence_sha256': evidence,
                                'historical_inventory_audit_sha256': historical_audit_sha},
             'limitations': verified['limitations'] + [
                 'This derived view reuses verified historical record-range accounting and recomputes effective scope partitions; it does not observe current source files.']}
    # Detect mutation during the derived scan and ledger write, before publishing completion.
    for name, expected in identity['shards'].items():
        if sha256_file(checkpoint / name) != expected:
            raise AuditFailure('scope_view_historical_shard_changed')
    wal_inputs = {path.name: sha256_file(path) for shard in checkpoint.glob('inventory_shard_*.sqlite')
                  for path in [Path(str(shard) + '-wal')] if path.exists() and path.stat().st_size}
    if wal_inputs != identity.get('wal_inputs', {}):
        raise AuditFailure('scope_view_historical_wal_changed')
    if sha256_file(checkpoint / 'source_manifest.jsonl') != identity['manifest_sha256']:
        raise AuditFailure('scope_view_historical_manifest_changed')
    for name, key in (('statistics.json', 'summary_sha256'), ('manifest.json', 'completion_sha256')):
        if sha256_file(checkpoint / name) != identity[key]:
            raise AuditFailure('scope_view_historical_checkpoint_changed')
    if sha256_file(historical_path) != historical_audit_sha or validate_source_exclusion(checkpoint, config, freeze=False) != effective:
        raise AuditFailure('scope_view_authorization_or_audit_changed')
    atomic_json(output / 'statistics.json', statistics)
    atomic_json(output / 'inventory_reconciliation.json', audit)
    artifacts = {name: sha256_file(output / name) for name in ('statistics.json', 'inventory_reconciliation.json')}
    artifacts.update({relative: sha256_file(output / relative) for relative in ledger['artifacts'].values()})
    atomic_json(output / 'manifest.json', {'version': 1, 'complete': True, 'kind': 'inventory_scope_reconciliation',
                                         'scope_reconciliation': provenance, 'artifacts': artifacts})
    return {'statistics': statistics, 'audit': audit,
            'artifacts_base_relative_to_run': provenance['artifacts_base_relative_to_run']}
