"""Immutable, independently revalidated reuse of historical checkpoints 1–4.

An approved later exclusion changes current coverage, never prior artifacts or
statistics. Reuse is allowed only when no accepted source or raw candidate came
from any root excluded by the effective authorization.
"""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
import uuid

from .core import atomic_json, check_checkpoint, digest, safe_output, sha256_file
from .source_scope import (validate_source_exclusion, historical_source_exclusion,
                           source_exclusion_artifact_paths, is_source_excluded)

CHECKPOINTS = {1: 'checkpoint_01_inventory', 2: 'checkpoint_02_source_plans',
               3: 'checkpoint_03_raw_candidates', 4: 'checkpoint_04_validated_candidates'}
VERSION = 1


class ScopeReconciliationError(RuntimeError):
    pass


def _relative(value):
    if (not isinstance(value, str) or not value or PurePosixPath(value).is_absolute()
            or '..' in PurePosixPath(value).parts or str(PurePosixPath(value)) != value or value == '.'):
        raise ScopeReconciliationError('unsafe_scope_reconciliation_path')
    return value


def _path(run, relative):
    path = safe_output(run / _relative(relative))
    if run not in path.parents:
        raise ScopeReconciliationError('scope_reconciliation_path_outside_run')
    return path


def _object(path):
    path = safe_output(path)
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ScopeReconciliationError('scope_reconciliation_object_required')
    return value


def _pin(path):
    path = safe_output(path)
    if not path.is_file():
        raise ScopeReconciliationError('scope_reconciliation_artifact_missing')
    before = path.stat()
    result = {'sha256': sha256_file(path), 'bytes': before.st_size}
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ScopeReconciliationError('scope_reconciliation_artifact_changed_during_read')
    return result


def _tree_pins(run, directory):
    pins = {}
    for path in sorted(safe_output(directory).rglob('*')):
        safe_output(path)  # rejects symlinks, including directory components
        if path.is_dir():
            continue
        pins[path.relative_to(run).as_posix()] = _pin(path)
    return pins


def _checkpoint_inputs(run, config, scope):
    pins, statistics = {}, {}
    for number, name in CHECKPOINTS.items():
        checkpoint = run / name
        manifest = _object(checkpoint / 'checkpoint_manifest.json')
        paths = set()
        for item in manifest.get('artifacts', []):
            relative = _relative(item['path'])
            if relative in paths:
                raise ScopeReconciliationError('duplicate_checkpoint_artifact')
            paths.add(relative)
            safe_output(checkpoint / relative)
        if not check_checkpoint(checkpoint, config):
            raise ScopeReconciliationError('scope_reconciliation_requires_four_complete_checkpoints')
        if not {'statistics.json', 'configuration.json'} <= paths:
            raise ScopeReconciliationError('scope_reconciliation_checkpoint_statistics_not_frozen')
        expected_checksums = {item['path']: item['sha256'] for item in manifest['artifacts']}
        expected_checksums['checkpoint_manifest.json'] = _pin(checkpoint / 'checkpoint_manifest.json')['sha256']
        checksums = {}
        for line in (checkpoint / 'checksums.sha256').read_text().splitlines():
            checksum, relative = line.split('  ', 1)
            _relative(relative)
            if relative in checksums:
                raise ScopeReconciliationError('duplicate_checkpoint_checksum')
            checksums[relative] = checksum
        if checksums != expected_checksums:
            raise ScopeReconciliationError('checkpoint_checksum_manifest_changed')
        authoritative = paths | {'checkpoint_manifest.json', 'checksums.sha256'}
        for path in sorted(checkpoint.rglob('*')):
            safe_output(path)
            if path.is_dir():
                continue
            relative = path.relative_to(checkpoint).as_posix()
            if relative not in authoritative:
                # Only documented pass-one telemetry and SQLite shared-memory
                # readmarks are nonauthoritative. Declared files always win.
                if number == 1 and (path.name == 'progress.json' or path.name.endswith('_heartbeat.json')
                        or path.name.endswith('.sqlite-shm') and path.with_name(path.name[:-4]).is_file()):
                    continue
                if not (number == 1 and path.name.endswith('.sqlite-wal')
                        and path.with_name(path.name[:-4]).is_file()):
                    raise ScopeReconciliationError('unexpected_unfrozen_checkpoint_artifact')
            pins[path.relative_to(run).as_posix()] = _pin(path)
        statistics[str(number)] = _object(checkpoint / 'statistics.json')
    historical = historical_source_exclusion(scope)
    if historical == scope or not scope['frozen']:
        raise ScopeReconciliationError('scope_reconciliation_requires_frozen_later_exclusion')
    if statistics['1'].get('source_exclusion_amendment') != historical:
        raise ScopeReconciliationError('historical_inventory_scope_mismatch')
    for number in ('2', '3'):
        if statistics[number].get('source_exclusion_amendment_sha256') != historical['sha256']:
            raise ScopeReconciliationError('historical_task_scope_mismatch')
    reference = scope
    while reference is not None:
        for path in source_exclusion_artifact_paths(run / CHECKPOINTS[1], reference).values():
            pins[path.relative_to(run).as_posix()] = _pin(path)
        reference = reference.get('predecessor')
    audit_path = run / 'audits/inventory/inventory_reconciliation.json'
    pins.update(_tree_pins(run, audit_path.parent))
    historical_audit = _object(audit_path)
    identity = historical_audit.get('input_identity', {})
    inventory = run / CHECKPOINTS[1]
    if historical_audit.get('source_exclusion_amendment') != historical or historical_audit.get('identified_accounting_passed') is not True:
        raise ScopeReconciliationError('historical_inventory_audit_scope_or_accounting_invalid')
    for relative, key in (('statistics.json', 'summary_sha256'), ('manifest.json', 'completion_sha256'),
                          ('source_manifest.jsonl', 'manifest_sha256')):
        if identity.get(key) != pins[(inventory / relative).relative_to(run).as_posix()]['sha256']:
            raise ScopeReconciliationError('historical_inventory_audit_baseline_changed')
    shards = {path.name: pins[path.relative_to(run).as_posix()]['sha256']
              for path in inventory.glob('inventory_shard_*.sqlite')}
    wal_inputs = {path.name: pins[path.relative_to(run).as_posix()]['sha256']
                  for path in inventory.glob('inventory_shard_*.sqlite-wal') if path.stat().st_size}
    if identity.get('shards') != shards or identity.get('wal_inputs', {}) != wal_inputs:
        raise ScopeReconciliationError('historical_inventory_audit_database_or_wal_changed')
    return {'configuration_sha256': digest(config), 'historical_scope': historical,
            'effective_scope': scope, 'checkpoint_statistics': statistics, 'artifacts': pins}


def _rows(path):
    with safe_output(path).open(encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ScopeReconciliationError('scope_reconciliation_row_malformed')
            yield row


def _reuse_proof(run, scope):
    from .reporting import _stable_hash
    raw_signatures = {}
    counts = {'accepted_plan_files': 0, 'accepted_generation_files': 0,
              'raw_candidates': 0, 'raw_evidence_rows': 0}
    for number, metric in ((2, 'accepted_plan_files'), (3, 'accepted_generation_files')):
        for row in _rows(run / CHECKPOINTS[number] / 'source_dispositions.jsonl'):
            relative = _relative(row.get('source_file'))
            if row.get('status') == 'accepted':
                if is_source_excluded(relative, scope):
                    raise ScopeReconciliationError('excluded_source_accepted_in_historical_checkpoint')
                counts[metric] += 1
    raw = run / CHECKPOINTS[3]
    for path in sorted(raw.rglob('candidates.jsonl')):
        for row in _rows(path):
            metadata = row.get('metadata')
            if not isinstance(metadata, dict):
                raise ScopeReconciliationError('raw_candidate_metadata_missing')
            if is_source_excluded(_relative(metadata.get('source_file')), scope):
                raise ScopeReconciliationError('excluded_source_present_in_raw_candidates')
            identity = row.get('id')
            if not isinstance(identity, str) or not identity or identity in raw_signatures:
                raise ScopeReconciliationError('raw_candidate_identity_missing_or_duplicate')
            raw_signatures[identity] = _stable_hash(row)
            counts['raw_candidates'] += 1
        for row in _rows(path.with_name('evidence.jsonl')):
            if is_source_excluded(_relative(row.get('source_file')), scope):
                raise ScopeReconciliationError('excluded_source_present_in_raw_evidence')
            counts['raw_evidence_rows'] += 1
    if counts['raw_candidates'] != counts['raw_evidence_rows']:
        raise ScopeReconciliationError('raw_candidate_evidence_count_mismatch')
    declared = _object(raw / 'statistics.json')
    if declared.get('candidates') != counts['raw_candidates']:
        raise ScopeReconciliationError('raw_candidate_proof_count_mismatch')
    stages = {}
    validated = run / CHECKPOINTS[4]
    for stage, relative, wrapper in (
            ('validated', 'validated.jsonl', None), ('quarantined', 'quarantined.jsonl', 'candidate'),
            ('clean', 'contamination/clean_candidates.jsonl', None),
            ('contaminated', 'contamination/contaminated_candidates.jsonl', 'candidate')):
        members = set()
        for row in _rows(validated / relative):
            candidate = row.get(wrapper) if wrapper else row
            if not isinstance(candidate, dict) or not isinstance(candidate.get('metadata'), dict):
                raise ScopeReconciliationError('pass_four_candidate_or_metadata_missing')
            if is_source_excluded(_relative(candidate['metadata'].get('source_file')), scope):
                raise ScopeReconciliationError('excluded_source_present_in_pass_four_candidates')
            identity = candidate.get('id')
            if (not isinstance(identity, str) or identity in members or identity not in raw_signatures
                    or _stable_hash(candidate) != raw_signatures[identity]):
                raise ScopeReconciliationError('pass_four_candidate_lineage_missing_duplicate_or_changed')
            members.add(identity)
        stages[stage] = members
        counts[stage + '_candidates'] = len(members)
    if (stages['validated'] & stages['quarantined']
            or stages['validated'] | stages['quarantined'] != raw_signatures.keys()
            or stages['clean'] & stages['contaminated']
            or stages['clean'] | stages['contaminated'] != stages['validated']):
        raise ScopeReconciliationError('pass_four_candidate_partition_incomplete_or_duplicate')
    return {**counts, 'excluded_accepted_files': 0, 'excluded_raw_candidates': 0,
            'excluded_source_roots': scope['amendment']['excluded_source_roots']}


def _root(run, scope):
    return safe_output(run / 'scope_reconciliations' / scope['sha256'])


def _validate_publication(run, config, scope, publication):
    if set(publication) != {'version', 'view_path', 'view_sha256', 'artifacts'} or publication['version'] != VERSION:
        raise ScopeReconciliationError('scope_reconciliation_publication_invalid')
    view_path = _path(run, publication['view_path'])
    expected_root = _root(run, scope)
    if expected_root not in view_path.parents:
        raise ScopeReconciliationError('scope_reconciliation_view_outside_scope')
    for relative, expected in publication['artifacts'].items():
        path = _path(run, relative)
        if view_path.parent not in path.parents or _pin(path) != expected:
            raise ScopeReconciliationError('scope_reconciliation_artifact_changed')
    if _pin(view_path)['sha256'] != publication['view_sha256']:
        raise ScopeReconciliationError('scope_reconciliation_view_changed')
    view = _object(view_path)
    inputs = _checkpoint_inputs(run, config, scope)
    if view.get('version') != VERSION or view.get('inputs') != inputs:
        raise ScopeReconciliationError('scope_reconciliation_inputs_changed')
    if view.get('reuse_proof') != _reuse_proof(run, scope):
        raise ScopeReconciliationError('scope_reconciliation_reuse_proof_changed')
    base = _path(run, view['artifacts_base_relative_to_run'])
    if view_path.parent not in base.parents:
        raise ScopeReconciliationError('scope_reconciliation_ledger_outside_view')
    derived_manifest = _object(base / 'manifest.json')
    if derived_manifest.get('complete') is not True or derived_manifest.get('kind') != 'inventory_scope_reconciliation':
        raise ScopeReconciliationError('scope_reconciliation_inventory_view_incomplete')
    for relative, expected in derived_manifest.get('artifacts', {}).items():
        if _pin(base / _relative(relative))['sha256'] != expected:
            raise ScopeReconciliationError('scope_reconciliation_inventory_artifact_changed')
    if view.get('statistics') != _object(base / 'statistics.json') or view.get('audit') != _object(base / 'inventory_reconciliation.json'):
        raise ScopeReconciliationError('scope_reconciliation_derived_statistics_changed')
    if view['statistics'].get('source_exclusion_amendment') != scope or view['audit'].get('source_exclusion_amendment') != scope:
        raise ScopeReconciliationError('scope_reconciliation_effective_scope_changed')
    measured = _tree_pins(run, view_path.parent)
    if measured != publication['artifacts']:
        raise ScopeReconciliationError('scope_reconciliation_artifact_set_changed')
    return view


def validate_scope_reconciliation(run, config, reference=None):
    """Read-only independent validation; an unfinished view is never reusable."""
    run = safe_output(run)
    scope = validate_source_exclusion(run / CHECKPOINTS[1], config)
    if scope is None or historical_source_exclusion(scope) == scope:
        raise ScopeReconciliationError('scope_reconciliation_not_applicable')
    root = _root(run, scope)
    publication = _object(root / 'completion.json')
    if (publication != _object(root / 'publication_intent.json')
            or _pin(root / 'completion.json') != _pin(root / 'publication_intent.json')):
        raise ScopeReconciliationError('scope_reconciliation_publication_changed')
    view = _validate_publication(run, config, scope, publication)
    actual_reference = {'path': (root / 'completion.json').relative_to(run).as_posix(),
                        'sha256': _pin(root / 'completion.json')['sha256'],
                        'view_path': publication['view_path'], 'view_sha256': publication['view_sha256'],
                        'historical_scope_sha256': historical_source_exclusion(scope)['sha256'],
                        'effective_scope_sha256': scope['sha256'], 'reused_passes': [1, 2, 3, 4]}
    if reference is not None and reference != actual_reference:
        raise ScopeReconciliationError('scope_reconciliation_reference_changed')
    if validate_source_exclusion(run / CHECKPOINTS[1], config) != scope:
        raise ScopeReconciliationError('scope_reconciliation_authorization_changed_during_validation')
    artifact_pins = dict(view['inputs']['artifacts'], **publication['artifacts'])
    for path in (root / 'completion.json', root / 'publication_intent.json'):
        artifact_pins[path.relative_to(run).as_posix()] = _pin(path)
    return dict(view, reference=actual_reference, artifact_pins=artifact_pins)


def prepare_scope_reconciliation(run, config):
    """Publish a fresh view, or recover only an already pinned final publication."""
    from .audit import reconcile_inventory_scope
    run = safe_output(run)
    scope = validate_source_exclusion(run / CHECKPOINTS[1], config, freeze=True)
    if scope is None or historical_source_exclusion(scope) == scope:
        raise ScopeReconciliationError('scope_reconciliation_not_applicable')
    root = _root(run, scope)
    root.mkdir(parents=True, exist_ok=True)
    completion, intent = root / 'completion.json', root / 'publication_intent.json'
    if completion.exists():
        return validate_scope_reconciliation(run, config)
    if intent.exists():
        publication = _object(intent)
        _validate_publication(run, config, scope, publication)
    else:
        inputs = _checkpoint_inputs(run, config, scope)
        proof = _reuse_proof(run, scope)
        attempt = safe_output(root / 'attempts' / uuid.uuid4().hex)
        attempt.mkdir(parents=True)
        derived = reconcile_inventory_scope(run / CHECKPOINTS[1], attempt / 'inventory', config,
            run / 'audits/inventory/inventory_reconciliation.json')
        view = {'version': VERSION, 'inputs': inputs, 'reuse_proof': proof,
                'statistics': derived['statistics'], 'audit': derived['audit'],
                'artifacts_base_relative_to_run': derived['artifacts_base_relative_to_run']}
        view_path = attempt / 'view.json'
        atomic_json(view_path, view)
        publication = {'version': VERSION, 'view_path': view_path.relative_to(run).as_posix(),
                       'view_sha256': _pin(view_path)['sha256'], 'artifacts': _tree_pins(run, attempt)}
        _validate_publication(run, config, scope, publication)
        atomic_json(intent, publication)
    atomic_json(completion, publication)
    return validate_scope_reconciliation(run, config)
