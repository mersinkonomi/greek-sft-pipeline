"""Explicit, incident-bound source exclusions; historical baselines stay intact."""
from __future__ import annotations

import datetime as dt
import hashlib
from pathlib import Path, PurePosixPath
import re

NAME = 'source_exclusion_amendment.json'
CHECKSUM_NAME = 'source_exclusion_amendment.sha256.json'
APPROVED_ROOT = 'greek_training/.git'
DERIVED_NAME = 'derived_collection_exclusion_amendment.json'
DERIVED_CHECKSUM_NAME = 'derived_collection_exclusion_amendment.sha256.json'
DERIVED_ROOT = 'greek_training'
DERIVED_INSTRUCTION = 'greek training is a mix of the others so we dont make sft from that'
DERIVED_REASON = 'derived_mixture_of_other_source_collections'
DERIVED_MODE = 'exclude_derived_collection_from_current_source_coverage_and_sft'
APPROVED_QUESTION = 'May I exclude `greek_training/.git/` from source coverage and resume with that exception documented?'
TEMPORARY_NAME = 'temporary_collection_exclusion_amendment.json'
TEMPORARY_CHECKSUM_NAME = 'temporary_collection_exclusion_amendment.sha256.json'
TEMPORARY_FROZEN_DIR = 'source_scope_amendments/temporary_collection'
TEMPORARY_ROOT = 'greek_training_temp'
TEMPORARY_INSTRUCTION = 'leave it continue with the other ones'
TEMPORARY_QUESTION = 'May I also exclude `greek_training_temp/` from SFT generation and current source coverage, then resume?'
TEMPORARY_REASON = 'user_requested_temporary_collection_exclusion'
TEMPORARY_MODE = 'exclude_temporary_collection_from_current_source_coverage_and_sft'


class SourceExclusionConflict(RuntimeError):
    pass


def is_source_excluded(relative, scope):
    if not scope:
        return False
    if not isinstance(relative, str):
        raise ValueError('source_exclusion_invalid_relative_path')
    path = PurePosixPath(relative)
    if path.is_absolute() or '..' in path.parts or str(path) != relative or relative == '.':
        raise ValueError('source_exclusion_unsafe_relative_path')
    roots = scope['amendment']['excluded_source_roots']
    return any(relative == root or relative.startswith(root + '/') for root in roots)


def validate_source_exclusion_binding(report, scope):
    if 'source_exclusion_amendment_sha256' in report:
        if not scope or report['source_exclusion_amendment_sha256'] != scope['sha256']:
            raise SourceExclusionConflict('cached_source_exclusion_identity_missing_or_changed')


class _ValidatedTemporaryScope(dict):
    """Runtime-only provenance: deserializing a report cannot grant scope reuse."""


def historical_source_exclusion(scope):
    """Return the scope of immutable inventory rows, never of current outputs."""
    if isinstance(scope, _ValidatedTemporaryScope):
        predecessor = scope.get('predecessor')
        if (scope.get('artifact') != TEMPORARY_NAME or not predecessor
                or predecessor.get('artifact') != DERIVED_NAME or not predecessor.get('frozen')
                or scope['amendment'].get('excluded_source_roots') != [DERIVED_ROOT, TEMPORARY_ROOT]
                or scope['amendment'].get('predecessor_checkpoint_sha256') != predecessor.get('sha256')
                or scope['amendment'].get('predecessor_run_local_sha256') != predecessor.get('run_local_sha256')
                or predecessor['amendment'].get('excluded_source_roots') != [DERIVED_ROOT]):
            raise SourceExclusionConflict('source_exclusion_invalid_historical_scope')
        return predecessor
    return scope


def source_exclusion_artifact_paths(checkpoint, scope):
    """Locate the four evidence artifacts for one validated chain node."""
    checkpoint = Path(checkpoint)
    artifact = scope['artifact']
    names = {NAME: CHECKSUM_NAME, DERIVED_NAME: DERIVED_CHECKSUM_NAME,
             TEMPORARY_NAME: TEMPORARY_CHECKSUM_NAME}
    if artifact not in names or scope['checksum_artifact'] != names[artifact]:
        raise SourceExclusionConflict('source_exclusion_unknown_artifact')
    frozen = checkpoint.parent / TEMPORARY_FROZEN_DIR if artifact == TEMPORARY_NAME else checkpoint
    from .core import safe_output
    return {key: safe_output(path) for key, path in {
        'run_local': checkpoint.parent / artifact,
        'frozen': frozen / artifact,
        'checksum': frozen / names[artifact],
        'incident': checkpoint.parent / scope['amendment']['integrity_incident_path'],
    }.items()}


def validate_source_exclusion(checkpoint, config, *, freeze=False):
    """Resolve the append-only current scope without rewriting historical inventory."""
    checkpoint = Path(checkpoint)
    frozen = checkpoint.parent / TEMPORARY_FROZEN_DIR
    temporary = any(path.exists() or path.is_symlink() for path in (
        checkpoint.parent / TEMPORARY_NAME, frozen,
        frozen / TEMPORARY_NAME, frozen / TEMPORARY_CHECKSUM_NAME))
    if not temporary:
        return _validate_historical_source_exclusion(checkpoint, config, freeze=freeze)
    predecessor = _validate_historical_source_exclusion(checkpoint, config)
    if (not predecessor or predecessor['artifact'] != DERIVED_NAME
            or not predecessor['frozen'] or not predecessor.get('predecessor', {}).get('frozen')):
        raise SourceExclusionConflict('source_exclusion_temporary_predecessor_missing_or_unfrozen')
    result = _validate_source_exclusion(checkpoint, config, freeze=freeze,
        predecessor=predecessor, temporary=True)
    return _ValidatedTemporaryScope(result, predecessor=predecessor)


def _validate_historical_source_exclusion(checkpoint, config, *, freeze=False):
    """Validate the legacy authorization and optional derived-collection extension."""
    checkpoint = Path(checkpoint)
    derived = any(path.exists() or path.is_symlink() for path in (
        checkpoint.parent / DERIVED_NAME, checkpoint / DERIVED_NAME,
        checkpoint / DERIVED_CHECKSUM_NAME))
    predecessor = _validate_source_exclusion(checkpoint, config,
        effective_extension=derived)
    if not derived:
        return (_validate_source_exclusion(checkpoint, config, freeze=True)
                if freeze else predecessor)
    if predecessor is None:
        raise SourceExclusionConflict('source_exclusion_predecessor_missing')
    # Validate the entire chain before writing either frozen authorization.
    result = _validate_source_exclusion(checkpoint, config, predecessor=predecessor)
    if freeze:
        predecessor = _validate_source_exclusion(checkpoint, config, freeze=True,
            effective_extension=True)
        result = _validate_source_exclusion(checkpoint, config, freeze=True,
            predecessor=predecessor)
    return dict(result, predecessor=predecessor)


def _validate_source_exclusion(checkpoint, config, *, freeze=False,
                               predecessor=None, effective_extension=False, temporary=False):
    # Local imports keep inventory's public compatibility entry points acyclic.
    from .inventory import _read_scope_file, _atomic_json, _json, validate_inventory_scope

    checkpoint = Path(checkpoint)
    run = checkpoint.parent
    derived = predecessor is not None
    name = TEMPORARY_NAME if temporary else DERIVED_NAME if derived else NAME
    checksum_name = TEMPORARY_CHECKSUM_NAME if temporary else DERIVED_CHECKSUM_NAME if derived else CHECKSUM_NAME
    frozen_dir = run / TEMPORARY_FROZEN_DIR if temporary else checkpoint
    run_file, copy_file, checksum_file = run / name, frozen_dir / name, frozen_dir / checksum_name
    present = [path.exists() or path.is_symlink() for path in (run_file, copy_file, checksum_file)]
    complete_file = checkpoint / 'manifest.json'
    completion, completion_raw = (_read_scope_file(complete_file)
        if complete_file.exists() or complete_file.is_symlink() else ({}, b''))
    complete = completion.get('complete') is True
    completed_binding = completion.get('source_exclusion_amendment_sha256')
    if not any(present):
        if completed_binding is not None:
            raise SourceExclusionConflict('source_exclusion_authorization_removed_after_completion')
        return None
    if not present[0]:
        raise SourceExclusionConflict('source_exclusion_authorization_removed')
    amendment, raw = _read_scope_file(run_file)
    keys = {'version', 'run_id', 'authorized_at', 'user_instruction', 'approved_question',
            'excluded_source_roots', 'mode', 'base_inventory_config_sha256',
            'record_scope_amendment_sha256', 'integrity_incident_path', 'integrity_incident_sha256',
            'preserve_historical_inventory', 'full_original_source_integrity_claim_allowed',
            'current_excluded_coverage'}
    if derived:
        keys = keys - {'approved_question'} | {'reason', 'predecessor_run_local_sha256',
                                               'predecessor_checkpoint_sha256'}
    if temporary:
        keys |= {'approved_question', 'inventory_checkpoint_manifest_sha256',
                 'inventory_manifest_sha256', 'inventory_source_manifest_sha256'}
    config_hash = hashlib.sha256(_json(config).encode()).hexdigest()
    if (not isinstance(amendment, dict) or set(amendment) != keys
            or type(amendment['version']) is not int or amendment['version'] != 1
            or amendment['run_id'] != run.name or amendment['user_instruction'] != (TEMPORARY_INSTRUCTION if temporary else DERIVED_INSTRUCTION if derived else 'continue')
            or (not derived and amendment['approved_question'] != APPROVED_QUESTION)
            or (temporary and amendment['approved_question'] != TEMPORARY_QUESTION)
            or amendment['excluded_source_roots'] != ([DERIVED_ROOT, TEMPORARY_ROOT] if temporary else [DERIVED_ROOT if derived else APPROVED_ROOT])
            or amendment['mode'] != (TEMPORARY_MODE if temporary else DERIVED_MODE if derived else 'exclude_subtree_from_current_source_coverage')
            or amendment['base_inventory_config_sha256'] != config_hash
            or amendment['preserve_historical_inventory'] is not True
            or amendment['full_original_source_integrity_claim_allowed'] is not False
            or amendment['current_excluded_coverage'] != 'unknown'):
        raise SourceExclusionConflict('source_exclusion_invalid_or_unapproved_amendment')
    if derived and (amendment['reason'] != (TEMPORARY_REASON if temporary else DERIVED_REASON)
            or amendment['predecessor_run_local_sha256'] != predecessor['run_local_sha256']
            or amendment['predecessor_checkpoint_sha256'] != predecessor['sha256']):
        raise SourceExclusionConflict('source_exclusion_predecessor_or_reason_changed')
    try:
        authorized_at = dt.datetime.fromisoformat(amendment['authorized_at'])
        if authorized_at.tzinfo is None or authorized_at.utcoffset() != dt.timedelta(0):
            raise ValueError('not_utc')
    except (TypeError, ValueError) as error:
        raise SourceExclusionConflict('source_exclusion_invalid_authorization_time') from error
    state_file = checkpoint / 'inventory_state.json'
    if state_file.exists() or state_file.is_symlink():
        state, _ = _read_scope_file(state_file)
        if not isinstance(state, dict) or state.get('config_sha256') != config_hash:
            raise SourceExclusionConflict('source_exclusion_frozen_config_conflict')
    record_scope = validate_inventory_scope(checkpoint, config)
    record_scope_hash = record_scope['sha256'] if record_scope else None
    if (amendment['record_scope_amendment_sha256'] != record_scope_hash
            or record_scope is not None and not record_scope['frozen']):
        raise SourceExclusionConflict('source_exclusion_record_scope_missing_changed_or_unfrozen')
    if temporary:
        from .core import safe_output
        # Pin the two small immutable manifests here. The independent verifier
        # and checkpoint audit still hash the full source_manifest.jsonl bytes.
        checkpoint_manifest, checkpoint_raw = _read_scope_file(checkpoint / 'checkpoint_manifest.json')
        declared_source_hash = completion.get('source_manifest_sha256')
        if (not complete or completed_binding != predecessor['sha256']
                or not isinstance(declared_source_hash, str)
                or not re.fullmatch('[0-9a-f]{64}', declared_source_hash)
                or amendment['inventory_manifest_sha256'] != hashlib.sha256(completion_raw).hexdigest()
                or amendment['inventory_checkpoint_manifest_sha256'] != hashlib.sha256(checkpoint_raw).hexdigest()
                or amendment['inventory_source_manifest_sha256'] != declared_source_hash
                or not isinstance(checkpoint_manifest, dict)
                or checkpoint_manifest.get('configuration_hash') != config_hash
                or not isinstance(checkpoint_manifest.get('artifacts'), list)):
            raise SourceExclusionConflict('source_exclusion_historical_inventory_identity_changed')
        for historical_name, expected in (('manifest.json', amendment['inventory_manifest_sha256']),
                               ('source_manifest.jsonl', declared_source_hash)):
            bindings = [item.get('sha256') for item in checkpoint_manifest['artifacts']
                        if isinstance(item, dict) and item.get('path') == historical_name]
            if bindings != [expected]:
                raise SourceExclusionConflict('source_exclusion_historical_inventory_manifest_conflict')
        if not safe_output(checkpoint / 'source_manifest.jsonl').is_file():
            raise SourceExclusionConflict('source_exclusion_historical_source_manifest_missing')
    relative_incident = amendment['integrity_incident_path']
    if not isinstance(relative_incident, str):
        raise SourceExclusionConflict('source_exclusion_invalid_incident_reference')
    incident_path = PurePosixPath(relative_incident)
    if (incident_path.is_absolute() or '..' in incident_path.parts or str(incident_path) != relative_incident
            or len(incident_path.parts) != 3 or incident_path.parts[0] != 'integrity_incidents'
            or incident_path.name != 'incident.json'):
        raise SourceExclusionConflict('source_exclusion_invalid_incident_reference')
    incident, incident_raw = _read_scope_file(run / incident_path)
    if hashlib.sha256(incident_raw).hexdigest() != amendment['integrity_incident_sha256']:
        raise SourceExclusionConflict('source_exclusion_preserved_incident_changed')
    scope_probe = {'amendment': amendment}
    if (not isinstance(incident, dict) or incident.get('run_id') != run.name
            or incident.get('status') != 'halted_source_integrity_failure'
            or incident.get('sha256_matches') is not False
            or not is_source_excluded(incident.get('source_file'), scope_probe)
            or not isinstance(incident.get('baseline_sha256'), str)
            or not re.fullmatch('[0-9a-f]{64}', incident['baseline_sha256'])
            or not isinstance(incident.get('observed_sha256'), str)
            or not re.fullmatch('[0-9a-f]{64}', incident['observed_sha256'])
            or incident['baseline_sha256'] == incident['observed_sha256']):
        raise SourceExclusionConflict('source_exclusion_incident_not_applicable')
    if derived and not temporary and incident['source_file'] != 'greek_training/.gitignore':
        raise SourceExclusionConflict('source_exclusion_derived_incident_not_applicable')
    if temporary and not (incident['source_file'] == TEMPORARY_ROOT
            or incident['source_file'].startswith(TEMPORARY_ROOT + '/')):
        raise SourceExclusionConflict('source_exclusion_temporary_incident_not_applicable')
    snapshot_raw = (_json(amendment) + '\n').encode('utf-8')
    identity = {'version': 1, 'run_local_sha256': hashlib.sha256(raw).hexdigest(),
                'checkpoint_sha256': hashlib.sha256(snapshot_raw).hexdigest()}
    if complete and not temporary and (not (present[1] and present[2]) or (not effective_extension and completed_binding != identity['checkpoint_sha256'])):
        raise SourceExclusionConflict('source_exclusion_cannot_amend_completed_inventory')
    if derived and (present[1] or present[2]) and (
            (present[1] and not present[2]) or not predecessor['frozen']):
        raise SourceExclusionConflict('source_exclusion_frozen_chain_artifact_missing')
    if present[2] and not present[1] and not derived:
        raise SourceExclusionConflict('source_exclusion_snapshot_missing')
    if present[1]:
        copied, copied_raw = _read_scope_file(copy_file)
        if copied != amendment or hashlib.sha256(copied_raw).hexdigest() != identity['checkpoint_sha256']:
            raise SourceExclusionConflict('source_exclusion_snapshot_or_authorization_changed')
    if present[2]:
        stored, _ = _read_scope_file(checksum_file)
        if stored != identity:
            raise SourceExclusionConflict('source_exclusion_resume_identity_changed')
    if freeze:
        if temporary:
            from .core import safe_output
            safe_output(frozen_dir).mkdir(parents=True, exist_ok=True)
        # Pin raw and canonical identities first for crash-safe extension recovery.
        # Legacy publication order remains unchanged.
        if derived and not present[2]:
            _atomic_json(checksum_file, identity)
        if not present[1]:
            _atomic_json(copy_file, amendment)
        if not derived and not present[2]:
            _atomic_json(checksum_file, identity)
        present[1] = present[2] = True
    return {'amendment': amendment, 'sha256': identity['checkpoint_sha256'],
            'run_local_sha256': identity['run_local_sha256'], 'artifact': name,
            'checksum_artifact': checksum_name, 'frozen': present[1] and present[2]}
