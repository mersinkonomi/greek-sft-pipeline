"""Audit exact *file-byte* duplication using completed inventory metadata only.

The caller must first validate inventory completion. This module never opens a
source file, removes data, or claims semantic/document/record deduplication.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
import uuid
from pathlib import Path, PurePosixPath

from .core import atomic_json, atomic_text, canonical_json, safe_output, sha256_file, utcnow

VERSION = 'source-file-duplicates-1.0.0'
MAX_MANIFEST_LINE_BYTES = 8 * 1024 * 1024
BATCH_SIZE = 10000
SQLITE_SYNCHRONOUS = 'FULL'
KINDS = ('data', 'sidecar_metadata', 'cache_or_derived_artifact',
         'repository_or_bytecode', 'documentation_code_or_log', 'other_unsupported')
LIMITATIONS = [
    'This audit compares raw-file SHA-256 and byte size from the completed inventory; it does not reread source content.',
    'File identity is not semantic, document, entity, or within-file/record-level duplication detection.',
    'Differently compressed or serialized files with identical decoded content may not match.',
    'Data-file counts exclude sidecars, caches, derived outputs, repository files, code and logs; they are not counts of duplicated training documents.',
    'Classifications describe filename/manifest-format evidence and do not establish eligibility, licensing or training suitability.',
    'Redundant copies are accounting only; every source and artifact remains untouched.',
    'Per-family and per-format redundant bytes use the globally smallest relative path as representative, including cross-family groups.',
]


def _kind(relative, file_format):
    parts = PurePosixPath(relative).parts
    name = parts[-1]
    if parts[0] in {'.hf_cache', '.claude', '00aa_tools', 'greek_training', 'greek_training_temp'}:
        return 'cache_or_derived_artifact'
    if '.git' in parts or '__pycache__' in parts:
        return 'repository_or_bytecode'
    if name.endswith(('.meta', '.idx')) or name == 'dataset_dict.jsonl':
        return 'sidecar_metadata'
    if name.endswith(('.md', '.py', '.pyc', '.sh', '.yaml', '.yml', '.log', '.paths', '.sample')):
        return 'documentation_code_or_log'
    if file_format in {'jsonl', 'json_document', 'json', 'parquet', 'csv', 'tsv', 'text', 'xml'}:
        return 'data'
    return 'other_unsupported'


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate_manifest_json_key')
        result[key] = value
    return result


def _text(value, field, maximum=4096):
    if not isinstance(value, str) or not value or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise ValueError('invalid_manifest_' + field)
    return value


def _row(item):
    if not isinstance(item, dict):
        raise ValueError('manifest_row_must_be_object')
    relative = _text(item.get('relative_path'), 'relative_path')
    path = PurePosixPath(relative)
    if path.is_absolute() or '..' in path.parts or str(path) != relative or relative == '.':
        raise ValueError('unsafe_manifest_relative_path')
    checksum = item.get('sha256')
    if not isinstance(checksum, str) or not re.fullmatch('[0-9a-f]{64}', checksum):
        raise ValueError('invalid_manifest_sha256')
    size = item.get('size_bytes')
    if type(size) is not int or not 0 <= size <= 2**63 - 1:
        raise ValueError('invalid_manifest_size_bytes')
    if size == 0 and checksum != hashlib.sha256(b'').hexdigest():
        raise ValueError('invalid_empty_file_sha256')
    family = _text(item.get('family'), 'family')
    file_format = _text(item.get('format'), 'format', 256)
    return relative, checksum, size, family, file_format, _kind(relative, file_format)


def _fingerprint(value):
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _guard_tree(directory):
    safe_output(directory)
    if directory.exists():
        for base, dirs, files in os.walk(directory, followlinks=False):
            for name in dirs + files:
                safe_output(Path(base) / name)


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextlib.contextmanager
def _jsonl_writer(path):
    path = safe_output(path)
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        yield lambda value: stream.write(canonical_json(value) + '\n')
        stream.flush()
        os.fsync(stream.fileno())


def _ordered(db, sql):
    # Tables and indices are populated incrementally. No SQLite external sort,
    # temporary B-tree, or unbounded in-memory grouping is permitted.
    plan = ' '.join(str(row[-1]) for row in db.execute('EXPLAIN QUERY PLAN ' + sql))
    if 'TEMP B-TREE' in plan or 'AUTOMATIC' in plan:
        raise RuntimeError('unbounded_duplicate_audit_query_plan')
    return db.execute(sql)


def _increment(db, dimension, key, files=0, size=0, duplicate=0, redundant=0, redundant_bytes=0):
    db.execute('''INSERT INTO breakdown VALUES(?,?,?,?,?,?,?)
        ON CONFLICT(dimension,label) DO UPDATE SET
        files=files+excluded.files,bytes=bytes+excluded.bytes,
        duplicate_members=duplicate_members+excluded.duplicate_members,
        redundant_copies=redundant_copies+excluded.redundant_copies,
        redundant_bytes=redundant_bytes+excluded.redundant_bytes''',
        (dimension, key, files, size, duplicate, redundant, redundant_bytes))


def _build(manifest_path, attempt, output_dir, identity):
    db_path = safe_output(attempt / 'file_identity.sqlite')
    totals = {'files': 0, 'bytes': 0, 'groups': 0, 'duplicate_member_files': 0,
              'redundant_copies': 0, 'redundant_bytes': 0, 'zero_byte_files': 0,
              'zero_byte_groups': 0, 'zero_byte_duplicate_member_files': 0,
              'zero_byte_redundant_copies': 0}
    by_kind = {key: {'files': 0, 'bytes': 0, 'groups_with_multiple_files_of_kind': 0,
                     'duplicate_member_files_within_kind': 0, 'redundant_copies_within_kind': 0,
                     'redundant_bytes_within_kind': 0} for key in KINDS}
    with contextlib.closing(sqlite3.connect(db_path)) as db:
        db.execute('PRAGMA journal_mode=DELETE')
        db.execute('PRAGMA synchronous=' + SQLITE_SYNCHRONOUS)
        db.execute('PRAGMA cache_size=-16384')
        db.execute('PRAGMA temp_store=MEMORY')
        db.execute('PRAGMA automatic_index=OFF')
        db.executescript('''
            CREATE TABLE files(relative_path TEXT PRIMARY KEY,sha256 TEXT NOT NULL,size_bytes INTEGER NOT NULL,
                               family TEXT NOT NULL,format TEXT NOT NULL,kind TEXT NOT NULL) WITHOUT ROWID;
            CREATE INDEX content_identity ON files(sha256,size_bytes,relative_path);
            CREATE TABLE duplicate_groups(sha256 TEXT,size_bytes INTEGER,representative TEXT NOT NULL,
                               members INTEGER NOT NULL,PRIMARY KEY(sha256,size_bytes)) WITHOUT ROWID;
            CREATE TABLE breakdown(dimension TEXT,label TEXT,files INTEGER,bytes INTEGER,
                               duplicate_members INTEGER,redundant_copies INTEGER,redundant_bytes INTEGER,
                               PRIMARY KEY(dimension,label)) WITHOUT ROWID;
        ''')
        before = manifest_path.stat()
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('manifest_not_regular_file')
        checksum = hashlib.sha256()
        fd = os.open(manifest_path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as stream:
            if _fingerprint(os.fstat(stream.fileno())) != _fingerprint(before):
                raise ValueError('manifest_changed_before_read')
            line_number = 0
            while True:
                raw = stream.readline(MAX_MANIFEST_LINE_BYTES + 1)
                if not raw:
                    break
                line_number += 1
                if len(raw) > MAX_MANIFEST_LINE_BYTES:
                    raise ValueError('manifest_row_exceeds_limit_at_line_' + str(line_number))
                checksum.update(raw)
                try:
                    item = json.loads(raw.decode('utf-8'), object_pairs_hook=_json_object)
                    row = _row(item)
                except (UnicodeError, ValueError, TypeError) as error:
                    raise ValueError('invalid_manifest_row_at_line_' + str(line_number)) from error
                try:
                    db.execute('INSERT INTO files VALUES(?,?,?,?,?,?)', row)
                except sqlite3.IntegrityError as error:
                    raise ValueError('duplicate_manifest_relative_path_at_line_' + str(line_number)) from error
                relative, _, size, family, file_format, kind = row
                totals['files'] += 1
                totals['bytes'] += size
                totals['zero_byte_files'] += size == 0
                by_kind[kind]['files'] += 1
                by_kind[kind]['bytes'] += size
                for dimension, label in (('family', family), ('format', file_format), ('kind', kind)):
                    _increment(db, dimension, label, files=1, size=size)
                if totals['files'] % BATCH_SIZE == 0:
                    db.commit()
            if (_fingerprint(os.fstat(stream.fileno())) != _fingerprint(before)
                    or _fingerprint(manifest_path.stat()) != _fingerprint(before)
                    or checksum.hexdigest() != identity['sha256']):
                raise ValueError('source_manifest_changed_during_audit')
        db.commit()
        group_path = attempt / 'duplicate_groups.jsonl'
        with _jsonl_writer(group_path) as write_group:
            current = None
            representative = None
            members = 0
            kind_counts = dict.fromkeys(KINDS, 0)

            def finish_group():
                if members < 2:
                    return
                checksum, size = current
                db.execute('INSERT INTO duplicate_groups VALUES(?,?,?,?)',
                           (checksum, size, representative, members))
                totals['groups'] += 1
                totals['duplicate_member_files'] += members
                totals['redundant_copies'] += members - 1
                totals['redundant_bytes'] += size * (members - 1)
                if size == 0:
                    totals['zero_byte_groups'] += 1
                    totals['zero_byte_duplicate_member_files'] += members
                    totals['zero_byte_redundant_copies'] += members - 1
                for kind, count in kind_counts.items():
                    if count > 1:
                        values = by_kind[kind]
                        values['groups_with_multiple_files_of_kind'] += 1
                        values['duplicate_member_files_within_kind'] += count
                        values['redundant_copies_within_kind'] += count - 1
                        values['redundant_bytes_within_kind'] += size * (count - 1)
                write_group({'group_id': checksum + ':' + str(size), 'sha256': checksum,
                             'size_bytes': size, 'representative': representative, 'member_files': members,
                             'redundant_copies': members - 1, 'redundant_bytes': size * (members - 1),
                             'zero_byte': size == 0, 'member_kind_counts': kind_counts})

            for checksum, size, relative, kind in _ordered(db,
                    'SELECT sha256,size_bytes,relative_path,kind FROM files INDEXED BY content_identity '
                    'ORDER BY sha256,size_bytes,relative_path'):
                identity_key = checksum, size
                if current != identity_key:
                    finish_group()
                    current, representative, members = identity_key, relative, 0
                    kind_counts = dict.fromkeys(KINDS, 0)
                members += 1
                kind_counts[kind] += 1
            finish_group()
        db.commit()
        with _jsonl_writer(attempt / 'duplicate_members.jsonl') as write_member:
            for relative, checksum, size, family, file_format, kind, representative in _ordered(db,
                    'SELECT f.relative_path,f.sha256,f.size_bytes,f.family,f.format,f.kind,d.representative '
                    'FROM files f INDEXED BY content_identity JOIN duplicate_groups d '
                    'ON f.sha256=d.sha256 AND f.size_bytes=d.size_bytes '
                    'ORDER BY f.sha256,f.size_bytes,f.relative_path'):
                redundant = int(relative != representative)
                write_member({'group_id': checksum + ':' + str(size), 'relative_path': relative,
                              'family': family, 'format': file_format, 'kind': kind,
                              'representative': representative, 'is_representative': not redundant,
                              'size_bytes': size, 'zero_byte': size == 0})
                for dimension, label in (('family', family), ('format', file_format), ('kind', kind)):
                    _increment(db, dimension, label, duplicate=1, redundant=redundant,
                               redundant_bytes=size * redundant)
        db.commit()
        with _jsonl_writer(attempt / 'breakdowns.jsonl') as write_breakdown:
            for row in _ordered(db, 'SELECT * FROM breakdown ORDER BY dimension,label'):
                write_breakdown(dict(zip(('dimension', 'label', 'files', 'bytes',
                    'duplicate_member_files', 'redundant_copies', 'redundant_bytes'), row)))
        if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise RuntimeError('duplicate_audit_database_integrity_failed')
    with db_path.open('rb') as stream:
        os.fsync(stream.fileno())
    relative = str(attempt.relative_to(output_dir))
    report = {'version': VERSION, 'created_at': utcnow(), 'completed': True,
              'source_manifest': identity, 'counts': totals, 'by_kind': by_kind,
              'data_file_duplicate_counts': by_kind['data'],
              'source_files_opened': 0, 'source_files_removed': 0,
              'artifacts': {name: relative + '/' + name for name in (
                  'duplicate_groups.jsonl', 'duplicate_members.jsonl', 'breakdowns.jsonl',
                  'file_identity.sqlite', 'configuration.json', 'errors.jsonl', 'report.json', 'checksums.sha256')},
              'limitations': LIMITATIONS}
    atomic_json(attempt / 'configuration.json', {
        'version': VERSION, 'identity': ['sha256', 'size_bytes'],
        'representative': 'lexicographically_smallest_relative_path', 'kinds': KINDS,
        'maximum_manifest_line_bytes': MAX_MANIFEST_LINE_BYTES,
        'sqlite_cache_kib': 16384, 'sqlite_sorting': 'No temporary sorting B-trees; indices precede inserts.',
        'read_scope': 'Completed source manifest only; caller verifies inventory completion.'})
    atomic_text(attempt / 'errors.jsonl', '')
    atomic_json(attempt / 'report.json', report)
    return report


def audit_source_file_duplicates(manifest_path, output_dir):
    """Stream a completed source manifest into a new, immutable duplicate audit.

    Both paths must be under PIPELINE_ROOT and free of symlinks. A completed
    audit resumes only after checking its input identity and every artifact.
    Interrupted/failed attempts are preserved and a fresh unique attempt is used.
    """
    manifest_path, output_dir = safe_output(manifest_path), safe_output(output_dir)
    if output_dir == manifest_path or output_dir in manifest_path.parents:
        raise ValueError('duplicate_audit_output_must_not_contain_input_manifest')
    if not manifest_path.is_file():
        raise ValueError('completed_source_manifest_missing')
    _guard_tree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    lock_path = safe_output(output_dir / '.audit.lock')
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError('duplicate_audit_already_running') from error
        before = manifest_path.stat()
        identity = {'sha256': sha256_file(manifest_path), 'size_bytes': before.st_size}
        if _fingerprint(manifest_path.stat()) != _fingerprint(before):
            raise ValueError('source_manifest_changed_while_hashing')
        marker = safe_output(output_dir / 'manifest.json')
        if marker.exists():
            stored = json.loads(marker.read_text(encoding='utf-8'))
            if stored.get('version') != VERSION or stored.get('source_manifest') != identity:
                raise ValueError('duplicate_audit_resume_input_or_version_changed')
            if not stored.get('artifacts'):
                raise ValueError('duplicate_audit_resume_manifest_invalid')
            artifact_paths = [item['path'] for item in stored['artifacts']]
            if len(artifact_paths) != len(set(artifact_paths)):
                raise ValueError('duplicate_audit_duplicate_artifact_reference')
            report_reference = PurePosixPath(stored.get('report', ''))
            if (len(report_reference.parts) != 3 or report_reference.parts[0] != 'attempts'
                    or not re.fullmatch('[0-9a-f]{32}', report_reference.parts[1])
                    or report_reference.name != 'report.json'):
                raise ValueError('duplicate_audit_invalid_report_reference')
            expected_names = {'duplicate_groups.jsonl', 'duplicate_members.jsonl', 'breakdowns.jsonl',
                              'file_identity.sqlite', 'configuration.json', 'errors.jsonl',
                              'report.json', 'checksums.sha256'}
            expected_paths = {str(report_reference.parent / name) for name in expected_names}
            if set(artifact_paths) != expected_paths:
                raise ValueError('duplicate_audit_artifact_coverage_changed')
            for item in stored['artifacts']:
                relative = PurePosixPath(item['path'])
                if relative.is_absolute() or '..' in relative.parts:
                    raise ValueError('duplicate_audit_unsafe_artifact_reference')
                path = safe_output(output_dir / relative)
                if not path.is_file() or path.stat().st_size != item['size_bytes'] or sha256_file(path) != item['sha256']:
                    raise ValueError('duplicate_audit_artifact_changed')
            report_path = safe_output(output_dir / stored['report'])
            if stored['report'] not in {item['path'] for item in stored['artifacts']}:
                raise ValueError('duplicate_audit_unchecksummed_report')
            report = json.loads(report_path.read_text(encoding='utf-8'))
            if (report.get('source_manifest') != identity or not report.get('completed')
                    or report.get('version') != VERSION
                    or set(report.get('artifacts', {}).values()) != expected_paths):
                raise ValueError('duplicate_audit_report_identity_mismatch')
            return report
        attempts = safe_output(output_dir / 'attempts')
        attempts.mkdir(exist_ok=True)
        attempt = safe_output(attempts / uuid.uuid4().hex)
        attempt.mkdir()
        try:
            report = _build(manifest_path, attempt, output_dir, identity)
            artifacts = []
            for path in sorted(attempt.iterdir()):
                if not path.is_file():
                    raise ValueError('unexpected_duplicate_audit_artifact')
                safe_output(path)
                artifacts.append({'path': str(path.relative_to(output_dir)),
                                  'size_bytes': path.stat().st_size, 'sha256': sha256_file(path)})
            checksums = safe_output(attempt / 'checksums.sha256')
            atomic_text(checksums, ''.join(item['sha256'] + '  ' + Path(item['path']).name + '\n' for item in artifacts))
            artifacts.append({'path': str(checksums.relative_to(output_dir)),
                              'size_bytes': checksums.stat().st_size, 'sha256': sha256_file(checksums)})
            _sync_directory(attempt)
            _sync_directory(attempts)
            atomic_json(marker, {'version': VERSION, 'source_manifest': identity,
                                'report': report['artifacts']['report.json'], 'artifacts': artifacts})
            return report
        except Exception as error:
            atomic_json(attempt / 'failure.json', {'status': 'processing_error',
                         'error_type': type(error).__name__, 'source_manifest': identity,
                         'reason': 'Duplicate audit did not complete; preserve this attempt and retry after investigation.'})
            raise
    finally:
        os.close(lock_fd)
