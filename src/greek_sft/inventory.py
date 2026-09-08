"""Read-only, resumable corpus inventory and independent byte verification.

Each SQLite shard has a single writer. JSONL accounting uses consecutive physical
row ranges; the range hash commits to the SHA-256 of every unmodified row in order.
Candidate generation must rescan its source row to obtain individual lineage.
Opaque formats explicitly retain unresolved record boundaries.
"""
from __future__ import annotations

import concurrent.futures
import contextlib
import datetime as dt
import hashlib
import heapq
import io
import json
import os
from pathlib import Path
import queue
import re
import sqlite3
import stat
import threading
import multiprocessing
import signal
import time
import tempfile
from collections import Counter

try:
    import orjson
    _loads = orjson.loads
except ImportError:
    _loads = json.loads

VERSION = "inventory-1.0.0"
PIPELINE_ROOT = Path("/datadisk2/greekllm/GreekLLM_sft_pipeline")
BLOCK = 1024 * 1024
_GREEK = re.compile(r"[\u0370-\u03ff\u1f00-\u1fff]")
_LETTERS = re.compile(r"[^\W\d_]", re.UNICODE)
_PII = {
    "email": re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,200}\.[A-Za-z]{2,20}\b"),
    "greek_phone": re.compile(r"(?<!\d)(?:\+30[ .-]?)?(?:69|21|23|26|28)\d{8}(?!\d)"),
    "iban": re.compile(r"\bGR\s?\d{2}(?:\s?[A-Z0-9]){23}\b", re.I),
    "secret": re.compile(r"(?:sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"),
}


from .source_io import open_source_readonly
from .source_scope import validate_source_exclusion, is_source_excluded, validate_source_exclusion_binding
from .zstd_integrity import ZstdFrameIntegrity, is_zstandard_magic, VERSION as ZSTD_INTEGRITY_VERSION

class SourceChangedError(RuntimeError):
    pass


class CompressionIntegrityUpgradeRequired(RuntimeError):
    pass


def _require_current_compression_integrity(report):
    if (report.get('compression') == 'zstandard' or report.get('relative_path', '').lower().endswith('.zst')):
        if report.get('compression_integrity_version') != ZSTD_INTEGRITY_VERSION:
            raise CompressionIntegrityUpgradeRequired('cached_compressed_inventory_requires_explicit_integrity_migration')


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _safe_output(path: Path):
    path = Path(path)
    resolved = path.resolve()
    root = PIPELINE_ROOT.resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError("output_outside_pipeline_root")
    current = path.absolute()
    while current != current.parent:
        if current.is_symlink():
            raise ValueError("symlink_output_component")
        current = current.parent
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def _paths(source: Path, output: Path):
    source = Path(source).resolve(strict=True)
    candidate = Path(output).resolve()
    if not source.is_dir() or candidate == source or source in candidate.parents:
        raise ValueError("unsafe_source_output_relationship")
    output = _safe_output(output)
    _reject_output_links(output)
    return source, output


def _reject_output_links(path):
    # SQLite also follows its journal/WAL/SHM leaf names: reject all existing
    # output links before starting any process or opening a writable artifact.
    for base, directories, files in os.walk(path, followlinks=False):
        for name in (*directories, *files):
            if (Path(base) / name).is_symlink():
                raise ValueError("symlink_in_output_subtree")


def _atomic_json(path: Path, value, *, durable=True):
    path = Path(path)
    _safe_output(path.parent)
    if path.is_symlink():
        raise ValueError("symlink_output_leaf")
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".partial", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as f:
            f.write(_json(value) + "\n")
            f.flush()
            if durable:
                os.fsync(f.fileno())
        os.replace(temporary, path)
        if durable:
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _fingerprint(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


_SCOPE_NAME = 'inventory_scope_amendment.json'
_SCOPE_CHECKSUM_NAME = 'inventory_scope_amendment.sha256.json'


def _read_scope_file(path):
    path = Path(path).absolute()
    root = PIPELINE_ROOT.resolve()
    resolved = path.resolve()
    if root != resolved and root not in resolved.parents:
        raise ValueError('inventory_scope_path_outside_pipeline')
    current = path
    while current != current.parent:
        if current.is_symlink():
            raise ValueError('inventory_scope_symlink_forbidden')
        current = current.parent
    with open_source_readonly(path) as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError('inventory_scope_file_exceeds_limit')
    def strict_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('inventory_scope_duplicate_json_key')
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=strict_object)
    except (UnicodeError, ValueError) as error:
        raise ValueError('inventory_scope_invalid_json') from error
    return value, raw


def validate_inventory_scope(checkpoint, config, *, freeze=False):
    """Validate explicit run-local record scope; read-only unless freeze=True.

    A completed inventory cannot acquire a new amendment. Frozen copies and
    run-local authorization must continue to agree on every resume. A pending
    incomplete inventory may be inspected read-only before its first freeze.
    """
    checkpoint = Path(checkpoint)
    run_file = checkpoint.parent / _SCOPE_NAME
    copy_file = checkpoint / _SCOPE_NAME
    checksum_file = checkpoint / _SCOPE_CHECKSUM_NAME
    present = [path.exists() or path.is_symlink() for path in (run_file, copy_file, checksum_file)]
    if not any(present):
        return None
    if not present[0]:
        raise ValueError('inventory_scope_authorization_removed')
    amendment, raw = _read_scope_file(run_file)
    keys = {'version', 'run_id', 'authorized_at', 'user_instruction', 'excluded_record_roots',
            'deferred_hash_roots', 'mode', 'original_source_hash_requirement_preserved',
            'prior_scanned_records_preserved', 'base_inventory_config_sha256', 'record_coverage_limitation'}
    expected_config = hashlib.sha256(_json(config).encode()).hexdigest()
    if (not isinstance(amendment, dict) or set(amendment) != keys
            or type(amendment['version']) is not int or amendment['version'] != 1
            or amendment['run_id'] != checkpoint.parent.name
            or amendment['user_instruction'] != 'go past greek training'
            or amendment['excluded_record_roots'] != ['greek_training']
            or amendment['deferred_hash_roots'] != ['greek_training']
            or amendment['mode'] != 'hash_only_for_unscanned_files'
            or amendment['original_source_hash_requirement_preserved'] is not True
            or amendment['prior_scanned_records_preserved'] is not True
            or amendment['base_inventory_config_sha256'] != expected_config
            or not isinstance(amendment['record_coverage_limitation'], str)
            or not 1 <= len(amendment['record_coverage_limitation']) <= 2048):
        raise ValueError('inventory_scope_invalid_or_unauthorized_amendment')
    try:
        authorized_at = dt.datetime.fromisoformat(amendment['authorized_at'])
        if authorized_at.tzinfo is None or authorized_at.utcoffset() != dt.timedelta(0):
            raise ValueError('not_utc')
    except (TypeError, ValueError) as error:
        raise ValueError('inventory_scope_invalid_authorization_time') from error
    state_file = checkpoint / 'inventory_state.json'
    if state_file.exists() or state_file.is_symlink():
        existing_state, _ = _read_scope_file(state_file)
        if not isinstance(existing_state, dict) or existing_state.get('config_sha256') != expected_config:
            raise ValueError('inventory_scope_existing_config_state_conflict')
    snapshot_raw = (_json(amendment) + '\n').encode('utf-8')
    identity = {'version': 1, 'run_local_sha256': hashlib.sha256(raw).hexdigest(),
                'checkpoint_sha256': hashlib.sha256(snapshot_raw).hexdigest()}
    complete_file = checkpoint / 'manifest.json'
    complete = complete_file.exists() and _read_scope_file(complete_file)[0].get('complete') is True
    if complete and not (present[1] and present[2]):
        raise ValueError('inventory_scope_cannot_amend_completed_inventory')
    if present[2] and not present[1]:
        raise ValueError('inventory_scope_snapshot_missing')
    if present[1]:
        copied, copied_raw = _read_scope_file(copy_file)
        if copied != amendment or hashlib.sha256(copied_raw).hexdigest() != identity['checkpoint_sha256']:
            raise ValueError('inventory_scope_snapshot_or_authorization_changed')
    if present[2]:
        stored, _ = _read_scope_file(checksum_file)
        if stored != identity:
            raise ValueError('inventory_scope_resume_identity_changed')
    if freeze:
        if not present[1]:
            _atomic_json(copy_file, amendment)
        if not present[2]:
            _atomic_json(checksum_file, identity)
        present[1] = present[2] = True
    return {'amendment': amendment, 'sha256': identity['checkpoint_sha256'],
            'run_local_sha256': identity['run_local_sha256'], 'artifact': _SCOPE_NAME,
            'checksum_artifact': _SCOPE_CHECKSUM_NAME, 'frozen': present[1] and present[2]}


class InventoryScopeConflict(RuntimeError):
    pass


def _require_current_record_scope(report, scope):
    if 'inventory_scope_amendment_sha256' in report or report.get('record_assessment_skipped'):
        if not scope or report.get('inventory_scope_amendment_sha256') != scope['sha256']:
            raise InventoryScopeConflict('cached_excluded_record_scope_missing_or_changed')


def _record_scope_excluded(relative, scope):
    parts = Path(relative).parts
    return bool(scope and len(parts) > 1 and parts[0] in scope['amendment']['excluded_record_roots'])


def _walk(source: Path, deferred_roots=(), source_exclusion=None):
    """Do not follow links; account links separately from regular source files."""
    def failed(error):
        raise OSError("source_directory_unreadable") from error
    for base, dirs, files in os.walk(source, followlinks=False, onerror=failed):
        relative_base = Path(base).relative_to(source)
        dirs[:] = [name for name in dirs if not is_source_excluded(str(relative_base / name), source_exclusion)]
        dirs.sort(key=lambda name: (Path(base) == source and name in deferred_roots, name))
        for name in sorted(files):
            path = Path(base) / name
            if is_source_excluded(str(path.relative_to(source)), source_exclusion):
                continue
            s = path.lstat()
            if stat.S_ISREG(s.st_mode):
                yield path, str(path.relative_to(source)), s


def _family(relative):
    parts = Path(relative).parts
    if len(parts) == 1:
        return "_root"
    if parts[0] in {"common_corpus", "greek_dialects", "greekllm_additional", "phd-theses-corpus"} and len(parts) > 2:
        return "/".join(parts[:2])
    return parts[0]


def _artifact(relative):
    parts = Path(relative).parts
    if parts[0] in {".hf_cache", ".claude", "00aa_tools", "greek_training", "greek_training_temp"}:
        return "preexisting_pipeline_cache_or_tool_artifact"
    if ".git" in parts or "__pycache__" in parts:
        return "repository_or_bytecode_artifact"
    name = parts[-1]
    if name.endswith((".meta", ".idx")) or name == "dataset_dict.jsonl":
        return "source_sidecar_metadata"
    if name.endswith((".md", ".py", ".pyc", ".sh", ".yaml", ".yml", ".log", ".paths", ".sample")):
        return "documentation_code_or_log_artifact"
    return None


class _HashingReader(io.RawIOBase):
    def __init__(self, raw, progress=None, observer=None):
        self.raw = raw
        self.progress = progress
        self.observer = observer
        self.digest = hashlib.sha256()
        self.bytes_read = 0

    def readable(self):
        return True

    def readinto(self, buffer):
        n = self.raw.readinto(buffer)
        if n:
            self.digest.update(memoryview(buffer)[:n])
            self.bytes_read += n
            if self.observer is not None:
                self.observer.feed(memoryview(buffer)[:n])
            if self.progress is not None:
                self.progress(self.bytes_read)
        return n


def _connect(path):
    conn = sqlite3.connect(path, timeout=60)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS files (
          relative_path TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,
          report TEXT NOT NULL, completed INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS record_ranges (
          relative_path TEXT NOT NULL, first_record INTEGER NOT NULL,
          last_record INTEGER NOT NULL, status TEXT NOT NULL, reason TEXT NOT NULL,
          row_hash_chain TEXT NOT NULL,
          PRIMARY KEY(relative_path,first_record));
    """)
    return conn


def _texts(obj):
    stack = [obj]
    while stack:
        value = stack.pop()
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            stack.extend(value.values())
        elif isinstance(value, list):
            stack.extend(value)


def _inspect_record(obj, counts, schemas):
    if not isinstance(obj, dict):
        counts["non_object_records"] += 1
        return "quarantined", "unsupported_non_object_schema"
    schema = _json({str(k): type(v).__name__ for k, v in obj.items()})
    digest = hashlib.sha256(schema.encode()).hexdigest()
    if digest in schemas or len(schemas) < 256:
        entry = schemas.setdefault(digest, {"fields": json.loads(schema), "count": 0})
        entry["count"] += 1
    else:
        counts["schema_variants_beyond_report_limit"] += 1
    flags = set()
    greek = letters = 0
    for value in _texts(obj):
        for name, expression in _PII.items():
            if name not in flags and expression.search(value):
                flags.add(name)
        # This is explicitly a language screen, not a fluency/grammar claim.
        probe = value[:4096] + (value[-4096:] if len(value) > 4096 else "")
        greek += len(_GREEK.findall(probe))
        letters += len(_LETTERS.findall(probe))
    for flag in flags:
        counts["risk_" + flag + "_records"] += 1
    if flags:
        counts["pii_or_secret_flagged_records"] += 1
    if letters and greek / letters >= .5:
        counts["greek_screen_positive_records"] += 1
    elif letters:
        counts["greek_screen_negative_records"] += 1
    else:
        counts["language_unknown_records"] += 1
    # No source license is established merely by inspecting an upstream string.
    return "license_blocked", "license_not_verified_for_sft_redistribution"


def _scan(path, relative, before, conn, config, progress=None, scope_amendment=None):
    maximum = int(config.get("inventory_max_record_bytes", config.get("max_record_bytes", 64 * 1024 * 1024)))
    json_maximum = int(config.get("max_json_bytes", maximum))
    range_limit = int(config.get("inventory_range_records", 10000))
    report = {"relative_path": relative, "family": _family(relative),
              "size_bytes": before.st_size, "format": "opaque", "encoding": "binary_or_unknown",
              "record_count": 0, "record_boundary_complete": False,
              "status": "unsupported", "reason": "unsupported_format_record_boundaries_unresolved",
              "stats": {}, "schema_variants": {}, "inventory_version": VERSION}
    artifact = _artifact(relative)
    excluded = _record_scope_excluded(relative, scope_amendment)
    counts = Counter()
    schemas = {}
    with open_source_readonly(path, buffering=0) as raw:
        if _fingerprint(os.fstat(raw.fileno())) != _fingerprint(before):
            raise SourceChangedError("source_changed_before_read:" + relative)
        heartbeat_rows = 0
        def on_read(bytes_read):
            if progress is not None:
                progress(bytes_read, heartbeat_rows)
        lower = relative.lower()
        integrity = ZstdFrameIntegrity() if lower.endswith('.zst') else None
        hashed = _HashingReader(raw, on_read, integrity)
        buffered = io.BufferedReader(hashed, BLOCK)
        initial = buffered.peek(4)
        magic = initial[:4]
        if is_zstandard_magic(magic) and integrity is None:
            # peek has not consumed input: attach the checker to the exact raw
            # prefix already hashed, then observe every subsequent raw read.
            if len(initial) != hashed.bytes_read:
                raise RuntimeError('zstandard_initial_hash_observer_prefix_mismatch')
            integrity = ZstdFrameIntegrity()
            integrity.feed(initial)
            hashed.observer = integrity
        stream = buffered
        zstream = None
        lower = relative.lower()
        is_jsonl = lower.endswith((".jsonl", ".jsonl.zst", ".qjsonl.zst"))
        is_json = lower.endswith((".json", ".meta", ".idx"))
        parse_error = None
        if is_zstandard_magic(magic):
            report["compression"] = "zstandard"
            if is_jsonl and not excluded:
                try:
                    import zstandard
                    zstream = zstandard.ZstdDecompressor().stream_reader(buffered, closefd=False, read_across_frames=True)
                    stream = io.BufferedReader(zstream, BLOCK)
                except Exception:
                    parse_error = "zstandard_decoder_unavailable"
        elif lower.endswith(".zst"):
            parse_error = "invalid_zstandard_magic"
        if is_jsonl and magic.startswith((b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff")):
            report["encoding"] = "utf-32" if magic in (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff") else "utf-16"
            parse_error = "unsupported_multibyte_record_delimiter"
        first = last = 0
        current_status = current_reason = None
        chain = hashlib.sha256()
        ranges = []

        def flush_range():
            if first:
                ranges.append((relative, first, last, current_status, current_reason, chain.hexdigest()))
            if len(ranges) >= 1000:
                conn.executemany("INSERT INTO record_ranges VALUES (?,?,?,?,?,?)", ranges)
                ranges.clear()

        def account(number, row_hash, status, reason):
            nonlocal first, last, current_status, current_reason, chain
            if first and (status != current_status or reason != current_reason or last - first + 1 >= range_limit):
                flush_range()
                first = 0
            if not first:
                first = number
                current_status, current_reason = status, reason
                chain = hashlib.sha256()
            last = number
            chain.update(bytes.fromhex(row_hash))
            counts["status_" + status] += 1
            counts["reason_" + reason] += 1

        try:
            if parse_error and not excluded:
                raise ValueError(parse_error)
            if excluded:
                report.update(status='unsupported', reason='user_requested_intermediate_data_exclusion',
                    record_assessment_skipped=True,
                    record_assessment_exclusion_reason='user_requested_intermediate_data_exclusion',
                    record_count_scope='identified_record_lower_bound_only; total_records_unassessed_by_user_scope',
                    total_record_count=None,
                    record_assessments={'json_parsing': 'not_assessed', 'decompression': 'not_assessed',
                        'language': 'not_assessed', 'pii': 'not_assessed', 'decoded_payload_checksum': 'not_assessed'},
                    generation_eligible=False, inventory_scope_amendment_sha256=scope_amendment['sha256'])
                counts['user_excluded_record_assessment_files'] += 1
                counts['unassessed_record_count_files'] += 1
            elif is_jsonl:
                report["format"] = "jsonl"
                report["encoding"] = "utf-8"
                number = 0
                while True:
                    line = stream.readline(maximum + 1)
                    if not line:
                        break
                    number += 1
                    heartbeat_rows = number
                    if number % 1000 == 0 and progress is not None:
                        progress(hashed.bytes_read, number)
                    row_hash = hashlib.sha256(line)
                    oversized = len(line) > maximum
                    if oversized and not line.endswith(b"\n"):
                        while True:
                            remainder = stream.readline(BLOCK)
                            row_hash.update(remainder)
                            if not remainder or remainder.endswith(b"\n"):
                                break
                    if oversized:
                        status, reason = "quarantined", "record_exceeds_safe_parse_limit"
                    else:
                        try:
                            text = line.decode("utf-8-sig" if number == 1 else "utf-8", errors="strict")
                        except UnicodeDecodeError:
                            counts["invalid_utf8_records"] += 1
                            status, reason = "malformed", "invalid_utf8"
                        else:
                            try:
                                obj = _loads(text)
                            except (ValueError, RecursionError):
                                status, reason = "malformed", "blank_physical_row" if not text.strip() else "invalid_json"
                            else:
                                if artifact:
                                    status, reason = "unsupported", artifact
                                    counts["risk_assessment_excluded_artifact_records"] += 1
                                    if not schemas and isinstance(obj, dict):
                                        fields = {str(k): type(v).__name__ for k, v in obj.items()}
                                        schema_hash = hashlib.sha256(_json(fields).encode()).hexdigest()
                                        schemas[schema_hash] = {"fields": fields, "count": 1, "scope": "first_parsed_artifact_record_only"}
                                else:
                                    status, reason = _inspect_record(obj, counts, schemas)
                    account(number, row_hash.hexdigest(), status, reason)
                report["record_count"] = number
                report["record_boundary_complete"] = True
                if counts["invalid_utf8_records"]:
                    report["encoding"] = "mixed_or_invalid_utf8"
            elif is_json:
                report["format"] = "json_document"
                payload = stream.read(json_maximum + 1)
                if len(payload) > json_maximum:
                    report["reason"] = "json_document_exceeds_safe_parse_limit"
                else:
                    report["record_count"] = 1 if payload else 0
                    report["record_boundary_complete"] = True
                    report["encoding"] = "utf-8"
                    if payload:
                        try:
                            obj = _loads(payload.decode("utf-8-sig"))
                            status, reason = _inspect_record(obj, counts, schemas)
                            if artifact:
                                status, reason = "unsupported", artifact
                        except UnicodeDecodeError:
                            report["encoding"] = "invalid_utf8"
                            status, reason = "malformed", "invalid_utf8"
                        except (ValueError, RecursionError):
                            status, reason = "malformed", "invalid_json_document"
                        account(1, hashlib.sha256(payload).hexdigest(), status, reason)
                        if isinstance(locals().get("obj"), list):
                            report["json_array_elements"] = len(obj)
                            report["record_unit"] = "whole_json_document_including_all_array_elements"
        except SourceChangedError:
            raise
        except Exception as error:
            # Never persist exception text, which may contain raw private content.
            report["status"] = "processing_error"
            report["reason"] = parse_error or "decoder_or_parser_failure_" + type(error).__name__
            report["record_boundary_complete"] = False
            report["record_count"] = sum(v for k, v in counts.items() if k.startswith("status_"))
        finally:
            flush_range()
            if ranges:
                conn.executemany("INSERT INTO record_ranges VALUES (?,?,?,?,?,?)", ranges)
            # Hash unread compressed or opaque bytes even after a parse failure.
            while buffered.read(BLOCK):
                pass
            after = os.fstat(raw.fileno())
            if _fingerprint(before) != _fingerprint(after) or _fingerprint(path.lstat()) != _fingerprint(before):
                raise SourceChangedError("source_changed_during_read:" + relative)
            if hashed.bytes_read != before.st_size:
                raise SourceChangedError("source_size_disagrees_with_read:" + relative)
            report["sha256"] = hashed.digest.hexdigest()
            if integrity is not None:
                checked = integrity.finish()
                checked['native_decoder_reached_eof'] = bool(zstream is not None and report['record_boundary_complete'])
                report['compression_integrity_version'] = ZSTD_INTEGRITY_VERSION
                report['compression_integrity'] = checked
                if checked['bytes_observed'] != hashed.bytes_read:
                    raise RuntimeError('zstandard_integrity_hash_byte_coverage_mismatch')
                if not checked['framing_complete']:
                    if report['status'] == 'processing_error':
                        checked['decoder_or_parser_failure_reason'] = report['reason']
                    report['status'] = 'processing_error'
                    report['reason'] = checked['error']
                    report['record_boundary_complete'] = False
                    report['record_count'] = sum(v for k, v in counts.items() if k.startswith('status_'))
            if zstream is not None:
                zstream.close()
        report["stats"] = dict(counts)
        report["schema_variants"] = schemas
        if report["status"] != "processing_error" and report["record_boundary_complete"]:
            if artifact:
                report["status"], report["reason"] = "unsupported", artifact
            elif counts["status_malformed"]:
                report["status"], report["reason"] = "quarantined", "contains_malformed_records"
            elif counts["status_quarantined"]:
                report["status"], report["reason"] = "quarantined", "contains_unsupported_records"
            else:
                report["status"], report["reason"] = "license_blocked", "license_not_verified_for_sft_redistribution"
        report["stat_fingerprint"] = _fingerprint(before)
    return report


def _iter_database(path):
    conn = sqlite3.connect("file:" + str(path) + "?mode=ro", uri=True)
    try:
        for relative, report in conn.execute("SELECT relative_path,report FROM files WHERE completed=1 ORDER BY relative_path"):
            yield relative, report
    finally:
        conn.close()


def _exclusion_sql(exclusion):
    roots = sorted(set(exclusion['amendment']['excluded_source_roots']))
    if not roots or any(not root or root.startswith('/') or '..' in Path(root).parts
                        or root.endswith('/') for root in roots):
        raise InventoryScopeConflict('invalid_source_exclusion_roots')
    roots = [root for root in roots if not any(root.startswith(other + '/') for other in roots if other != root)]
    # substr equality treats SQL/GLOB metacharacters literally and honors path boundaries.
    condition = '(' + ' OR '.join('(relative_path=? OR substr(relative_path,1,?)=?)' for _ in roots) + ')'
    parameters = tuple(value for root in roots for value in (root, len(root) + 1, root + '/'))
    return condition, parameters


def _write_source_exclusion_ledger(checkpoint, workers, exclusion, manifest_sha256, ledger_checkpoint=None):
    import uuid
    ledger_checkpoint = Path(ledger_checkpoint) if ledger_checkpoint is not None else checkpoint
    directory = _safe_output(ledger_checkpoint / 'source_exclusion_ledgers' / uuid.uuid4().hex)
    files_path, ranges_path = directory / 'files.jsonl', directory / 'record_ranges.jsonl'
    counts = Counter({key: 0 for key in ('historical_excluded_files', 'historical_excluded_bytes',
        'historical_excluded_identified_records', 'historical_excluded_record_ranges', 'historical_excluded_records_in_ranges')})
    condition, parameters = _exclusion_sql(exclusion)
    with files_path.open('x', encoding='utf-8') as files, ranges_path.open('x', encoding='utf-8') as ranges:
        for index in range(workers):
            shard = checkpoint / f'inventory_shard_{index:02d}.sqlite'
            with contextlib.closing(sqlite3.connect('file:' + str(shard.resolve()) + '?mode=ro', uri=True)) as db:
                for relative, value in db.execute('SELECT relative_path,report FROM files WHERE completed=1 AND ' + condition + ' ORDER BY relative_path', parameters):
                    report = json.loads(value)
                    counts['historical_excluded_files'] += 1
                    counts['historical_excluded_bytes'] += report['size_bytes']
                    counts['historical_excluded_identified_records'] += report['record_count']
                    files.write(_json({'source_file': relative, 'inventory_shard': shard.name,
                        'historical_report_json_sha256': hashlib.sha256(value.encode()).hexdigest(),
                        'historical_report': report, 'source_exclusion_amendment_sha256': exclusion['sha256'],
                        'current_sha256': None, 'current_size_bytes': None,
                        'current_coverage': 'unknown_due_to_user_approved_source_exclusion'}) + '\n')
                query = ('SELECT relative_path,first_record,last_record,status,reason,row_hash_chain '
                         'FROM record_ranges WHERE ' + condition + ' ORDER BY relative_path,first_record')
                for values in db.execute(query, parameters):
                    record = dict(zip(('relative_path', 'first_record', 'last_record', 'status', 'reason', 'row_hash_chain'), values))
                    record['inventory_shard'] = shard.name
                    counts['historical_excluded_record_ranges'] += 1
                    counts['historical_excluded_records_in_ranges'] += record['last_record'] - record['first_record'] + 1
                    ranges.write(_json(record) + '\n')
        for stream in (files, ranges):
            stream.flush()
            os.fsync(stream.fileno())
    if counts['historical_excluded_identified_records'] != counts['historical_excluded_records_in_ranges']:
        raise InventoryScopeConflict('historical_excluded_record_ranges_do_not_reconcile')
    checksums = {}
    for path in (files_path, ranges_path):
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(BLOCK), b''):
                digest.update(block)
        checksums[path.name] = {'sha256': digest.hexdigest(), 'size_bytes': path.stat().st_size}
    checksum_path = directory / 'checksums.json'
    _atomic_json(checksum_path, {'version': 1, 'source_exclusion_amendment_sha256': exclusion['sha256'],
        'source_manifest_sha256': manifest_sha256, 'artifacts': checksums, 'counts': dict(counts)})
    return {'artifacts': {p.name: str(p.relative_to(ledger_checkpoint)) for p in (files_path, ranges_path, checksum_path)},
            'checksums_sha256': hashlib.sha256(checksum_path.read_bytes()).hexdigest(), 'counts': dict(counts)}


def _summarize(checkpoint, workers, config, scope_amendment=None, source_exclusion=None):
    stats = Counter()
    if source_exclusion:
        stats.update({prefix + suffix: 0 for prefix in ('historical_excluded_', 'in_scope_')
                      for suffix in ('files', 'bytes', 'identified_records')})
    families = {}
    manifest = checkpoint / "source_manifest.jsonl"
    tmp = manifest.with_suffix(".jsonl.partial")
    digest = hashlib.sha256()
    merged = heapq.merge(*[_iter_database(checkpoint / f"inventory_shard_{i:02d}.sqlite") for i in range(workers)])
    with tmp.open("wb") as f:
        for relative, value in merged:
            record = json.loads(value)
            _require_current_record_scope(record, scope_amendment)
            validate_source_exclusion_binding(record, source_exclusion)
            if source_exclusion:
                prefix = 'historical_excluded_' if is_source_excluded(relative, source_exclusion) else 'in_scope_'
                stats[prefix + 'files'] += 1
                stats[prefix + 'bytes'] += record['size_bytes']
                stats[prefix + 'identified_records'] += record['record_count']
            encoded = (value + "\n").encode("utf-8")
            f.write(encoded)
            digest.update(encoded)
            stats["files"] += 1
            stats["bytes"] += record["size_bytes"]
            stats["records"] += record["record_count"]
            stats["file_status_" + record["status"]] += 1
            if not record["record_boundary_complete"]:
                stats["files_with_unresolved_record_boundaries"] += 1
            family = families.setdefault(record["family"], Counter())
            family["files"] += 1
            family["bytes"] += record["size_bytes"]
            family["records"] += record["record_count"]
            family["file_status_" + record["status"]] += 1
            for key, count in record["stats"].items():
                stats[key] += count
                family[key] += count
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, manifest)
    summary = {"version": VERSION, "completed_at": _utc(), "workers": workers,
               "manifest_sha256": digest.hexdigest(), "statistics": dict(stats),
               "commit_batch_files": config.get("inventory_commit_files", 256),
               "families": {k: dict(v) for k, v in sorted(families.items())},
               "record_accounting": "every_physical_jsonl_row; one_whole_json_document; opaque_boundaries_unresolved",
               "row_hash_commitment": "SHA256(concatenated_binary_SHA256_of_each_unmodified_row_in_range)",
               "language_method": "Unicode Greek letter ratio over bounded per-field samples; not grammar validation",
               "privacy_method": "full-string heuristic email/Greek-phone/IBAN/common-secret screening; human assessment unresolved"}
    if scope_amendment:
        summary['record_accounting'] = ('every_physical_jsonl_row_for_record_assessed_files; one_whole_json_document; '
            'opaque_boundaries_unresolved; user_excluded_files_have_only_identified_record_lower_bounds_with_total_records_unassessed')
        summary['language_method'] += '; user-excluded record content is unassessed'
        summary['privacy_method'] += '; user-excluded record content is unassessed'
    summary['inventory_scope_amendment'] = scope_amendment
    summary['source_exclusion_amendment'] = source_exclusion
    if source_exclusion:
        ledger = _write_source_exclusion_ledger(checkpoint, workers, source_exclusion, digest.hexdigest())
        for key in ('historical_excluded_files', 'historical_excluded_bytes', 'historical_excluded_identified_records'):
            if ledger['counts'].get(key, 0) != stats[key]:
                raise InventoryScopeConflict('historical_excluded_ledger_count_mismatch')
        summary['source_exclusion_accounting'] = {**ledger, 'current_excluded_coverage': 'unknown',
            'current_excluded_files': None, 'current_excluded_bytes': None, 'current_excluded_records': None,
            'full_original_source_integrity': False, 'historical_baselines_preserved': True}
        summary['full_original_source_integrity'] = False
        summary['record_accounting'] += '; excluded Git subtree retains historical baseline rows only; current coverage unknown'
    _atomic_json(checkpoint / "statistics.json", summary)
    _atomic_json(checkpoint / "checksums.json", {"source_manifest.jsonl": digest.hexdigest()})
    _atomic_json(checkpoint / "configuration_snapshot.json", config)
    completion = {"pass": 1, "complete": True, "statistics": "statistics.json", "source_manifest": "source_manifest.jsonl", "source_manifest_sha256": digest.hexdigest()}
    if source_exclusion:
        completion["source_exclusion_amendment_sha256"] = source_exclusion["sha256"]
    _atomic_json(checkpoint / "manifest.json", completion)
    return summary


def run_inventory(source_root: Path, checkpoint_dir: Path, config: dict) -> dict:
    """Inventory all regular files, resuming only durable completed file units."""
    source, checkpoint = _paths(source_root, checkpoint_dir)
    commit_batch_files = config.get("inventory_commit_files", 256)
    if type(commit_batch_files) is not int or commit_batch_files <= 0:
        raise ValueError("inventory_commit_files_must_be_positive_integer")
    workers = min(4, max(1, int(config.get("inventory_workers", config.get("workers", 4)))))
    import fcntl
    with (checkpoint / ".inventory.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        scope_amendment = validate_inventory_scope(checkpoint, config, freeze=True)
        source_exclusion = validate_source_exclusion(checkpoint, config, freeze=True)
        complete = checkpoint / "manifest.json"
        if complete.exists():
            manifest = json.loads(complete.read_text())
            if manifest.get("complete"):
                if manifest.get('source_exclusion_amendment_sha256') != (source_exclusion['sha256'] if source_exclusion else None):
                    raise InventoryScopeConflict('completed_inventory_requires_scope_reconciliation')
                actual = hashlib.sha256()
                with (checkpoint / "source_manifest.jsonl").open("rb") as f:
                    for line in f:
                        actual.update(line)
                        entry = _loads(line)
                        if not is_source_excluded(entry["relative_path"], source_exclusion):
                            _require_current_compression_integrity(entry)
                        validate_source_exclusion_binding(entry, source_exclusion)
                        _require_current_record_scope(entry, scope_amendment)
                if actual.hexdigest() != manifest["source_manifest_sha256"]:
                    raise ValueError("immutable_inventory_manifest_changed")
                return json.loads((checkpoint / "statistics.json").read_text())
        state_path = checkpoint / "inventory_state.json"
        state = {"version": VERSION, "workers": workers, "source_root": str(source), "config_sha256": hashlib.sha256(_json(config).encode()).hexdigest()}
        if state_path.exists() and json.loads(state_path.read_text()) != state:
            raise ValueError("inventory_resume_configuration_conflict")
        if not state_path.exists():
            _atomic_json(state_path, state)
        # Fork only before any feeder threads start. This pipeline is POSIX-only
        # (fcntl/O_NOFOLLOW are source-protection requirements). Separate processes
        # avoid the GIL during JSON parsing, Unicode screening and record hashing.
        context = multiprocessing.get_context("fork")
        queues = [context.Queue(maxsize=64) for _ in range(workers)]
        stop = context.Event()
        worker_errors = context.Queue()
        errors = []

        def worker(index):
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            conn = None
            processed = resumed = 0
            last_heartbeat = 0.0
            current = {}
            def heartbeat(bytes_read=0, records=0, force=False, phase="reading"):
                nonlocal last_heartbeat
                now = time.monotonic()
                if force or now - last_heartbeat >= 5.0:
                    _atomic_json(checkpoint / f"worker_{index:02d}_heartbeat.json", {
                        "worker": index, "pid": os.getpid(), "at": _utc(),
                        "phase": phase, "files_processed_this_attempt": processed,
                        "files_resumed_this_attempt": resumed,
                        "raw_bytes_hashed_current_file": bytes_read,
                        "records_seen_current_file": records, **current}, durable=False)
                    last_heartbeat = time.monotonic()
            try:
                conn = _connect(checkpoint / f"inventory_shard_{index:02d}.sqlite")
                while not stop.is_set():
                    try:
                        item = queues[index].get(timeout=.2)
                    except queue.Empty:
                        continue
                    if item is None:
                        break
                    path, relative, before = item
                    current = {"relative_path": relative, "size_bytes": before.st_size}
                    old = conn.execute("SELECT fingerprint,completed,report FROM files WHERE relative_path=?", (relative,)).fetchone()
                    if old and old[1]:
                        if json.loads(old[0]) != _fingerprint(before):
                            raise SourceChangedError("source_changed_since_checkpoint:" + relative)
                        if relative.lower().endswith('.zst') or '"compression"' in old[2]:
                            _require_current_compression_integrity(_loads(old[2]))
                        if '"inventory_scope_amendment_sha256"' in old[2] or '"record_assessment_skipped"' in old[2]:
                            _require_current_record_scope(_loads(old[2]), scope_amendment)
                        if '"source_exclusion_amendment_sha256"' in old[2]:
                            validate_source_exclusion_binding(_loads(old[2]), source_exclusion)
                        resumed += 1
                        heartbeat(force=False, phase="resuming")
                        continue
                    heartbeat()
                    if not conn.in_transaction:
                        conn.execute("BEGIN")
                    conn.execute("DELETE FROM record_ranges WHERE relative_path=?", (relative,))
                    report = _scan(path, relative, before, conn, config, heartbeat, scope_amendment=scope_amendment)
                    if source_exclusion:
                        report["source_exclusion_amendment_sha256"] = source_exclusion["sha256"]
                    conn.execute("INSERT OR REPLACE INTO files VALUES (?,?,?,1)", (relative, _json(_fingerprint(before)), _json(report)))
                    processed += 1
                    if processed % commit_batch_files == 0 or before.st_size >= 64 * 1024 * 1024:
                        conn.commit()
                    heartbeat(before.st_size, report["record_count"], phase="file_processed")
                    if report["status"] == "processing_error":
                        with (checkpoint / f"errors_{index:02d}.jsonl").open("a", encoding="utf-8") as error_log:
                            error_log.write(_json({"relative_path": relative, "reason": report["reason"]}) + "\n")
                if not stop.is_set():
                    conn.commit()
                    current = {}
                    heartbeat(force=True, phase="complete")
            except BaseException as error:
                if conn is not None:
                    conn.rollback()
                # Transfer sanitized exception identity; never source payload text.
                worker_errors.put((type(error).__name__, str(error) if isinstance(error, SourceChangedError) else type(error).__name__))
                worker_errors.close()
                worker_errors.join_thread()
                stop.set()
            finally:
                if conn is not None:
                    conn.close()

        processes = [context.Process(target=worker, args=(i,), name=f"sft-inventory-{i:02d}") for i in range(workers)]
        for process in processes:
            process.start()
        discovered = 0
        previous_handler = signal.getsignal(signal.SIGTERM)
        def interrupted(signum, frame):
            stop.set()
            raise RuntimeError("inventory_interrupted_resume_same_run")
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGTERM, interrupted)
        def check_workers():
            for process in processes:
                if process.exitcode not in (None, 0):
                    errors.append(RuntimeError("inventory_worker_terminated_" + str(process.exitcode)))
                    stop.set()
                    break
        try:
            deferred_roots = scope_amendment['amendment']['deferred_hash_roots'] if scope_amendment else ()
            for item in _walk(source, deferred_roots=deferred_roots, source_exclusion=source_exclusion):
                check_workers()
                if stop.is_set():
                    break
                index = int.from_bytes(hashlib.sha256(item[1].encode()).digest()[:4], "big") % workers
                while not stop.is_set():
                    try:
                        queues[index].put(item, timeout=.2)
                        discovered += 1
                        break
                    except queue.Full:
                        check_workers()
                if discovered % 10000 == 0:
                    _atomic_json(checkpoint / "progress.json", {"discovered_files": discovered, "at": _utc(), "phase": "inventory", "worker_pids": [p.pid for p in processes], "execution": "multiprocessing"}, durable=False)
            if not stop.is_set():
                for q in queues:
                    while not stop.is_set():
                        try:
                            q.put(None, timeout=.2)
                            break
                        except queue.Full:
                            check_workers()
            while not stop.is_set() and any(p.is_alive() for p in processes):
                for process in processes:
                    process.join(timeout=.2)
                check_workers()
        except BaseException as error:
            errors.append(error)
            stop.set()
        finally:
            if stop.is_set():
                # In-flight SQLite transactions roll back; previously committed
                # file units remain reusable. No source descriptor was writable.
                for process in processes:
                    if process.is_alive():
                        process.terminate()
            for process in processes:
                process.join()
            if threading.current_thread() is threading.main_thread():
                signal.signal(signal.SIGTERM, previous_handler)
            while True:
                try:
                    kind, reason = worker_errors.get_nowait()
                    errors.append(SourceChangedError(reason) if kind == "SourceChangedError" else RuntimeError(reason))
                except queue.Empty:
                    break
            if stop.is_set() and not errors:
                errors.append(RuntimeError("inventory_worker_failed"))
            for q in [*queues, worker_errors]:
                q.cancel_join_thread()
                q.close()
        if errors:
            _atomic_json(checkpoint / "fatal_error.json", {"type": type(errors[0]).__name__, "at": _utc()})
            raise errors[0]
        stored_files = 0
        for i in range(workers):
            with contextlib.closing(sqlite3.connect(checkpoint / f"inventory_shard_{i:02d}.sqlite")) as conn:
                if source_exclusion:
                    condition, parameters = _exclusion_sql(source_exclusion)
                    stored_files += conn.execute('SELECT COUNT(*) FROM files WHERE completed=1 AND NOT ' + condition,
                        parameters).fetchone()[0]
                else:
                    stored_files += conn.execute("SELECT COUNT(*) FROM files WHERE completed=1").fetchone()[0]
        if stored_files != discovered:
            raise SourceChangedError("source_file_set_changed_since_partial_inventory")
        return _summarize(checkpoint, workers, config, scope_amendment, source_exclusion)


def verify_source_hashes(source_root: Path, checkpoint_dir: Path, verification_dir: Path, config: dict) -> dict:
    """Independently hash every original byte and check the complete regular-file set."""
    source, output = _paths(source_root, verification_dir)
    checkpoint = Path(checkpoint_dir).resolve(strict=True)
    manifest_path = checkpoint / "source_manifest.jsonl"
    if not manifest_path.is_file():
        raise ValueError("inventory_manifest_missing")
    expected_manifest_sha = json.loads((checkpoint / "manifest.json").read_text())["source_manifest_sha256"]
    manifest_digest = hashlib.sha256()
    with manifest_path.open("rb") as f:
        for block in iter(lambda: f.read(BLOCK), b""):
            manifest_digest.update(block)
    if manifest_digest.hexdigest() != expected_manifest_sha:
        raise ValueError("immutable_inventory_manifest_changed")
    db = sqlite3.connect(output / "verification.sqlite")
    db.execute("PRAGMA temp_store=MEMORY")
    db.execute("CREATE TABLE IF NOT EXISTS expected(relative_path TEXT PRIMARY KEY,sha256 TEXT,size_bytes INTEGER,seen INTEGER DEFAULT 0)")
    db.execute("DELETE FROM expected")
    with manifest_path.open(encoding="utf-8") as f:
        for line in f:
            record = json.loads(line)
            db.execute("INSERT INTO expected(relative_path,sha256,size_bytes) VALUES(?,?,?)", (record["relative_path"], record["sha256"], record["size_bytes"]))
    db.commit()
    counts = Counter()
    tmp = output / "source_hashes_after.jsonl.partial"

    def hash_item(item):
        path, relative, before = item
        digest = hashlib.sha256()
        with open_source_readonly(path) as f:
            if _fingerprint(os.fstat(f.fileno())) != _fingerprint(before):
                raise SourceChangedError("source_changed_before_verification:" + relative)
            for block in iter(lambda: f.read(BLOCK), b""):
                digest.update(block)
            if _fingerprint(os.fstat(f.fileno())) != _fingerprint(before) or _fingerprint(path.lstat()) != _fingerprint(before):
                raise SourceChangedError("source_changed_during_verification:" + relative)
        return relative, digest.hexdigest(), before.st_size

    workers = min(4, max(1, int(config.get("inventory_workers", config.get("workers", 4)))))
    with tmp.open("w", encoding="utf-8") as results, concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        pending = set()

        def collect(done):
            for future in done:
                relative, digest, size = future.result()
                expected = db.execute("SELECT sha256,size_bytes FROM expected WHERE relative_path=?", (relative,)).fetchone()
                status = "added" if expected is None else "unchanged" if expected == (digest, size) else "changed"
                db.execute("UPDATE expected SET seen=1 WHERE relative_path=?", (relative,))
                counts[status] += 1
                counts["files"] += 1
                counts["bytes"] += size
                results.write(_json({"relative_path": relative, "sha256": digest, "size_bytes": size, "status": status}) + "\n")
                if counts["files"] % 10000 == 0:
                    db.commit()
                    _atomic_json(output / "progress.json", {**dict(counts), "at": _utc()})

        for item in _walk(source):
            pending.add(executor.submit(hash_item, item))
            if len(pending) >= workers * 4:
                done, pending = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)
                collect(done)
        while pending:
            done, pending = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)
            collect(done)
        for (relative,) in db.execute("SELECT relative_path FROM expected WHERE seen=0"):
            counts["removed"] += 1
            results.write(_json({"relative_path": relative, "status": "removed"}) + "\n")
        results.flush()
        os.fsync(results.fileno())
    db.commit()
    db.close()
    os.replace(tmp, output / "source_hashes_after.jsonl")
    passed = not any(counts[k] for k in ("added", "removed", "changed"))
    report = {"passed": passed, "statistics": dict(counts), "completed_at": _utc(), "method": "independent full raw-byte SHA-256"}
    _atomic_json(output / "source_integrity.json", report)
    if not passed:
        raise SourceChangedError("source_hash_or_file_set_changed_release_blocked")
    return report
