"""Fail-fast independent verification of immutable inventory bytes and file sets.

Every invocation owns a fresh attempt directory. SQLite keeps million-file
accounting on disk; workers have no writable handles and stop between bounded
reads when any worker detects a mismatch. An incomplete check is never a pass.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import tempfile
import threading

from .core import atomic_json, safe_output, utcnow
from .source_io import open_source_readonly
from .source_scope import validate_source_exclusion, is_source_excluded, validate_source_exclusion_binding, historical_source_exclusion
from .inventory import SourceChangedError, _fingerprint, _reject_output_links

VERSION = "integrity-2.1.0"
BLOCK = 1024 * 1024
MANIFEST_ROW_LIMIT = 4 * 1024 * 1024
BASELINE_INSERT_BATCH = 10000


class _BaselineError(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def _walk_regular(source, scope=None):
    """Stream directory entries without retaining all names in a directory."""
    def visit(directory):
        with os.scandir(directory) as entries:
            for entry in entries:
                relative = Path(entry.path).relative_to(source).as_posix()
                if is_source_excluded(relative, scope):
                    continue
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    yield from visit(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    path = Path(entry.path)
                    before = entry.stat(follow_symlinks=False)
                    if stat.S_ISREG(before.st_mode):
                        yield path, path.relative_to(source).as_posix(), before
    yield from visit(source)


def _read_block(handle):
    # Kept as a small seam for deterministic mutation/cancellation tests.
    return handle.read(BLOCK)


def _source_result(item, expected, cancelled, fail):
    path, relative, before = item
    result = {"relative_path": relative, "status": "cancelled", "sha256": None,
              "size_bytes": before.st_size, "bytes_hashed": 0}
    digest = hashlib.sha256()

    def changed(reason, error_type=None):
        result.update(status="changed", reason=reason)
        if error_type:
            result["error_type"] = error_type
        fail(reason, relative, error_type)
        return result

    if cancelled.is_set():
        return result
    if before.st_size != expected[1] or _fingerprint(before) != expected[2]:
        return changed("source_stat_changed_before_read")
    try:
        with open_source_readonly(path) as handle:
            if _fingerprint(os.fstat(handle.fileno())) != _fingerprint(before):
                return changed("source_stat_changed_before_read")
            while not cancelled.is_set():
                block = _read_block(handle)
                if cancelled.is_set():
                    return result
                if _fingerprint(os.fstat(handle.fileno())) != _fingerprint(before):
                    return changed("source_stat_changed_during_read")
                if not block:
                    break
                digest.update(block)
                result["bytes_hashed"] += len(block)
            if cancelled.is_set():
                return result
            if _fingerprint(path.lstat()) != _fingerprint(before):
                return changed("source_stat_changed_after_read")
        result["sha256"] = digest.hexdigest()
        if result["bytes_hashed"] != expected[1] or result["sha256"] != expected[0]:
            return changed("source_hash_or_size_changed")
        result["status"] = "unchanged"
        return result
    except Exception as error:
        # A protected open can reject a source replaced by a FIFO or symlink.
        # Preserve that source-change classification without opening it again.
        try:
            if _fingerprint(path.lstat()) != _fingerprint(before):
                return changed("source_identity_changed_while_opening_or_reading", type(error).__name__)
        except OSError:
            return changed("source_path_became_unavailable", type(error).__name__)
        # No exception string, content, or absolute source path enters artifacts.
        result.update(status="processing_error", reason="source_read_failed", error_type=type(error).__name__)
        fail("source_read_failed", relative, type(error).__name__)
        return result


def _load_baseline(checkpoint, connection, scope=None):
    metadata_path = checkpoint / "manifest.json"
    manifest_path = checkpoint / "source_manifest.jsonl"
    if metadata_path.is_symlink() or manifest_path.is_symlink():
        raise _BaselineError("symlink_inventory_manifest")
    with metadata_path.open(encoding="utf-8") as handle:
        metadata = json.load(handle)
    checksum = metadata["source_manifest_sha256"]
    if not metadata.get("complete") or not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise _BaselineError("incomplete_or_invalid_inventory_manifest")
    before = manifest_path.stat()
    digest = hashlib.sha256()
    count = 0
    batch = []
    historical_scope = historical_source_exclusion(scope)
    descriptor = os.open(manifest_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        if _fingerprint(os.fstat(handle.fileno())) != _fingerprint(before):
            raise _BaselineError("immutable_inventory_manifest_changed")
        while True:
            line = handle.readline(MANIFEST_ROW_LIMIT + 1)
            if not line:
                break
            if len(line) > MANIFEST_ROW_LIMIT:
                raise _BaselineError("inventory_manifest_row_exceeds_bound")
            digest.update(line)
            record = json.loads(line)
            validate_source_exclusion_binding(record, historical_scope)
            relative, sha256, size = record["relative_path"], record["sha256"], record["size_bytes"]
            fingerprint = record["stat_fingerprint"]
            if (not isinstance(relative, str) or not relative or "\x00" in relative
                    or PurePosixPath(relative).is_absolute() or ".." in PurePosixPath(relative).parts
                    or PurePosixPath(relative).as_posix() != relative
                    or not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256)
                    or type(size) is not int or size < 0
                    or not isinstance(fingerprint, list) or len(fingerprint) != 5
                    or any(type(value) is not int for value in fingerprint)
                    or fingerprint[2] != size):
                raise _BaselineError("invalid_inventory_manifest_record")
            batch.append((relative, sha256, size, json.dumps(fingerprint), int(is_source_excluded(relative, scope))))
            count += 1
            if len(batch) == BASELINE_INSERT_BATCH:
                connection.executemany("INSERT INTO expected(relative_path,sha256,size_bytes,fingerprint,excluded) VALUES(?,?,?,?,?)", batch)
                connection.commit()
                batch.clear()
        connection.executemany("INSERT INTO expected(relative_path,sha256,size_bytes,fingerprint,excluded) VALUES(?,?,?,?,?)", batch)
        connection.commit()
        if (_fingerprint(os.fstat(handle.fileno())) != _fingerprint(before)
                or _fingerprint(manifest_path.stat()) != _fingerprint(before)
                or digest.hexdigest() != checksum):
            raise _BaselineError("immutable_inventory_manifest_changed")
    return count, checksum, before


def verify_source_hashes(source_root: Path, checkpoint_dir: Path,
                         verification_dir: Path, config: dict) -> dict:
    """Verify independently; preserve a failed attempt before raising on failure.

    ``source_hashes_path`` and ``integrity_report_path`` are relative to the run
    (``checkpoint_dir.parent``), or null for an output outside that run. The
    ``artifacts`` mapping is always relative to ``verification_dir``. ``unverified_files``
    includes changed/missing files and cancelled or never scheduled baseline files.
    SQLite records their exact paths without loading the full file set into memory.
    An invocation always creates a new attempt, including after an earlier pass.
    """
    source = Path(source_root).resolve(strict=True)
    output = safe_output(verification_dir)
    if not source.is_dir() or source == output or source in output.parents or output in source.parents:
        raise ValueError("unsafe_source_output_relationship")
    checkpoint = Path(checkpoint_dir).resolve(strict=True)
    if checkpoint == output or output in checkpoint.parents:
        raise ValueError("verification_output_contains_inventory")
    source_exclusion = validate_source_exclusion(checkpoint, config, freeze=False)
    if source_exclusion is not None and not source_exclusion["frozen"]:
        raise ValueError("source_exclusion_must_be_frozen_before_verification")
    workers = min(4, max(1, int(config.get("integrity_workers", config.get("inventory_workers", config.get("workers", 4))))))
    output.mkdir(parents=True, exist_ok=True)
    _reject_output_links(output)
    attempt = Path(tempfile.mkdtemp(prefix="attempt_", dir=output))
    _reject_output_links(attempt)
    cancelled = threading.Event()
    first_failure = []
    failure_lock = threading.Lock()
    counts = {key: 0 for key in ("expected_files", "observed_files", "files", "verified_files",
                               "unverified_files", "bytes", "changed", "added", "removed",
                               "cancelled", "processing_error", "hash_completed_files", "final_rechecked_files",
                               "excluded_files", "excluded_baseline_bytes", "scoped_expected_files", "scoped_unverified_files")}
    enumeration_complete = final_recheck_complete = baseline_verified = False
    baseline_checksum = None
    started = utcnow()
    connection = results = executor = None
    pending = set()
    detection_written = False
    progress_count = 0

    def fail(reason, relative=None, error_type=None):
        with failure_lock:
            if not first_failure:
                first_failure.append({"reason": reason, "relative_path": relative,
                                      "error_type": error_type, "detected_at": utcnow()})
            cancelled.set()

    def persist_detection():
        nonlocal detection_written
        if first_failure and not detection_written:
            atomic_json(attempt / "failure_detected.json", first_failure[0])
            detection_written = True

    def write_result(record):
        results.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        status = record["status"]
        if status == "unchanged":
            counts["verified_files"] += 1
        elif status == "excluded_by_user":
            counts["excluded_files"] += 1
            counts["excluded_baseline_bytes"] += record["baseline_size_bytes"]
        if status in counts:
            counts[status] += 1
        counts["files"] += 1
        counts["bytes"] += record.get("bytes_hashed", 0)
        counts["hash_completed_files"] += record.get("sha256") is not None
        connection.execute("UPDATE expected SET status=? WHERE relative_path=?", (status, record["relative_path"]))

    def collect(done):
        nonlocal progress_count
        for future in done:
            if future.cancelled():
                continue
            write_result(future.result())
        persist_detection()
        if counts["files"] - progress_count >= 1000:
            progress_count = counts["files"]
            connection.commit()
            results.flush()
            atomic_json(attempt / "progress.json", {**counts, "at": utcnow()})

    try:
        database_path = safe_output(attempt / "verification.sqlite")
        for suffix in ("-wal", "-shm", "-journal"):
            safe_output(Path(str(database_path) + suffix))
        descriptor = os.open(database_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(descriptor)
        connection = sqlite3.connect(database_path)
        connection.execute("PRAGMA temp_store=MEMORY")
        connection.execute("PRAGMA cache_size=-8192")
        connection.execute("CREATE TABLE expected(relative_path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL, fingerprint TEXT NOT NULL, seen INTEGER DEFAULT 0, final_seen INTEGER DEFAULT 0, status TEXT DEFAULT 'unverified', excluded INTEGER NOT NULL DEFAULT 0)")
        partial_path = safe_output(attempt / "source_hashes_after.jsonl.partial")
        descriptor = os.open(partial_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        results = os.fdopen(descriptor, "w", encoding="utf-8")
        counts["expected_files"], baseline_checksum, baseline_stat = _load_baseline(checkpoint, connection, source_exclusion)
        baseline_verified = True
        for relative, baseline_hash, baseline_size in connection.execute("SELECT relative_path,sha256,size_bytes FROM expected WHERE excluded=1 ORDER BY relative_path"):
            write_result({"relative_path": relative, "status": "excluded_by_user", "reason": "user_approved_source_coverage_exclusion",
                "baseline_sha256": baseline_hash, "baseline_size_bytes": baseline_size,
                "sha256": None, "size_bytes": None, "bytes_hashed": 0,
                "current_coverage": "unknown", "source_exclusion_amendment_sha256": source_exclusion["sha256"]})
        if source_exclusion is not None:
            atomic_json(attempt / "source_exclusion_reference.json", source_exclusion)
        def walk():
            return _walk_regular(source, source_exclusion) if source_exclusion else _walk_regular(source)

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="source_integrity")
        for item in walk():
            if cancelled.is_set():
                break
            path, relative, before = item
            counts["observed_files"] += 1
            expected = connection.execute("SELECT sha256,size_bytes,fingerprint FROM expected WHERE relative_path=?", (relative,)).fetchone()
            if expected is None:
                fail("source_file_added", relative)
                write_result({"relative_path": relative, "status": "added", "size_bytes": before.st_size})
                break
            expected = (expected[0], expected[1], json.loads(expected[2]))
            connection.execute("UPDATE expected SET seen=1 WHERE relative_path=?", (relative,))
            if before.st_size != expected[1] or _fingerprint(before) != expected[2]:
                fail("source_stat_changed_before_read", relative)
                write_result({"relative_path": relative, "status": "changed", "size_bytes": before.st_size,
                              "reason": "source_stat_changed_before_read"})
                break
            pending.add(executor.submit(_source_result, item, expected, cancelled, fail))
            if len(pending) >= workers * 2:
                done, pending = concurrent.futures.wait(pending, timeout=0.25, return_when=concurrent.futures.FIRST_COMPLETED)
                collect(done)
                while len(pending) >= workers * 2 and not cancelled.is_set():
                    done, pending = concurrent.futures.wait(pending, timeout=0.25, return_when=concurrent.futures.FIRST_COMPLETED)
                    collect(done)
        else:
            enumeration_complete = True
        persist_detection()
        while pending and not cancelled.is_set():
            done, pending = concurrent.futures.wait(pending, timeout=0.25, return_when=concurrent.futures.FIRST_COMPLETED)
            collect(done)
        if not cancelled.is_set():
            missing = connection.execute("SELECT relative_path FROM expected WHERE seen=0 AND excluded=0 LIMIT 1").fetchone()
            if missing:
                fail("source_file_removed", missing[0])
                write_result({"relative_path": missing[0], "status": "removed"})
        # Recheck metadata and the file set after hashing, catching changes to a
        # file or directory that was already read during the long corpus scan.
        if not cancelled.is_set():
            for path, relative, current in walk():
                expected = connection.execute("SELECT fingerprint FROM expected WHERE relative_path=?", (relative,)).fetchone()
                if expected is None:
                    fail("source_file_added_during_verification", relative)
                    write_result({"relative_path": relative, "status": "added"})
                    break
                if _fingerprint(current) != json.loads(expected[0]):
                    fail("source_stat_changed_after_verification", relative)
                    # This file's earlier hash no longer establishes integrity.
                    counts["verified_files"] -= 1
                    write_result({"relative_path": relative, "status": "changed", "reason": "source_stat_changed_after_verification"})
                    break
                connection.execute("UPDATE expected SET final_seen=1 WHERE relative_path=?", (relative,))
                counts["final_rechecked_files"] += 1
            else:
                final_recheck_complete = True
            if not cancelled.is_set():
                missing = connection.execute("SELECT relative_path FROM expected WHERE final_seen=0 AND excluded=0 LIMIT 1").fetchone()
                if missing:
                    fail("source_file_removed_during_verification", missing[0])
                    counts["verified_files"] -= 1
                    write_result({"relative_path": missing[0], "status": "removed"})
        if not cancelled.is_set() and _fingerprint((checkpoint / "source_manifest.jsonl").stat()) != _fingerprint(baseline_stat):
            fail("immutable_inventory_manifest_changed")
        if not cancelled.is_set() and validate_source_exclusion(checkpoint, config, freeze=False) != source_exclusion:
            fail("source_exclusion_authorization_changed_during_verification")
    except BaseException as error:
        # Never serialize arbitrary exception messages (which may contain data).
        fail(error.reason if isinstance(error, _BaselineError) else "verification_error", error_type=type(error).__name__)
    finally:
        if cancelled.is_set():
            try:
                persist_detection()
            except Exception as error:
                fail("verification_artifact_error", error_type=type(error).__name__)
            for future in pending:
                future.cancel()
        if executor is not None:
            executor.shutdown(wait=True, cancel_futures=True)
        try:
            if pending:
                collect(pending)
            if connection is not None:
                counts["expected_files"] = connection.execute("SELECT COUNT(*) FROM expected").fetchone()[0]
                counts["verified_files"] = connection.execute("SELECT COUNT(*) FROM expected WHERE status='unchanged'").fetchone()[0]
                counts["excluded_files"] = connection.execute("SELECT COUNT(*) FROM expected WHERE status='excluded_by_user'").fetchone()[0]
                counts["scoped_expected_files"] = connection.execute("SELECT COUNT(*) FROM expected WHERE excluded=0").fetchone()[0]
                counts["scoped_unverified_files"] = connection.execute("SELECT COUNT(*) FROM expected WHERE excluded=0 AND status<>'unchanged'").fetchone()[0]
                connection.commit()
            if results is not None:
                results.flush()
                os.fsync(results.fileno())
        except BaseException as error:
            fail("verification_artifact_error", error_type=type(error).__name__)
        finally:
            if results is not None:
                results.close()
            if connection is not None:
                connection.close()
    counts["unverified_files"] = counts["expected_files"] - counts["verified_files"]
    passed = (not first_failure and baseline_verified and enumeration_complete and final_recheck_complete
              and counts["scoped_unverified_files"] == 0
              and counts["verified_files"] + counts["excluded_files"] == counts["expected_files"])
    filename = "source_hashes_after.jsonl" if passed else "source_hashes_after.failed.jsonl"
    if (attempt / "source_hashes_after.jsonl.partial").exists():
        os.replace(safe_output(attempt / "source_hashes_after.jsonl.partial"), safe_output(attempt / filename))
    run_root = checkpoint.parent
    artifact_dir = attempt.relative_to(run_root).as_posix() if run_root in attempt.parents else None
    report = {"version": VERSION, "passed": passed, "complete": passed,
              "verification_scope": "approved_current_source_scope" if source_exclusion else "original_source_tree",
              "full_original_source_integrity": passed and source_exclusion is None,
              "full_original_source_coverage": enumeration_complete and source_exclusion is None,
              "source_exclusion_amendment": source_exclusion,
              "source_exclusion_amendment_sha256": source_exclusion["sha256"] if source_exclusion else None,
              "current_excluded_coverage": "unknown" if source_exclusion else "not_applicable",
              "current_excluded_files": None if source_exclusion else 0,
              "current_excluded_bytes": None if source_exclusion else 0,
              "current_excluded_records": None if source_exclusion else 0,
              "artifact_dir": artifact_dir,
              "source_hashes_path": str(Path(artifact_dir) / filename) if artifact_dir is not None else None,
              "integrity_report_path": str(Path(artifact_dir) / "source_integrity.json") if artifact_dir is not None else None,
              "statistics": counts, "started_at": started, "completed_at": utcnow(),
              "baseline_manifest_verified": baseline_verified, "expected_file_count_complete": baseline_verified,
              "source_manifest_sha256": baseline_checksum,
              "enumeration_complete": enumeration_complete, "final_metadata_recheck_complete": final_recheck_complete,
              "method": "independent full raw-byte SHA-256 of every file in the approved current scope, with fail-fast chunk cancellation and final scoped metadata/file-set recheck",
              "workers": workers, "chunk_bytes": BLOCK, "failure": first_failure[0] if first_failure else None,
              "artifacts": {"source_integrity": str((attempt / "source_integrity.json").relative_to(output)),
                            "results": str((attempt / filename).relative_to(output)),
                            "accounting": str((attempt / "verification.sqlite").relative_to(output))},
              "accounting_note": "Every historical baseline file remains in the accounting database. Excluded entries retain baseline hashes/sizes, have null current hashes/sizes and are never unchanged. Current excluded additions/deletions/counts are unknown. unverified_files includes excluded historical files; scoped_unverified_files must be zero to pass the approved scope. Full-original integrity is false when any source exclusion applies. A failed attempt stops at the first detected in-scope mismatch."}
    atomic_json(attempt / "source_integrity.json", report)
    if not passed:
        reason = first_failure[0]["reason"] if first_failure else "incomplete_verification"
        raise SourceChangedError("source_integrity_failed:" + reason) from None
    return report
