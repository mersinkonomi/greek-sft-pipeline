"""Independent, immutable pre-API release audits; no source content is copied.

The SQLite ledger bounds memory by one JSONL row and a bounded batch.  Counts
alone are insufficient: every transition is checked by identity and stable
content hash, and every raw candidate receives exactly one terminal outcome.
This module never grants review, privacy, licensing, or release approval.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import sqlite3
import uuid
from collections import Counter
from pathlib import Path

from jsonschema import Draft202012Validator

from .core import PIPELINE_ROOT, STATUSES, canonical_json, digest, safe_output, sha256_file, utcnow
from .source_scope import (validate_source_exclusion, is_source_excluded,
                           historical_source_exclusion, source_exclusion_artifact_paths)

VERSION = "reporting-1.0.0"
CHECKPOINTS = {
    1: "checkpoint_01_inventory", 2: "checkpoint_02_source_plans",
    3: "checkpoint_03_raw_candidates", 4: "checkpoint_04_validated_candidates",
    5: "checkpoint_05_dedup_splits",
}
STAGES = ("01_ExactSubstrings", "02_MinhashDedup", "03_SentenceDedup")
TERMINALS = ("quarantine", "contaminated", *(s + "_removed" for s in STAGES), "capped", "pre_api")


def _write_json(path, value):
    with safe_output(path).open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def _write_text(path, value):
    with safe_output(path).open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def _stable_hash(candidate):
    """Only these four fields are deliberately changed by passes four/five."""
    meta = {k: v for k, v in candidate.get("metadata", {}).items()
            if k not in {"validation_status", "review_status", "dedup_group", "split"}}
    return digest({"id": candidate.get("id"), "messages": candidate.get("messages"), "metadata": meta})


def _relative(value):
    return isinstance(value, str) and bool(value) and not Path(value).is_absolute() and ".." not in Path(value).parts


class _Audit:
    def __init__(self, run, output):
        self.run, self.output = run, output
        self.source_exclusion = None
        self.error_counts = Counter()
        self.artifacts = {}
        self.metrics = Counter()
        self.error_stream = safe_output(output / "errors.jsonl").open("x", encoding="utf-8")
        self.db = sqlite3.connect(safe_output(output / "accounting.sqlite"))
        self.db.executescript("""
            PRAGMA journal_mode=DELETE;
            PRAGMA temp_store=FILE;
            PRAGMA cache_size=-16384;
            CREATE TABLE files(path TEXT PRIMARY KEY,family TEXT NOT NULL,n INTEGER,boundary INTEGER,
              sha TEXT,status TEXT,reason TEXT,plan_seen INTEGER DEFAULT 0,build_seen INTEGER DEFAULT 0,
              build_status TEXT,build_reason TEXT,shard TEXT,bytes INTEGER NOT NULL,verification_seen INTEGER DEFAULT 0,sha_after TEXT,
              excluded INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE candidates(id TEXT PRIMARY KEY,source TEXT,line INTEGER,row_hash TEXT,
              stable_hash TEXT,family TEXT,domain TEXT,task TEXT);
            CREATE TABLE members(stage TEXT,id TEXT,h TEXT,reason TEXT,keeper TEXT,
              PRIMARY KEY(stage,id)) WITHOUT ROWID;
            CREATE TABLE generated(source TEXT,line INTEGER,status TEXT,reason TEXT,id TEXT,row_hash TEXT,
              PRIMARY KEY(source,line)) WITHOUT ROWID;
            CREATE TABLE rejected(source TEXT,line INTEGER,status TEXT,reason TEXT,row_hash TEXT,
              PRIMARY KEY(source,line)) WITHOUT ROWID;
            CREATE TABLE splits(id TEXT PRIMARY KEY,split TEXT,source TEXT,group_id TEXT,dedup_group TEXT,
              content_hash TEXT,message_hash TEXT,review_status TEXT,license_status TEXT,privacy_status TEXT);
            CREATE TABLE decisions(id TEXT PRIMARY KEY,status TEXT,reasons TEXT,schema_passed INTEGER,
              content_passed INTEGER,greek_ratio REAL);
            CREATE INDEX candidate_source ON candidates(source,line);
            CREATE INDEX candidate_family ON candidates(family);
            CREATE INDEX file_family ON files(family);
            CREATE INDEX generated_id ON generated(id);
            CREATE INDEX member_id ON members(id,stage);
        """)
        # Reporting calls must not overlap within one process: this SQLite pragma
        # is process-global. It pins all bounded-cache sort spill files here.
        prior = self.db.execute("PRAGMA temp_store_directory").fetchone()
        self.prior_temp_directory = prior[0] if prior and prior[0] else ""
        self.db.execute("PRAGMA temp_store_directory='" + str(output).replace("'", "''") + "'")
        self.operations = 0

    def close(self):
        self.db.commit()
        prior = self.prior_temp_directory
        if prior and not Path(prior).is_dir():
            prior = ""
        self.db.execute("PRAGMA temp_store_directory='" + prior.replace("'", "''") + "'")
        self.db.close()
        self.error_stream.flush()
        os.fsync(self.error_stream.fileno())
        self.error_stream.close()

    def error(self, code, **context):
        self.error_counts[code] += 1
        # Only structural identifiers/reason codes are ever written, never a row,
        # exception string, user/assistant message, credential, or source evidence.
        self.error_stream.write(canonical_json({"code": code, **context}) + "\n")

    def commit_batch(self):
        self.operations += 1
        if self.operations % 1000 == 0:
            self.db.commit()

    def label(self, path):
        return str(Path(path).relative_to(self.run))

    def input(self, path):
        path = safe_output(path)
        if self.run not in path.parents:
            raise ValueError("Audit input is outside its assigned run")
        if not path.is_file():
            self.error("missing_artifact", artifact=self.label(path))
            return None
        return path

    def rows(self, path):
        path = self.input(path)
        if path is None:
            return
        hasher, total = hashlib.sha256(), 0
        # Hash the very bytes audited, rather than reopening a potentially changed
        # file after inspection. Check stat identity before/after as an extra guard.
        before = path.stat()
        with path.open("rb") as stream:
            for number, raw in enumerate(stream, 1):
                hasher.update(raw)
                total += len(raw)
                try:
                    value = json.loads(raw.decode("utf-8"))
                    if not isinstance(value, dict):
                        raise ValueError("not_object")
                except (ValueError, UnicodeError):
                    self.error("malformed_artifact_row", artifact=self.label(path), line=number)
                    continue
                yield number, value
        after = path.stat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            self.error("artifact_changed_during_audit", artifact=self.label(path))
        self.artifacts[self.label(path)] = {"sha256": hasher.hexdigest(), "bytes": total}

    def object(self, path):
        path = self.input(path)
        if path is None:
            return {}
        raw = path.read_bytes()
        self.artifacts[self.label(path)] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
        try:
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError("not_object")
            return value
        except ValueError:
            self.error("malformed_artifact_object", artifact=self.label(path))
            return {}

    def count(self, query, parameters=()):
        return self.db.execute(query, parameters).fetchone()[0]

    def members(self, stage):
        return self.count("SELECT COUNT(*) FROM members WHERE stage=?", (stage,))

    def query_errors(self, code, query, columns, parameters=()):
        for row in self.db.execute(query, parameters):
            self.error(code, **dict(zip(columns, row)))

    def partition(self, before, after):
        """Require an exact disjoint union, not merely an equal row count."""
        placeholders = ",".join("?" for _ in after)
        self.query_errors("partition_missing_or_multiple", f"""
            SELECT p.id,COUNT(c.id) FROM members p LEFT JOIN members c
              ON p.id=c.id AND c.stage IN ({placeholders}) WHERE p.stage=?
              GROUP BY p.id HAVING COUNT(c.id)<>1""", ("example_id", "outcomes"), (*after, before))
        self.query_errors("partition_foreign_identity", f"""
            SELECT c.id,c.stage FROM members c LEFT JOIN members p ON p.id=c.id AND p.stage=?
              WHERE c.stage IN ({placeholders}) AND p.id IS NULL""", ("example_id", "stage"), (before, *after))
        self.query_errors("partition_content_changed", f"""
            SELECT c.id,c.stage FROM members c JOIN members p ON p.id=c.id AND p.stage=?
              WHERE c.stage IN ({placeholders}) AND c.h<>p.h""", ("example_id", "stage"), (before, *after))
        return {"input_stage": before, "input": self.members(before),
                "outputs": {s: self.members(s) for s in after}}

    def add_member(self, stage, candidate, reason="", keeper=None):
        identity = candidate.get("id")
        if not isinstance(identity, str) or not identity:
            self.error("candidate_missing_identity", stage=stage)
            return False
        try:
            self.db.execute("INSERT INTO members VALUES(?,?,?,?,?)", (stage, identity, _stable_hash(candidate), reason, keeper))
        except sqlite3.IntegrityError:
            self.error("duplicate_candidate_identity", stage=stage, example_id=identity)
            return False
        self.commit_batch()
        return True


def _inventory(audit, checkpoint, inventory_audit):
    for number, row in audit.rows(checkpoint / "source_manifest.jsonl"):
        path = row.get("relative_path")
        count = row.get("record_count")
        if not _relative(path) or (count is not None and (type(count) is not int or count < 0)):
            audit.error("invalid_inventory_identity_or_count", line=number)
            continue
        if type(row.get("record_boundary_complete")) is not bool:
            audit.error("inventory_boundary_unspecified", source_file=path)
        if row.get("status") not in STATUSES:
            audit.error("inventory_unknown_status", source_file=path)
        try:
            audit.db.execute("INSERT INTO files(path,family,n,boundary,sha,status,reason,bytes,excluded) VALUES(?,?,?,?,?,?,?,?,?)",
                (path, row.get("family") or "uncatalogued", count, int(row.get("record_boundary_complete") is True),
                 row.get("sha256"), row.get("status"), row.get("reason"), row.get("size_bytes", 0),
                 int(is_source_excluded(path, audit.source_exclusion))))
        except sqlite3.IntegrityError:
            audit.error("duplicate_inventory_file", source_file=path)
        audit.commit_batch()
    manifest_identity = audit.artifacts.get(audit.label(checkpoint / "source_manifest.jsonl"), {}).get("sha256")
    if inventory_audit.get("input_identity", {}).get("manifest_sha256") != manifest_identity:
        audit.error("inventory_audit_manifest_mismatch")
    for name, query in (("files", "COUNT(*)"), ("records", "COALESCE(SUM(n),0)"), ("bytes", "COALESCE(SUM(bytes),0)")):
        if inventory_audit.get("totals", {}).get(name) != audit.count("SELECT " + query + " FROM files"):
            audit.error("inventory_audit_totals_mismatch", metric=name)
    if inventory_audit.get("identified_accounting_passed") is not True:
        audit.error("inventory_range_accounting_unresolved")



def _source_reverification(audit, verification, checkpoint):
    exclusion = audit.source_exclusion
    if verification.get("source_exclusion_amendment") != exclusion:
        audit.error("source_verification_scope_mismatch")
    if exclusion is not None and (verification.get("source_exclusion_amendment_sha256") != exclusion["sha256"]
            or verification.get("verification_scope") != "approved_current_source_scope"
            or verification.get("full_original_source_integrity") is not False
            or verification.get("full_original_source_coverage") is not False
            or verification.get("current_excluded_coverage") != "unknown"
            or any(verification.get(key) is not None for key in
                   ("current_excluded_files", "current_excluded_bytes", "current_excluded_records"))):
        audit.error("source_verification_excluded_scope_claim_invalid")
    relative = verification.get("source_hashes_path")
    if relative is None:
        # Compatibility with the first pipeline implementation; current verifier
        # returns the unique attempt reference explicitly.
        path = checkpoint / "source_verification" / "source_hashes_after.jsonl"
    elif not _relative(relative):
        audit.error("invalid_source_verification_artifact_reference")
        return
    else:
        path = audit.run / relative
    for number, row in audit.rows(path):
        source_file = row.get("relative_path")
        original = audit.db.execute("SELECT sha,bytes,verification_seen,excluded FROM files WHERE path=?", (source_file,)).fetchone()
        if original is None:
            audit.error("source_verification_foreign_file", line=number)
            continue
        if original[2]:
            audit.error("source_verification_duplicate_file", source_file=source_file)
        if original[3]:
            if (exclusion is None or row.get("status") != "excluded_by_user"
                    or row.get("reason") != "user_approved_source_coverage_exclusion"
                    or (row.get("baseline_sha256"), row.get("baseline_size_bytes")) != original[:2]
                    or "sha256" not in row or row["sha256"] is not None
                    or "size_bytes" not in row or row["size_bytes"] is not None
                    or row.get("bytes_hashed") != 0 or row.get("current_coverage") != "unknown"
                    or row.get("source_exclusion_amendment_sha256") != exclusion["sha256"]):
                audit.error("source_verification_invalid_excluded_disposition", source_file=source_file)
        elif row.get("status") != "unchanged" or (row.get("sha256"), row.get("size_bytes")) != original[:2]:
            audit.error("source_verification_hash_or_size_mismatch", source_file=source_file)
        audit.db.execute("UPDATE files SET verification_seen=verification_seen+1,sha_after=? WHERE path=?",
                         (row.get("sha256"), source_file))
        audit.commit_batch()
    audit.query_errors("source_verification_missing_file", "SELECT path FROM files WHERE verification_seen=0", ("source_file",))
    expected = audit.count("SELECT COUNT(*) FROM files")
    excluded = audit.count("SELECT COUNT(*) FROM files WHERE excluded=1")
    scoped = expected - excluded
    stats = verification.get("statistics", {})
    verified = stats.get("verified_files", stats.get("unchanged"))
    if verified != scoped or stats.get("expected_files", expected) != expected or stats.get("unverified_files", 0) != excluded:
        audit.error("source_verification_statistics_mismatch")
    if exclusion is not None and (stats.get("excluded_files") != excluded
            or stats.get("scoped_expected_files") != scoped or stats.get("scoped_unverified_files") != 0
            or stats.get("excluded_baseline_bytes") != audit.count("SELECT COALESCE(SUM(bytes),0) FROM files WHERE excluded=1")):
        audit.error("source_verification_scoped_statistics_mismatch")
    if verification.get("passed") is not True:
        audit.error("source_verification_not_passed")
    report_path = verification.get("integrity_report_path")
    if report_path is not None:
        if not _relative(report_path):
            audit.error("invalid_source_integrity_report_reference")
        else:
            declared = audit.object(audit.run / report_path)
            if declared.get("passed") != verification.get("passed") or declared.get("statistics") != stats:
                audit.error("supplied_source_verification_report_mismatch")
            if any(declared.get(key) != verification.get(key) for key in
                   ("source_exclusion_amendment", "source_exclusion_amendment_sha256", "verification_scope",
                    "full_original_source_integrity", "full_original_source_coverage", "current_excluded_coverage",
                    "current_excluded_files", "current_excluded_bytes", "current_excluded_records")):
                audit.error("supplied_source_verification_scope_mismatch")


def _source_dispositions(audit, checkpoint, pass_number):
    seen = "plan_seen" if pass_number == 2 else "build_seen"
    for number, row in audit.rows(checkpoint / "source_dispositions.jsonl"):
        path = row.get("source_file")
        if not _relative(path):
            audit.error("invalid_disposition_path", pass_number=pass_number, line=number)
            continue
        if is_source_excluded(path, audit.source_exclusion) and row.get("status") == "accepted":
            audit.error("source_exclusion_accepted_disposition", pass_number=pass_number, source_file=path)
        original = audit.db.execute(f"SELECT n,boundary,family,{seen} FROM files WHERE path=?", (path,)).fetchone()
        if original is None:
            audit.error("foreign_disposition_file", pass_number=pass_number, source_file=path)
            continue
        n, boundary, family, old_seen = original
        if old_seen:
            audit.error("duplicate_source_disposition", pass_number=pass_number, source_file=path)
        if (row.get("record_count"), row.get("record_start"), row.get("record_end"),
                row.get("record_boundary_complete"), row.get("family")) != (n, 1 if n else None, n, bool(boundary), family):
            audit.error("source_disposition_inventory_mismatch", pass_number=pass_number, source_file=path)
        if row.get("status") not in STATUSES or not isinstance(row.get("reason"), str) or not row["reason"]:
            audit.error("invalid_source_disposition", pass_number=pass_number, source_file=path)
        if pass_number == 3:
            shard = row.get("shard")
            if row.get("status") == "accepted" and (not _relative(shard) or not str(shard).startswith("shards/")):
                audit.error("invalid_generation_shard", source_file=path)
            audit.db.execute("UPDATE files SET build_status=?,build_reason=?,shard=? WHERE path=?",
                             (row.get("status"), row.get("reason"), shard, path))
        audit.db.execute(f"UPDATE files SET {seen}={seen}+1 WHERE path=?", (path,))
        audit.commit_batch()
    audit.query_errors("missing_source_disposition", f"SELECT path FROM files WHERE {seen}=0", ("source_file",))


def _load_candidates(audit, paths, stage, validator, wrapper=None, split=None):
    for path in paths:
        for number, row in audit.rows(path):
            candidate = row.get(wrapper) if wrapper else row
            if not isinstance(candidate, dict):
                audit.error("invalid_candidate_wrapper", stage=stage, line=number)
                continue
            identity, meta = candidate.get("id"), candidate.get("metadata", {})
            if not isinstance(meta, dict):
                audit.error("invalid_candidate_metadata", stage=stage, line=number)
                continue
            source_path = meta.get("source_file")
            if _relative(source_path) and is_source_excluded(source_path, audit.source_exclusion):
                audit.error("source_exclusion_candidate_present", stage=stage, source_file=source_path)
                continue
            schema_passed = validator.is_valid(candidate)
            audit.metrics[stage + "_schema_checked"] += 1
            audit.metrics[stage + "_schema_failed"] += not schema_passed
            if not schema_passed:
                audit.error("candidate_canonical_schema_failed", stage=stage, example_id=identity if isinstance(identity, str) else None)
            reason = row.get("reason", row.get("reasons", "")) if wrapper else ""
            if not isinstance(reason, str):
                reason = canonical_json(reason)
            if not audit.add_member(stage, candidate, reason, row.get("keeper_id")):
                continue
            if wrapper and "example_id" in row and row["example_id"] != identity:
                audit.error("wrapper_candidate_identity_mismatch", stage=stage, example_id=identity)
            if stage == "raw":
                expected_id = digest({"family": meta.get("source_name"), "file": meta.get("source_file"),
                    "line": meta.get("source_line"), "record_hash": meta.get("source_record_hash"),
                    "task": meta.get("task_type"), "version": meta.get("generator_version")})
                if identity != expected_id or meta.get("source_record_id") != str(meta.get("source_line")):
                    audit.error("candidate_deterministic_identity_mismatch", example_id=identity)
                audit.db.execute("INSERT INTO candidates VALUES(?,?,?,?,?,?,?,?)",
                    (identity, meta.get("source_file"), meta.get("source_line"), meta.get("source_record_hash"),
                     _stable_hash(candidate), meta.get("source_name", "unknown"), meta.get("domain", "unknown"), meta.get("task_type", "unknown")))
                original = audit.db.execute("SELECT sha,n,family FROM files WHERE path=?", (meta.get("source_file"),)).fetchone()
                if (original is None or original[0] != meta.get("source_file_hash") or original[2] != meta.get("source_name")
                        or type(meta.get("source_line")) is not int or not 1 <= meta["source_line"] <= (original[1] or 0)):
                    audit.error("candidate_source_lineage_mismatch", example_id=identity)
            if stage in {"validated", "clean", "pre_api"} and meta.get("validation_status") != "passed":
                audit.error("accepted_candidate_validation_not_passed", stage=stage, example_id=identity)
            if stage in {"validated", "clean", "pre_api"}:
                if meta.get("license_status") != "verified" or meta.get("privacy_status") != "approved":
                    audit.error("accepted_candidate_permission_status_unresolved", stage=stage, example_id=identity)
            if stage == "pre_api":
                if meta.get("split") != split:
                    audit.error("split_metadata_mismatch", example_id=identity)
                if meta.get("review_status") != "pending":
                    audit.error("unexpected_pre_api_review_status", example_id=identity)
                from .dedup import source_derived_text, _normal
                audit.db.execute("INSERT INTO splits VALUES(?,?,?,?,?,?,?,?,?,?)", (
                    identity, split, digest([meta.get("source_file"), meta.get("source_record_id")]), meta.get("split_group"), meta.get("dedup_group"),
                    hashlib.sha256(_normal(source_derived_text(candidate)).encode()).hexdigest(), digest(candidate.get("messages")),
                    meta.get("review_status"), meta.get("license_status"), meta.get("privacy_status")))


def _generation_records(audit, checkpoint):
    for (relative,) in audit.db.execute("SELECT DISTINCT shard FROM files WHERE build_status='accepted' AND shard IS NOT NULL"):
        if not _relative(relative) or not relative.startswith("shards/"):
            continue
        directory = checkpoint / relative
        for number, row in audit.rows(directory / "record_dispositions.jsonl"):
            path, line = row.get("source_file"), row.get("source_line")
            original = audit.db.execute("SELECT n,shard,build_status FROM files WHERE path=?", (path,)).fetchone()
            if (original is None or original[1] != relative or original[2] != "accepted"
                    or type(line) is not int or not 1 <= line <= (original[0] or 0)):
                audit.error("record_disposition_outside_inventory", shard=relative, line=number)
            if row.get("status") not in STATUSES:
                audit.error("unknown_record_disposition", shard=relative, line=number)
            try:
                audit.db.execute("INSERT INTO generated VALUES(?,?,?,?,?,?)", (
                    path, line, row.get("status"), row.get("reason"), row.get("example_id"), row.get("source_record_hash")))
            except sqlite3.IntegrityError:
                audit.error("duplicate_record_disposition", shard=relative, line=number)
            audit.commit_batch()
        for number, row in audit.rows(directory / "rejected.jsonl"):
            try:
                audit.db.execute("INSERT INTO rejected VALUES(?,?,?,?,?)", (row.get("source_file"), row.get("source_line"),
                    row.get("status"), row.get("reason"), row.get("source_record_hash")))
            except sqlite3.IntegrityError:
                audit.error("duplicate_generation_rejection", shard=relative, line=number)
            audit.commit_batch()
    audit.query_errors("generated_file_record_coverage_mismatch", """
        SELECT f.path,f.n,COUNT(g.line) FROM files f LEFT JOIN generated g ON f.path=g.source
        WHERE f.build_status='accepted' GROUP BY f.path HAVING f.n<>COUNT(g.line)""", ("source_file", "expected", "observed"))
    audit.query_errors("accepted_record_candidate_mismatch", """
        SELECT g.source,g.line FROM generated g LEFT JOIN candidates c ON g.id=c.id
        WHERE g.status='accepted' AND (c.id IS NULL OR c.source<>g.source OR c.line<>g.line OR c.row_hash<>g.row_hash)""", ("source_file", "source_line"))
    audit.query_errors("candidate_without_accepted_source_record", """
        SELECT c.id FROM candidates c LEFT JOIN generated g ON c.id=g.id
        WHERE g.id IS NULL OR g.status<>'accepted' OR g.source<>c.source OR g.line<>c.line OR g.row_hash<>c.row_hash""", ("example_id",))
    audit.query_errors("rejected_record_artifact_mismatch", """
        SELECT g.source,g.line FROM generated g LEFT JOIN rejected r ON g.source=r.source AND g.line=r.line
        WHERE g.status<>'accepted' AND (r.source IS NULL OR g.status<>r.status OR g.reason<>r.reason OR g.row_hash<>r.row_hash)""", ("source_file", "source_line"))
    audit.query_errors("foreign_generation_rejection", """
        SELECT r.source,r.line FROM rejected r LEFT JOIN generated g ON g.source=r.source AND g.line=r.line
        WHERE g.source IS NULL OR g.status='accepted'""", ("source_file", "source_line"))


def _decisions(audit, checkpoint):
    for number, row in audit.rows(checkpoint / "record_decisions.jsonl"):
        try:
            audit.db.execute("INSERT INTO decisions VALUES(?,?,?,?,?,?)", (row.get("example_id"), row.get("status"),
                canonical_json(row.get("reasons", [])), row.get("schema_passed") is True, row.get("content_checks_passed") is True,
                row.get("greek_statistics", {}).get("greek_ratio")))
        except sqlite3.IntegrityError:
            audit.error("duplicate_validation_decision", line=number)
        audit.commit_batch()
    audit.query_errors("candidate_validation_decision_missing", "SELECT c.id FROM candidates c LEFT JOIN decisions d ON c.id=d.id WHERE d.id IS NULL", ("example_id",))
    audit.query_errors("foreign_validation_decision", "SELECT d.id FROM decisions d LEFT JOIN candidates c ON c.id=d.id WHERE c.id IS NULL", ("example_id",))
    audit.query_errors("validation_decision_outcome_mismatch", """
        SELECT d.id,d.status FROM decisions d LEFT JOIN members m ON d.id=m.id AND
          m.stage=CASE d.status WHEN 'accepted' THEN 'validated' WHEN 'quarantined' THEN 'quarantine' ELSE '' END
        WHERE m.id IS NULL OR (d.status='accepted' AND (d.schema_passed<>1 OR d.content_passed<>1 OR d.reasons<>'[]'))
          OR (d.status='quarantined' AND d.reasons<>m.reason)""", ("example_id", "status"))


def _split_audit(audit, checkpoint):
    for split in ("train", "validation", "test"):
        count = 0
        expected = iter(audit.db.execute("SELECT id,message_hash FROM splits WHERE split=? ORDER BY id", (split,)))
        for number, row in audit.rows(checkpoint / "pre_api" / split / "messages.jsonl"):
            count += 1
            item = next(expected, None)
            if item is None or set(row) != {"messages"} or digest(row.get("messages")) != item[1]:
                audit.error("training_export_mismatch", split=split, line=number)
        if next(expected, None) is not None:
            audit.error("training_export_missing_records", split=split)
    for name, columns in (("origin_record", "source"), ("source_entity", "group_id"), ("dedup_component", "dedup_group")):
        audit.query_errors("cross_split_" + name, f"SELECT {columns},COUNT(DISTINCT split) FROM splits GROUP BY {columns} HAVING COUNT(DISTINCT split)>1",
                           ("group", "split_count"))
    audit.query_errors("remaining_exact_candidate_duplicates", "SELECT content_hash,COUNT(*) FROM splits GROUP BY content_hash HAVING COUNT(*)>1", ("fingerprint", "records"))
    for _, row in audit.rows(checkpoint / "pre_api" / "near_pairs.jsonl"):
        pair = audit.db.execute("SELECT a.split,b.split FROM splits a JOIN splits b ON b.id=? WHERE a.id=?", (row.get("right_id"), row.get("left_id"))).fetchone()
        if pair and pair[0] != pair[1]:
            audit.error("detected_near_duplicate_split_leakage", left_id=row.get("left_id"), right_id=row.get("right_id"))


def _terminal_reports(audit):
    placeholders = ",".join("?" for _ in TERMINALS)
    audit.query_errors("candidate_terminal_outcome_missing_or_multiple", f"""
        SELECT c.id,COUNT(m.id) FROM candidates c LEFT JOIN members m ON c.id=m.id AND m.stage IN ({placeholders})
        GROUP BY c.id HAVING COUNT(m.id)<>1""", ("example_id", "outcomes"), TERMINALS)
    with safe_output(audit.output / "candidate_dispositions.jsonl").open("x", encoding="utf-8") as stream:
        for row in audit.db.execute(f"""
            SELECT c.id,c.source,c.line,c.row_hash,c.family,m.stage,m.reason,m.keeper FROM candidates c
            LEFT JOIN members m ON c.id=m.id AND m.stage IN ({placeholders}) ORDER BY c.id,m.stage""", TERMINALS):
            identity, source, line, row_hash, family, stage, reason, keeper = row
            stream.write(canonical_json({"example_id": identity, "source_file": source, "source_line": line,
                "source_record_hash": row_hash, "source_name": family, "terminal_stage": stage,
                "status": "quarantined" if stage in {"quarantine", "contaminated", "pre_api"} else "rejected" if stage else "processing_error",
                "reason": "api_review_pending" if stage == "pre_api" else reason or "missing_terminal_outcome",
                "keeper_id": keeper}) + "\n")
    with safe_output(audit.output / "source_dispositions.jsonl").open("x", encoding="utf-8") as stream:
        for path, family, n, boundary, original_status, original_reason, status, reason, file_hash, byte_size, hash_after in audit.db.execute(
                "SELECT path,family,n,boundary,status,reason,build_status,build_reason,sha,bytes,sha_after FROM files ORDER BY path"):
            # Keep the indexed source lookup outermost; a reordered join scans all candidates per file.
            candidate_counts = dict(audit.db.execute(f"""SELECT m.stage,COUNT(*) FROM candidates c CROSS JOIN members m ON c.id=m.id
                WHERE c.source=? AND m.stage IN ({placeholders}) GROUP BY m.stage""", (path, *TERMINALS)))
            generated_counts = dict(audit.db.execute("SELECT status,COUNT(*) FROM generated WHERE source=? GROUP BY status", (path,)))
            stream.write(canonical_json({"source_file": path, "source_name": family, "identified_records": n,
                "record_boundary_complete": bool(boundary), "source_sha256_before": file_hash, "source_sha256_after": hash_after, "source_bytes": byte_size,
                "inventory_status": original_status, "inventory_reason": original_reason,
                "generation_status": status, "generation_reason": reason, "generation_record_status_counts": generated_counts,
                "candidate_terminal_counts": candidate_counts, "final_status": "processing_error" if status is None else "quarantined",
                "final_reason": "api_review_and_release_approval_pending" if candidate_counts.get("pre_api") else
                                "candidate_validation_or_selection_blocked" if candidate_counts else reason,
                "license_release_clearance": "not_granted_by_this_audit"}) + "\n")
    with safe_output(audit.output / "blocked_sources.jsonl").open("x", encoding="utf-8") as stream:
        for family, files, records, boundaries in audit.db.execute(
                "SELECT family,COUNT(*),COALESCE(SUM(n),0),SUM(boundary=0) FROM files GROUP BY family ORDER BY family"):
            reasons = dict(audit.db.execute("SELECT COALESCE(build_reason,'missing_generation_disposition'),COUNT(*) FROM files WHERE family=? GROUP BY build_reason", (family,)))
            candidate_reasons = dict(audit.db.execute("SELECT m.reason,COUNT(*) FROM candidates c JOIN members m ON c.id=m.id WHERE c.family=? AND m.stage='quarantine' GROUP BY m.reason", (family,)))
            stream.write(canonical_json({"source_name": family, "files": files, "identified_records": records,
                "unresolved_boundary_files": boundaries, "file_generation_reasons": reasons,
                "candidate_validation_reasons": candidate_reasons, "status": "blocked_pending_review_and_release_gates",
                "release_license_status": "no_release_approval"}) + "\n")


def create_audited_release(run, results, review_plan, verification, inventory_audit):
    """Create a new audit attempt. All failures are recorded; no release is made.

    `inventory_audit` must be the completed independent range audit tied to this
    manifest. Return accounting_passed separately from semantic scope and release
    gates. A successful identity reconciliation is not a release authorization.
    """
    run = safe_output(run)
    if not run.is_dir():
        raise ValueError("Assigned run does not exist")
    parent = safe_output(run / "release" / "audits")
    parent.mkdir(parents=True, exist_ok=True)
    name = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ_") + uuid.uuid4().hex
    output = safe_output(parent / name)
    output.mkdir()
    audit = _Audit(run, output)
    try:
        checkpoints = {n: safe_output(run / relative) for n, relative in CHECKPOINTS.items()}
        config = audit.object(run / "configuration.json")
        exclusion = validate_source_exclusion(checkpoints[1], config, freeze=False)
        if exclusion is not None and not exclusion["frozen"]:
            raise ValueError("release_audit_requires_frozen_source_exclusion")
        audit.source_exclusion = exclusion
        reconciliation = None
        ledger_base = checkpoints[1]
        if exclusion is not None and historical_source_exclusion(exclusion) != exclusion:
            from .scope_reconciliation import validate_scope_reconciliation
            reconciliation = validate_scope_reconciliation(run, config, results.get("scope_reconciliation"))
            if results.get("scope_reconciliation") != reconciliation["reference"]:
                audit.error("source_exclusion_reconciliation_reference_missing_or_changed")
            if results.get("1") != reconciliation["statistics"] or inventory_audit != reconciliation["audit"]:
                audit.error("source_exclusion_reconciliation_effective_statistics_mismatch")
            ledger_base = safe_output(run / reconciliation["artifacts_base_relative_to_run"])
            # The independent validator measured all of these bytes and reran the
            # accepted-file/raw-candidate proof; preserve those exact input pins.
            audit.artifacts.update(reconciliation["artifact_pins"])
        elif results.get("scope_reconciliation") is not None:
            audit.error("source_exclusion_unexpected_reconciliation_reference")
        if results.get("1", {}).get("source_exclusion_amendment") != exclusion:
            audit.error("source_exclusion_inventory_statistics_mismatch")
        if inventory_audit.get("source_exclusion_amendment") != exclusion:
            audit.error("source_exclusion_inventory_audit_mismatch")
        if exclusion is not None:
            reference = exclusion
            while reference is not None:
                for source_path in source_exclusion_artifact_paths(checkpoints[1], reference).values():
                    audit.object(source_path)
                reference = reference.get("predecessor")
            accounting = results.get("1", {}).get("source_exclusion_accounting", {})
            if inventory_audit.get("source_exclusion_accounting") != accounting:
                audit.error("source_exclusion_inventory_ledger_reference_mismatch")
            refs = accounting.get("artifacts", {})
            if set(refs) != {"files.jsonl", "record_ranges.jsonl", "checksums.json"} or any(not _relative(v) for v in refs.values()):
                audit.error("source_exclusion_invalid_ledger_references")
            else:
                checksum_path = ledger_base / refs["checksums.json"]
                checksums = audit.object(checksum_path)
                if (audit.artifacts.get(audit.label(checksum_path), {}).get("sha256") != accounting.get("checksums_sha256")
                        or checksums.get("source_exclusion_amendment_sha256") != exclusion["sha256"]
                        or checksums.get("source_manifest_sha256") != inventory_audit.get("input_identity", {}).get("manifest_sha256")
                        or checksums.get("counts") != accounting.get("counts")):
                    audit.error("source_exclusion_ledger_checksum_identity_mismatch")
                for name in ("files.jsonl", "record_ranges.jsonl"):
                    artifact = ledger_base / refs[name]
                    for _ in audit.rows(artifact):
                        pass
                    measured_artifact = audit.artifacts.get(audit.label(artifact), {})
                    expected_artifact = checksums.get("artifacts", {}).get(name, {})
                    if (measured_artifact.get("sha256") != expected_artifact.get("sha256")
                            or measured_artifact.get("bytes") != expected_artifact.get("size_bytes")):
                        audit.error("source_exclusion_ledger_artifact_changed", artifact=name)
        # Generic artifact errors in source evidence must also close its gate.
        source_evidence_passed = not audit.error_counts
        schema_path = checkpoints[4] / "configuration_snapshot" / "schemas" / "canonical-sft.schema.json"
        if schema_path.exists():
            schema = audit.object(schema_path)
        else:
            # Synthetic and pre-checkpoint runs use the repository schema; pin it
            # in the audit explicitly so this fallback is visible and reproducible.
            schema_path = safe_output(PIPELINE_ROOT / "schemas" / "canonical-sft.schema.json")
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        _write_json(output / "canonical-sft.schema.json", schema)
        prior_source_errors = audit.error_counts.copy()
        _inventory(audit, checkpoints[1], inventory_audit)
        _source_reverification(audit, verification, checkpoints[5])
        source_evidence_passed = source_evidence_passed and audit.error_counts == prior_source_errors
        _source_dispositions(audit, checkpoints[2], 2)
        _source_dispositions(audit, checkpoints[3], 3)
        # Only complete published shards are read, never partial batch journals.
        raw_paths = sorted(checkpoints[3].glob("shards/*/candidates.jsonl"))
        _load_candidates(audit, raw_paths, "raw", validator)
        _generation_records(audit, checkpoints[3])
        _load_candidates(audit, [checkpoints[4] / "validated.jsonl"], "validated", validator)
        _load_candidates(audit, [checkpoints[4] / "quarantined.jsonl"], "quarantine", validator, "candidate")
        _decisions(audit, checkpoints[4])
        contamination = checkpoints[4] / "contamination"
        _load_candidates(audit, [contamination / "clean_candidates.jsonl"], "clean", validator)
        _load_candidates(audit, [contamination / "contaminated_candidates.jsonl"], "contaminated", validator, "candidate")
        contamination_report = audit.object(contamination / "report.json")
        equations = [audit.partition("raw", ("validated", "quarantine")), audit.partition("validated", ("clean", "contaminated"))]
        complete = checkpoints[5] / "completed"
        previous = "clean"
        stage_statistics = []
        for stage in STAGES:
            _load_candidates(audit, [complete / stage / "survivors.jsonl"], stage, validator)
            _load_candidates(audit, [complete / stage / "removals.jsonl"], stage + "_removed", validator, "record")
            equations.append(audit.partition(previous, (stage, stage + "_removed")))
            stage_statistics.append({"stage": stage[3:], "entering": audit.members(previous), "surviving": audit.members(stage),
                "removed": audit.members(stage + "_removed"), "removal_rate": audit.members(stage + "_removed") / audit.members(previous) if audit.members(previous) else None})
            audit.query_errors("dedup_keeper_missing", """SELECT r.id,r.keeper FROM members r LEFT JOIN members k ON k.id=r.keeper AND k.stage=?
                WHERE r.stage=? AND k.id IS NULL""", ("example_id", "keeper_id"), (stage, stage + "_removed"))
            declared = audit.object(complete / stage / "statistics.json")
            for metric, expected in (("entering", audit.members(previous)), ("surviving", audit.members(stage)),
                                     ("removed", audit.members(stage + "_removed"))):
                if declared.get(metric) != expected:
                    audit.error("dedup_stage_statistics_mismatch", stage=stage, metric=metric)
            previous = stage
        _load_candidates(audit, [complete / "pre_api" / "balancing_removals.jsonl"], "capped", validator, "record")
        for split in ("train", "validation", "test"):
            _load_candidates(audit, [complete / "pre_api" / split / "canonical.jsonl"], "pre_api", validator, split=split)
        equations.append(audit.partition(previous, ("capped", "pre_api")))
        _split_audit(audit, complete)
        leakage = audit.object(complete / "pre_api" / "leakage.json")
        fertility = audit.object(complete / "pre_api" / "fertility.json")
        _terminal_reports(audit)
        measured = {
            "source_files": audit.count("SELECT COUNT(*) FROM files"),
            "source_bytes": audit.count("SELECT COALESCE(SUM(bytes),0) FROM files"),
            "identified_source_records": audit.count("SELECT COALESCE(SUM(n),0) FROM files"),
            "unresolved_boundary_files": audit.count("SELECT COUNT(*) FROM files WHERE boundary=0"),
            "planned_files": audit.count("SELECT COUNT(*) FROM files WHERE plan_seen=1"),
            "generation_classified_files": audit.count("SELECT COUNT(*) FROM files WHERE build_seen=1"),
            "individual_generation_record_dispositions": audit.count("SELECT COUNT(*) FROM generated"),
            "range_quarantined_records": audit.count("SELECT COALESCE(SUM(n),0) FROM files WHERE build_status<>'accepted'"),
            "raw_candidates": audit.members("raw"), "deterministic_accepted": audit.members("validated"),
            "deterministic_quarantined": audit.members("quarantine"), "contamination_quarantined": audit.members("contaminated"),
            "dedup_removed": sum(audit.members(s + "_removed") for s in STAGES), "domain_cap_removed": audit.members("capped"),
            "awaiting_api_review": audit.members("pre_api"), "released_records": 0,
        }
        if exclusion is not None:
            for label, condition in (("historical_excluded", "excluded=1"), ("in_scope", "excluded=0")):
                for field, query in (("files", "COUNT(*)"), ("bytes", "COALESCE(SUM(bytes),0)"),
                                     ("identified_records", "COALESCE(SUM(n),0)")):
                    metric = label + "_" + field
                    measured[metric] = audit.count("SELECT " + query + " FROM files WHERE " + condition)
                    if results.get("1", {}).get("statistics", {}).get(metric) != measured[metric]:
                        audit.error("source_exclusion_partition_count_mismatch", metric=metric)
        expected_metrics = {
            ("2", "source_files"): measured["source_files"], ("2", "source_records"): measured["identified_source_records"],
            ("3", "source_files"): measured["source_files"], ("3", "source_records"): measured["identified_source_records"],
            ("3", "classified_records"): measured["identified_source_records"], ("3", "candidates"): measured["raw_candidates"],
            ("4", "candidates_entering"): measured["raw_candidates"], ("4", "candidates_leaving"): measured["deterministic_accepted"],
            ("5", "input_candidates"): audit.members("clean"), ("5", "awaiting_api_review"): measured["awaiting_api_review"],
            ("5", "dedup_removed"): measured["dedup_removed"], ("5", "domain_cap_removed"): measured["domain_cap_removed"],
        }
        for (number, metric), expected in expected_metrics.items():
            if results.get(number, {}).get(metric) != expected:
                audit.error("checkpoint_statistics_mismatch", pass_number=int(number), metric=metric, measured=expected)
        if review_plan.get("candidates") != measured["awaiting_api_review"]:
            audit.error("api_estimate_candidate_count_mismatch")
        if measured["identified_source_records"] != measured["individual_generation_record_dispositions"] + measured["range_quarantined_records"]:
            audit.error("source_record_flow_equation_failed")
        if measured["raw_candidates"] != sum(measured[k] for k in ("deterministic_quarantined", "contamination_quarantined", "dedup_removed", "domain_cap_removed", "awaiting_api_review")):
            audit.error("candidate_terminal_count_equation_failed")
        for metric, expected in (("input", measured["deterministic_accepted"]),
                                 ("quarantined", measured["contamination_quarantined"]),
                                 ("clean_against_available_evaluations", audit.members("clean"))):
            if contamination_report.get("counts", {}).get(metric, 0) != expected:
                audit.error("contamination_statistics_mismatch", metric=metric)
        for number, checkpoint in checkpoints.items():
            declared = audit.object(checkpoint / "statistics.json")
            # Fresh resume verification legitimately differs from checkpoint five.
            expected = {k: v for k, v in results.get(str(number), {}).items() if number != 5 or k != "source_verification"}
            actual = {k: v for k, v in declared.items() if number != 5 or k != "source_verification"}
            if number == 1 and reconciliation is not None:
                # Check the preserved checkpoint against its pinned historical
                # statistics; current pass-one figures were separately validated.
                expected = reconciliation["inputs"]["checkpoint_statistics"]["1"]
            if digest(actual) != digest(expected):
                audit.error("supplied_checkpoint_statistics_mismatch", pass_number=number)
        inventory_stats = results.get("1", {}).get("statistics", {})
        for metric, key in (("files", "source_files"), ("bytes", "source_bytes"), ("records", "identified_source_records")):
            if inventory_stats.get(metric) != measured[key]:
                audit.error("inventory_statistics_mismatch", metric=metric)
        if reconciliation is not None:
            final_reconciliation = validate_scope_reconciliation(run, config, reconciliation["reference"])
            if final_reconciliation != reconciliation:
                audit.error("source_exclusion_reconciliation_changed_during_audit")
        if validate_source_exclusion(checkpoints[1], config, freeze=False) != exclusion:
            audit.error("source_exclusion_changed_during_release_audit")
        accounting_passed = not audit.error_counts
        schema_passed = not audit.metrics["validated_schema_failed"] and not audit.metrics["pre_api_schema_failed"]
        actual_schema_count = audit.metrics["pre_api_schema_checked"]
        confirmed_boundaries = exclusion is None and measured["unresolved_boundary_files"] == 0 and inventory_audit.get("complete_semantic_record_coverage") is True
        scoped_unchanged = source_evidence_passed and verification.get("passed") is True and not any(code.startswith(("source_verification", "supplied_source_verification", "invalid_source_verification", "invalid_source_integrity", "source_exclusion")) for code in audit.error_counts)
        source_unchanged = scoped_unchanged and exclusion is None
        gates = {
            "file_coverage": {"passed": accounting_passed, "measured": measured["source_files"],
                              "scope": "historical_known_and_current_in_scope_files" if exclusion else "original_source_tree"},
            "identified_record_accounting": {"passed": accounting_passed, "measured": measured["identified_source_records"]},
            "complete_semantic_record_coverage": {"passed": confirmed_boundaries, "unresolved_files": measured["unresolved_boundary_files"]},
            "canonical_schema": {"passed": accounting_passed and schema_passed, "candidate_records_checked": actual_schema_count, "scope": "pre_api_candidates"},
            "deterministic_validation": {"passed": accounting_passed, "scope": "identity_join_to_pass_four_outcomes"},
            "all_api_reviews_accepted": {"passed": False, "reason": "API_disabled_no_final_review_set", "pending": measured["awaiting_api_review"]},
            "verified_licenses": {"passed": False, "reason": "Final_release_license_audit_and_legal_approval_pending"},
            "sensitive_data": {"passed": False, "reason": "Final_privacy_assessment_and_independent_review_pending"},
            "exact_deduplication": {"passed": accounting_passed and leakage.get("remaining_exact_duplicates") == 0, "scope": "pre_api_candidates"},
            "split_leakage": {"passed": accounting_passed and leakage.get("passed") is True, "scope": "Exact_groups_and_detected_near_pairs;near_detection_algorithm_not_independently_reexecuted"},
            "benchmark_contamination": {"passed": accounting_passed and contamination_report.get("complete") is True, "scope": "Configured_lexical_comparisons;semantic_contamination_unproven"},
            "source_hashes_unchanged": {"passed": source_unchanged, "scope": "original_source_tree"},
            "scoped_source_hashes_unchanged": {"passed": scoped_unchanged, "scope": "approved_current_source_scope"},
            "counts_reconciled": {"passed": accounting_passed},
            "release_auditor": {"passed": False, "reason": "Pre_API_audit_only;required_release_gates_unresolved"},
        }
        by_source = {}
        for family, in audit.db.execute("SELECT DISTINCT family FROM files ORDER BY family"):
            entry = {"raw_candidates": audit.count("SELECT COUNT(*) FROM candidates WHERE family=?", (family,))}
            entry["candidate_outcomes"] = dict(audit.db.execute(f"""SELECT m.stage,COUNT(*) FROM candidates c JOIN members m ON c.id=m.id
                WHERE c.family=? AND m.stage IN ({','.join('?' for _ in TERMINALS)}) GROUP BY m.stage""", (family, *TERMINALS)))
            entry["api_review"] = {"reviewed": 0, "accepted": 0, "revised": 0, "rejected": 0,
                "acceptance_rate": None, "revision_rate": None, "rejection_rate": None,
                "pending": entry["candidate_outcomes"].get("pre_api", 0)}
            by_source[family] = entry
        dimensions = {}
        for name, column in (("source", "family"), ("domain", "domain"), ("task_type", "task")):
            dimensions[name] = dict(audit.db.execute(f"SELECT c.{column},COUNT(*) FROM candidates c JOIN splits s ON c.id=s.id GROUP BY c.{column}"))
        dimensions["split"] = dict(audit.db.execute("SELECT split,COUNT(*) FROM splits GROUP BY split"))
        validation_reasons = dict(audit.db.execute("SELECT reasons,COUNT(*) FROM decisions WHERE status='quarantined' GROUP BY reasons"))
        greek_mean = audit.db.execute("SELECT AVG(greek_ratio) FROM decisions").fetchone()[0]
        summary = {"audit_version": VERSION, "created_at": utcnow(), "run_id": run.name, "release_ready": False,
            "status": "blocked_pre_api_audit", "accounting_passed": accounting_passed, "measured": measured,
            "inventory_scope_amendment": results.get("1", {}).get("inventory_scope_amendment"),
            "source_exclusion_amendment": exclusion,
            "source_exclusion_accounting": results.get("1", {}).get("source_exclusion_accounting"),
            "scope_reconciliation": reconciliation["reference"] if reconciliation else None,
            "historical_checkpoint_scopes": ({number: reconciliation["inputs"]["checkpoint_statistics"][number].get("source_exclusion_amendment_sha256")
                for number in ("2", "3", "4")} if reconciliation else None),
            "full_original_source_integrity": source_unchanged,
            "current_excluded_coverage": "unknown" if exclusion else "not_applicable",
            "equations": equations, "error_counts": dict(audit.error_counts), "gates": gates, "deduplication": stage_statistics,
            "counts": dimensions, "by_source": by_source, "schema_checks": dict(audit.metrics),
            "validation_reason_combinations": validation_reasons, "greek_quality": {"mean_user_greek_ratio": greek_mean,
                "grammar_and_naturalness": "unresolved_independent_review_required"},
            "contamination": contamination_report, "leakage": leakage, "fertility": fertility,
            "api": {"enabled": False, "calls_made_by_audit": 0, "reviewed": 0, "accepted": 0, "revised": 0,
                "rejected": 0, "pending": measured["awaiting_api_review"], "acceptance_rate": None, "revision_rate": None, "rejection_rate": None},
            "seed": config.get("seed"), "limitations": [
                "No final dataset is released by this audit; final human and legal approval remains required.",
                "Unknown semantic record boundaries remain unresolved even when all identifiable rows reconcile.",
                "Greek grammar, naturalness, safety and privacy are not established by lexical heuristics.",
                "Existing detected-near-pair artifacts are checked for leakage; exhaustive similarity is not recomputed here.",
                "API review has not run; empty acceptance/revision/rejection rates are null, never 100 percent."]}
        _write_json(output / "report.json", summary)
        _write_json(output / "release_gates.json", {"release_ready": False, "gates": gates})
        _write_json(output / "inventory_audit_reference.json", inventory_audit)
        if reconciliation is not None:
            _write_json(output / "scope_reconciliation_reference.json", reconciliation["reference"])
        if summary["inventory_scope_amendment"] is not None:
            _write_json(output / "inventory_scope_amendment_reference.json", summary["inventory_scope_amendment"])
        if exclusion is not None:
            _write_json(output / "source_exclusion_amendment_reference.json", exclusion)
            _write_json(output / "source_exclusion_accounting_reference.json", summary["source_exclusion_accounting"])
            original = exclusion
            while original.get("predecessor") is not None:
                original = original["predecessor"]
            _write_json(output / "original_integrity_incident_reference.json", {
                "path": original["amendment"]["integrity_incident_path"],
                "sha256": original["amendment"]["integrity_incident_sha256"]})
            _write_json(output / "effective_integrity_incident_reference.json", {
                "path": exclusion["amendment"]["integrity_incident_path"],
                "sha256": exclusion["amendment"]["integrity_incident_sha256"]})
        _write_json(output / "input_artifacts.json", audit.artifacts)
        with safe_output(output / "statistics.jsonl").open("x", encoding="utf-8") as stream:
            for metric, value in measured.items():
                stream.write(canonical_json({"metric": metric, "value": value}) + "\n")
            for family, counts in by_source.items():
                stream.write(canonical_json({"source_name": family, **counts}) + "\n")
        _markdown_reports(output, summary, config, run.name)
    except BaseException as error:
        audit.error("audit_execution_failed", error_type=type(error).__name__)
        raise
    finally:
        audit.close()
    checksums = []
    for path in sorted(output.iterdir()):
        if path.is_file():
            checksums.append(sha256_file(path) + "  " + path.name)
    _write_text(output / "SHA256SUMS", "\n".join(checksums) + "\n")
    return {"accounting_passed": accounting_passed, "candidate_count": measured["awaiting_api_review"],
            "release_ready": False, "audit_path": str(output.relative_to(run)),
            "report_path": str((output / "report.json").relative_to(run)), "error_counts": dict(audit.error_counts)}


def _markdown_reports(output, summary, config, run_id):
    m = summary["measured"]
    scope_note = ("\nUser-approved record-scan exclusions and the applied amendment checksum are preserved in "
        "`inventory_scope_amendment_reference.json`. Previously scanned records remain accounted for. "
        "Excluded unscanned records are unassessed; zero identified rows does not mean an empty source. "
        + ("All original files remain within the byte-hash inventory and final source-integrity check.\n"
           if summary.get("source_exclusion_amendment") is None else
           "The later source-coverage exception below narrows the original all-file hash requirement.\n")
        if summary.get("inventory_scope_amendment") is not None else "")
    if summary.get("source_exclusion_amendment") is not None:
        exclusion = summary["source_exclusion_amendment"]
        roots = ", ".join("`" + root + "/`" for root in exclusion["amendment"]["excluded_source_roots"])
        if exclusion.get("predecessor"):
            scope_note += "\nThe earlier `greek_training/.git/` authorization and integrity incident remain preserved as predecessor evidence. The user clarified that `greek_training` is a mixture of other collections and must not produce SFT.\n"
        scope_note += (f"\nThe user-authorized {roots} exclusion is pinned in "
            "`source_exclusion_amendment_reference.json` and bound to the preserved original integrity incident. "
            "Historical excluded file hashes, statuses and row ranges remain accounted for. They are not current verified files. "
            "Current contents, added/removed files and record totals inside that directory are unknown and unassessed. "
            "The separate scoped integrity gate covers every file outside that exact subtree; full-original-tree integrity "
            "remains failed. Historical excluded and current in-scope counts are shown separately in `report.json`.\n")
    if summary.get("scope_reconciliation") is not None:
        scope_note += ("\nThe later temporary-collection exclusion is reconciled separately in "
            "`scope_reconciliation_reference.json`. Checkpoints one through four retain their original bytes and "
            "historical statistics. Independent reuse checks found no accepted planning/generation files or raw "
            "candidates from any currently excluded root. Effective coverage is a separate derived inventory view.\n")
    counts = "\n".join(f"| {name.replace('_', ' ')} | {count:,} |" for name, count in m.items())
    blocked = [name for name, result in summary["gates"].items() if not result["passed"]]
    _write_text(output / "dataset_card.md", "# Greek SFT pre-API audit — blocked\n\n"
        "This immutable report describes internal candidates and their dispositions. No training dataset is released. "
        "Only after every required gate passes may an eligible result be called a **release-grade Greek SFT candidate**; "
        "final human and legal approval remains required.\n\n| Measured quantity | Count |\n| --- | ---: |\n" + counts +
        "\n\nUnresolved gates: " + ", ".join(blocked) + ".\n\nMachine-readable evidence is in `report.json`, "
        "`candidate_dispositions.jsonl`, `source_dispositions.jsonl`, and `blocked_sources.jsonl`.\n")
    _write_text(output / "provenance_report.md", f"# Provenance and coverage\n\n"
        f"Inventoried files: **{m['source_files']:,}**; source bytes: **{m['source_bytes']:,}**; "
        f"identified records: **{m['identified_source_records']:,}**. "
        f"Files with unresolved semantic record boundaries: **{m['unresolved_boundary_files']:,}**.\n\n"
        "The inventory manifest identifies file hashes and original statuses. Its independent range audit is pinned in "
        "`inventory_audit_reference.json`. Its source_file_duplicates section reports byte-identical source-file groups; the artifact base is relative to the run directory. Sidecar/cache matches are separated, and complete record-level duplication remains unassessed. Both planning and generation dispositions were joined to exact file identities, "
        "counts, boundary flags and family names. Selected source rows were joined to candidate IDs and row hashes. "
        "Candidates were partitioned by exact ID and stable content hash at every subsequent stage. "
        "No source text is copied into these reports.\n\n"
        f"Identified accounting passed: **{summary['accounting_passed']}**. Supplied full source hash verification passed: "
        f"**{summary['gates']['source_hashes_unchanged']['passed']}**. Unknown record boundaries remain unresolved.\n" + scope_note)
    _write_text(output / "license_report.md", "# License and redistribution status\n\n"
        f"All **{m['source_files']:,}** source files are represented in `source_dispositions.jsonl`; every source family "
        "is listed in `blocked_sources.jsonl`. These reports preserve original source reasons and candidate rejection "
        "combinations, including unresolved license and privacy decisions. Processing authorization does not establish "
        "training or redistribution rights. This audit grants no license and provides no legal certification.\n\n"
        "No records are released. A final release requires hash-scoped approved license evidence for every included record "
        "and final legal approval.\n")
    _write_text(output / "quality_report.md", "# Quality and candidate accounting\n\n"
        f"Raw candidates: **{m['raw_candidates']:,}**. Deterministically accepted: **{m['deterministic_accepted']:,}**; "
        f"quarantined: **{m['deterministic_quarantined']:,}**. Awaiting API review after selection: **{m['awaiting_api_review']:,}**.\n\n"
        "`report.json` includes independent schema checks, stage equations, clean per-source/domain/task/split counts, "
        "deduplication removal rates, exact/group/detected-near-pair split checks, validation reason combinations, "
        "Greek script statistics and tokenizer fertility results. `errors.jsonl` contains every audit discrepancy. "
        "`accounting.sqlite` preserves disk-backed identity joins without message or evidence text.\n\n"
        "Greek script ratios do not establish grammar or naturalness. Pattern-based PII and safety checks do not resolve "
        "all sensitive-data risks. API reviewed/accepted/revised/rejected counts are zero; their rates are null because "
        "no reviews have run. Canary reliability, full review approval and final human assessment remain required.\n")
    references = summary["contamination"].get("references", [])
    benchmarks = "\n".join(f"- {r.get('name', 'unknown')}: {r.get('records', 0):,} reference rows; SHA-256 `{r.get('sha256', 'missing')}`." for r in references)
    _write_text(output / "contamination_report.md", "# Benchmark and split contamination\n\n"
        f"Candidates quarantined by benchmark comparison: **{m['contamination_quarantined']:,}**. "
        f"Configured benchmark coverage complete: **{summary['contamination'].get('complete') is True}**.\n\n" +
        (benchmarks + "\n\n" if benchmarks else "No benchmark reference was recorded.\n\n") +
        "GreekMMLU and any supplied evaluation datasets are comparison-only references and never become training examples. "
        "Missing or unconfirmed private evaluation scope blocks a complete contamination claim. Lexical matching cannot "
        "prove absence of semantic paraphrases. Short generic matches require false-positive review. "
        "This audit independently joins source groups and detected near pairs across splits; it does not rerun the full "
        "similarity search. Complete fingerprints and limitations are preserved in `report.json`.\n")
    _write_text(output / "reproduction_instructions.md", "# Reproduction\n\n"
        f"From PIPELINE_ROOT, resume with `python3 -B scripts/run_pipeline.py --run-id {run_id} --through 5`. "
        "Never edit the source tree. Configuration changes require a new run. Each checkpoint contains its configuration, "
        "code snapshots, manifest, checksums and errors. This audit pins the exact JSONL artifacts it read in "
        f"`input_artifacts.json`; its own artifacts are covered by `SHA256SUMS`. Seed: `{config.get('seed', 'unspecified')}`. "
        f"Audit implementation: `{VERSION}`.\n\n"
        "Call `greek_sft.reporting.create_audited_release(run, results, review_plan, verification, inventory_audit)` after "
        "all five checkpoints and a fresh source verification. Every call creates a distinct immutable audit directory. "
        "No existing report is overwritten. API provider/protocol, endpoint, model, key environment-variable name, "
        "rate/concurrency/timeouts/retries, budgets and external-data permissions must be supplied and approved separately. "
        "Never place credentials in tracked files. Estimate and approve a small canary before separately approving full review.\n")
