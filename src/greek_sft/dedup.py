"""Conservative, auditable pass-five deduplication and grouped candidate splits.

No dataset produced here is a release: API review is still required.  This module
never downloads a tokenizer, changes input files, trims sentences, or packs text.
SQLite stores the corpus and indexes; memory use is bounded by the largest record
and its candidate-neighbour set. Completed artifacts are checksummed and reusable;
an interrupted attempt remains on disk and a new attempt uses a fresh directory.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import shutil
import sqlite3
import struct
import unicodedata
import uuid
from collections import Counter


VERSION = "dedup-1.1.0"
PIPELINE_ROOT = Path("/datadisk2/greekllm/GreekLLM_sft_pipeline")
SOURCE_ROOT = Path("/datadisk2/greekllm/GreekLLM_jsonl")
STAGES = ("ExactSubstrings", "MinhashDedup", "SentenceDedup")
PROTECTED_DOMAINS = {"legal", "religious", "academic", "historical", "educational"}


class DedupError(RuntimeError):
    """An unresolved integrity or resource issue; never silently skip a record."""


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _hash_file(path):
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return {"sha256": digest.hexdigest(), "bytes": size}


def _reject_symlinks(path):
    path = Path(path).absolute()
    if any(component.is_symlink() for component in (path, *path.parents)):
        raise DedupError("Symlink output paths are forbidden")
    return path


def _safe_output(path):
    path = Path(path).absolute()
    resolved = path.resolve()
    root = PIPELINE_ROOT.resolve()
    source = SOURCE_ROOT.resolve()
    if resolved == root or not resolved.is_relative_to(root):
        raise DedupError("Output must be a child of PIPELINE_ROOT")
    if resolved == source or resolved.is_relative_to(source):
        raise DedupError("Refusing an output path within SOURCE_ROOT")
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise DedupError("Symlink output paths are forbidden")
    path.mkdir(parents=True, exist_ok=True)
    return resolved


def _write_json(path, value):
    # Publish complete metadata atomically without replacing an existing file.
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    with temporary.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(_json(value) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.link(temporary, path)
    temporary.unlink()
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _records(paths):
    for path in paths:
        with Path(path).open("r", encoding="utf-8", errors="strict") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    raise DedupError(f"Empty JSONL record at input {Path(path).name}:{line_number}")
                try:
                    record = json.loads(line)
                    metadata = record["metadata"]
                    messages = record["messages"]
                    if not isinstance(record["id"], str) or not record["id"]:
                        raise ValueError("missing ID")
                    if [m["role"] for m in messages] != ["system", "user", "assistant"]:
                        raise ValueError("invalid message order")
                    if any(not isinstance(m["content"], str) or not m["content"].strip() for m in messages):
                        raise ValueError("empty message")
                    if any(not isinstance(metadata.get(k), str) or not metadata[k].strip()
                           for k in ("source_name", "source_file", "source_record_id", "split_group", "task_type")):
                        raise ValueError("missing lineage/group/task")
                except (ValueError, TypeError, KeyError) as error:
                    raise DedupError(f"Invalid canonical record at input {Path(path).name}:{line_number}") from error
                yield record


def _normal(text):
    return " ".join(unicodedata.normalize("NFC", text).casefold().split())


def source_derived_text(record):
    """Use user evidence and the grounded answer; exclude the system entirely.

    Producers may identify the exact evidence span with metadata.grounding_span
    = {"message_index": 1, "start": ..., "end": ...}. No raw duplicate text is
    added to public metadata. Without spans the user context and answer are used
    conservatively; sentence-stage thresholds prevent boilerplate-only removal.
    """
    messages = record["messages"]
    user = messages[1]["content"]
    span = record["metadata"].get("grounding_span")
    if span is not None:
        if (not isinstance(span, dict) or span.get("message_index") != 1
                or type(span.get("start")) is not int or type(span.get("end")) is not int
                or not 0 <= span["start"] < span["end"] <= len(user)):
            raise DedupError("Invalid source-evidence span")
        user = user[span["start"]:span["end"]]
    return user + "\n" + messages[2]["content"]


def _shingles(text, width):
    words = re.findall(r"\w+", _normal(text), flags=re.UNICODE)
    if len(words) < width:
        return set()
    return {int.from_bytes(hashlib.blake2b(" ".join(words[i:i + width]).encode(), digest_size=8).digest(), "big")
            for i in range(len(words) - width + 1)}


def _jaccard(left, right):
    return len(left & right) / len(left | right) if left and right else 0.0


def _sentences(text):
    # Include short sentences too: dropping them could discard a unique fact.
    return {_normal(sentence) for sentence in re.split(r"(?<=[.!?;·;])\s+|\n+", text) if sentence.strip()}


def _settings(config):
    supplied = config.get("dedup", {})
    settings = {
        "substring_min_chars": 240, "anchor_chars": 32,
        "minhash_threshold": 0.90, "shingle_words": 5,
        "minhash_permutations": 64, "minhash_bands": 8,
        "sentence_min_chars": 240, "seed": 1729,
        "max_candidate_pairs": 5_000_000, "overdedup_warning_rate": 0.20,
    }
    settings.update({k: supplied[k] for k in settings if k in supplied})
    for key in ("substring_min_chars", "anchor_chars", "shingle_words", "minhash_permutations",
                "minhash_bands", "sentence_min_chars", "max_candidate_pairs"):
        if type(settings[key]) is not int or settings[key] <= 0:
            raise DedupError(f"{key} must be a positive integer")
    if settings["substring_min_chars"] < 2 * settings["anchor_chars"]:
        raise DedupError("substring_min_chars must be at least twice anchor_chars")
    if not 0.8 <= settings["minhash_threshold"] <= 1:
        raise DedupError("Near-duplicate threshold must be conservative (0.8 to 1)")
    if settings["minhash_permutations"] % settings["minhash_bands"]:
        raise DedupError("minhash_permutations must be divisible by minhash_bands")
    settings["splits"] = config.get("splits", {"train": 0.9, "validation": 0.05, "test": 0.05})
    splits = settings["splits"]
    if (set(splits) != {"train", "validation", "test"}
            or any(type(v) not in (int, float) or not math.isfinite(v) or v < 0 for v in splits.values())
            or not math.isclose(sum(splits.values()), 1.0)):
        raise DedupError("splits must have nonnegative train/validation/test fractions summing to one")
    settings["domain_caps"] = config.get("domain_caps", {})
    if any(type(v) is not int or v < 0 for v in settings["domain_caps"].values()):
        raise DedupError("domain_caps values must be nonnegative record counts")
    settings["tokenizer_local_path"] = config.get("tokenizer", {}).get("local_path")
    settings["tokenizer_snapshot"] = _tokenizer_snapshot(settings["tokenizer_local_path"])
    return settings


def _database(path):
    db = sqlite3.connect(path)
    db.execute("PRAGMA journal_mode=DELETE")
    db.execute("PRAGMA temp_store=MEMORY")
    db.execute("PRAGMA cache_size=-32768")
    db.execute("CREATE TABLE records(id TEXT PRIMARY KEY, record TEXT NOT NULL, text TEXT NOT NULL, n INTEGER NOT NULL, h TEXT NOT NULL)")
    db.execute("CREATE INDEX record_length ON records(n DESC,id)")
    return db


def _load(db, paths):
    count = 0
    for record in _records(paths):
        text = _normal(source_derived_text(record))
        try:
            db.execute("INSERT INTO records VALUES(?,?,?,?,?)", (record["id"], _json(record), text, len(text), hashlib.sha256(text.encode()).hexdigest()))
        except sqlite3.IntegrityError as error:
            raise DedupError("Duplicate candidate ID; record accounting would be ambiguous") from error
        count += 1
        if count % 1000 == 0:
            db.commit()
    db.commit()
    return count


def _anchors(text, width, query=False):
    positions = range(min(width, len(text) - width + 1)) if query else range(0, len(text) - width + 1, width)
    return {hashlib.sha256(text[i:i + width].encode()).digest() for i in positions}


def _candidate_limit(counter, settings):
    if counter > settings["max_candidate_pairs"]:
        raise DedupError("Candidate-pair safety limit exceeded; change workload plan explicitly")


def _stage(stage, inputs, directory, settings):
    directory.mkdir()
    db = _database(directory / "index.sqlite")
    count = _load(db, inputs)
    db.execute("CREATE TABLE kept(id TEXT PRIMARY KEY,h TEXT NOT NULL)")
    db.execute("CREATE INDEX kept_hash ON kept(h)")
    db.execute("CREATE TABLE index_entries(key BLOB NOT NULL,id TEXT NOT NULL,PRIMARY KEY(key,id)) WITHOUT ROWID")
    rng = random.Random(settings["seed"])
    prime = (1 << 61) - 1
    permutations = [(rng.randrange(1, prime), rng.randrange(prime)) for _ in range(settings["minhash_permutations"])]
    by_source = Counter()
    by_domain = Counter()
    removed_source = Counter()
    removed_domain = Counter()
    comparisons = removed = 0
    with (directory / "survivors.jsonl").open("x", encoding="utf-8") as survivors, (directory / "removals.jsonl").open("x", encoding="utf-8") as removals:
        for identity, raw, text, length, digest in db.execute("SELECT id,record,text,n,h FROM records ORDER BY n DESC,id"):
            record = json.loads(raw)
            metadata = record["metadata"]
            source, domain = metadata["source_name"], metadata.get("domain", "unknown")
            by_source[source] += 1
            by_domain[domain] += 1
            keys = set()
            candidates = set()
            keeper = None
            reason = None
            similarity = None
            if stage == "ExactSubstrings":
                exact = db.execute("SELECT id FROM kept WHERE h=? ORDER BY id LIMIT 1", (digest,)).fetchone()
                if exact:
                    keeper, reason = exact[0], "identical_source_derived_content"
                if keeper is None and length >= settings["substring_min_chars"]:
                    keys = _anchors(text, settings["anchor_chars"], query=True)
                insert_keys = _anchors(text, settings["anchor_chars"]) if length >= settings["substring_min_chars"] else set()
            elif stage == "MinhashDedup":
                shingles = _shingles(text, settings["shingle_words"])
                if shingles and length >= settings["substring_min_chars"]:
                    signature = [min((a * (x % prime) + b) % prime for x in shingles) for a, b in permutations]
                    band_width = settings["minhash_permutations"] // settings["minhash_bands"]
                    keys = {struct.pack(">I", band) + b"".join(struct.pack(">Q", x) for x in signature[band * band_width:(band + 1) * band_width])
                            for band in range(settings["minhash_bands"])}
                insert_keys = keys
            else:
                sentences = _sentences(source_derived_text(record))
                if length >= settings["sentence_min_chars"] and len(sentences) >= 2:
                    # Any containing survivor must contain this exact sentence.
                    first = min(sentences)
                    keys = {hashlib.sha256(first.encode()).digest()}
                insert_keys = {hashlib.sha256(s.encode()).digest() for s in sentences}
            for key in keys:
                candidates.update(row[0] for row in db.execute("SELECT id FROM index_entries WHERE key=?", (key,)))
                _candidate_limit(comparisons + len(candidates), settings)
            if keeper is None:
                for candidate_id in sorted(candidates):
                    comparisons += 1
                    _candidate_limit(comparisons, settings)
                    other_text, other_raw = db.execute("SELECT text,record FROM records WHERE id=?", (candidate_id,)).fetchone()
                    other = json.loads(other_raw)
                    if stage == "ExactSubstrings" and text in other_text:
                        keeper, reason = candidate_id, "whole_content_exact_substring"
                    elif stage == "MinhashDedup":
                        similarity = _jaccard(shingles, _shingles(other_text, settings["shingle_words"]))
                        # Similar passages with different answers/numbers must not
                        # disappear as presumed paraphrases of the same facts.
                        same_answer = _normal(record["messages"][2]["content"]) == _normal(other["messages"][2]["content"])
                        same_numbers = re.findall(r"\d+(?:[.,/]\d+)*", text) == re.findall(r"\d+(?:[.,/]\d+)*", other_text)
                        same_task = metadata["task_type"] == other["metadata"]["task_type"]
                        if similarity >= settings["minhash_threshold"] and same_answer and same_numbers and same_task:
                            keeper, reason = candidate_id, "verified_minhash_neighbour_same_answer_and_numbers"
                    elif stage == "SentenceDedup" and sentences <= _sentences(source_derived_text(other)):
                        keeper, reason = candidate_id, "all_sentences_present_in_single_survivor"
                    if keeper:
                        break
            if keeper:
                removed += 1
                removed_source[source] += 1
                removed_domain[domain] += 1
                event = {"stage": stage, "example_id": identity, "keeper_id": keeper, "reason": reason, "record": record}
                if similarity is not None:
                    event["verified_jaccard"] = similarity
                removals.write(_json(event) + "\n")
            else:
                survivors.write(raw + "\n")
                db.execute("INSERT INTO kept VALUES(?,?)", (identity, digest))
                db.executemany("INSERT OR IGNORE INTO index_entries VALUES(?,?)", ((key, identity) for key in insert_keys))
            if (removed + db.total_changes) % 1000 == 0:
                db.commit()
    db.commit()
    db.close()
    audit = {domain: {"entering": n, "removed": removed_domain[domain], "removal_rate": removed_domain[domain] / n,
                      "manual_overdedup_audit_required": domain.casefold() in PROTECTED_DOMAINS and removed_domain[domain] > 0}
             for domain, n in sorted(by_domain.items())}
    stats = {"stage": stage, "entering": count, "surviving": count - removed, "removed": removed,
             "removal_rate": removed / count if count else 0.0, "comparisons": comparisons,
             "entering_by_source": dict(by_source), "removed_by_source": dict(removed_source),
             "domain_audit": audit,
             "high_removal_rate": bool(count and removed / count > settings["overdedup_warning_rate"]),
             "method": "whole-record removal; original candidates preserved; system message excluded"}
    _write_json(directory / "statistics.json", stats)
    return stats


def _find(parent, identity):
    while True:
        result = parent.execute("SELECT parent FROM groups WHERE id=?", (identity,)).fetchone()[0]
        if result == identity:
            return identity
        identity = result


def _union(db, left, right):
    left, right = _find(db, left), _find(db, right)
    if left != right:
        small, large = sorted((left, right))
        db.execute("UPDATE groups SET parent=? WHERE id=?", (small, large))


def _near_groups(db, settings):
    """Exhaustive prefix-filtered Jaccard join, independent of probabilistic LSH.

    Prefix length |S|-ceil(t*|S|)+1 in a common token order guarantees a shared
    prefix token for any pair with Jaccard >= t. Exact verification follows.
    """
    db.execute("CREATE TABLE prefixes(token BLOB NOT NULL,id TEXT NOT NULL,PRIMARY KEY(token,id)) WITHOUT ROWID")
    db.execute("CREATE TABLE near_pairs(left_id TEXT,right_id TEXT,similarity REAL,PRIMARY KEY(left_id,right_id))")
    threshold = settings["minhash_threshold"]
    comparisons = pairs = 0
    for identity, text, length in db.execute("SELECT id,text,n FROM records ORDER BY n DESC,id"):
        shingles = _shingles(text, settings["shingle_words"])
        if not shingles:
            continue
        prefix = sorted(shingles)[:len(shingles) - math.ceil(threshold * len(shingles)) + 1]
        candidates = set()
        for token in prefix:
            candidates.update(row[0] for row in db.execute("SELECT id FROM prefixes WHERE token=?", (struct.pack(">Q", token),)))
            _candidate_limit(comparisons + len(candidates), settings)
        for candidate in sorted(candidates):
            comparisons += 1
            _candidate_limit(comparisons, settings)
            other_text = db.execute("SELECT text FROM records WHERE id=?", (candidate,)).fetchone()[0]
            other_shingles = _shingles(other_text, settings["shingle_words"])
            similarity = _jaccard(shingles, other_shingles)
            if similarity >= threshold:
                left, right = sorted((identity, candidate))
                db.execute("INSERT INTO near_pairs VALUES(?,?,?)", (left, right, similarity))
                _union(db, left, right)
                pairs += 1
        db.executemany("INSERT INTO prefixes VALUES(?,?)", ((struct.pack(">Q", token), identity) for token in prefix))
    return {"compared_pairs": comparisons, "detected_near_pairs": pairs, "threshold": threshold,
            "method": "exhaustive prefix-filtered word-shingle Jaccard; no LSH-only leakage claim",
            "minimum_content_characters": 0,
            "minimum_word_count": settings["shingle_words"]}


def _tokenizer_snapshot(local_path):
    """Fingerprint only local tokenizer assets; never model weights or a registry."""
    from importlib.metadata import PackageNotFoundError, version
    package_versions = {}
    for package in ("transformers", "tokenizers"):
        try:
            package_versions[package] = version(package)
        except PackageNotFoundError:
            package_versions[package] = None
    result = {"files": {}, "package_versions": package_versions, "status": "not_configured"}
    if not local_path:
        return result
    local = Path(local_path).resolve()
    result["local_path"] = str(local)
    if not local.is_dir():
        return {**result, "status": "unavailable"}
    names = {"tokenizer.json", "tokenizer_config.json", "special_tokens_map.json",
             "added_tokens.json", "config.json", "vocab.json", "vocab.txt",
             "merges.txt", "tokenizer.model", "sentencepiece.model", "spiece.model",
             "chat_template.jinja"}
    assets = [p for p in local.iterdir() if p.is_file() and
              (p.name in names or p.name.startswith("tokenizer.") or
               p.name.startswith("vocab.") or p.name.endswith(".model") or
               p.name.endswith(".jinja"))]
    templates = local / "additional_chat_templates"
    if templates.is_dir():
        assets.extend(p for p in templates.rglob("*.jinja") if p.is_file())
    result["files"] = {str(p.relative_to(local)): _hash_file(p) for p in sorted(assets)}
    result["status"] = "available"
    return result


def _check_tokenizer_snapshot(settings):
    snapshot = _tokenizer_snapshot(settings["tokenizer_local_path"])
    if snapshot != settings["tokenizer_snapshot"]:
        raise DedupError("Local tokenizer assets or loader versions changed; use a new run")
    return snapshot


def _fertility(paths, settings, directory):
    snapshot = _check_tokenizer_snapshot(settings)
    result = {"packing_enabled": False, "packing_blocked": True, "mean_fertility": None,
              "words": 0, "tokens": 0, "examples": 0, "tokenizer_modified": False,
              "tokenizer_backend": None, "tokenizer_fingerprint": snapshot["files"],
              "tokenizer_snapshot_sha256": hashlib.sha256(_json(snapshot).encode()).hexdigest(),
              "tokenizer_package_versions": snapshot["package_versions"],
              "special_tokens_included": False, "truncation_enabled": False,
              "padding_enabled": False}
    local_path = settings["tokenizer_local_path"]
    if not local_path:
        return {**result, "status": "unresolved", "reason": "No approved local tokenizer configured"}
    local = Path(local_path).resolve()
    if not local.is_dir():
        return {**result, "status": "unresolved", "reason": "Configured local tokenizer directory is unavailable"}
    # Neither loader contacts a registry or runs user-provided Python code.
    cache = directory / "tokenizer_cache"
    cache.mkdir()
    loader_errors = {}
    try:
        from transformers import AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(str(local), local_files_only=True, trust_remote_code=False, cache_dir=str(cache))
        encode = lambda text: tokenizer.encode(text, add_special_tokens=False, truncation=False)
        result["tokenizer_backend"] = "transformers.AutoTokenizer"
    except Exception as error:
        loader_errors["transformers.AutoTokenizer"] = type(error).__name__
        try:
            from tokenizers import Tokenizer
            tokenizer = Tokenizer.from_file(str(local / "tokenizer.json"))
            # Runtime encoding options only; assets/vocabulary are never saved or edited.
            tokenizer.no_truncation()
            tokenizer.no_padding()
            encode = lambda text: tokenizer.encode(text, add_special_tokens=False).ids
            result["tokenizer_backend"] = "tokenizers.Tokenizer.from_file"
        except Exception as fallback_error:
            loader_errors["tokenizers.Tokenizer.from_file"] = type(fallback_error).__name__
            _check_tokenizer_snapshot(settings)
            return {**result, "status": "unresolved", "reason": "Local tokenizer unavailable", "loader_errors": loader_errors}
    result["loader_errors"] = loader_errors
    _check_tokenizer_snapshot(settings)
    for record in _records(paths):
        text = source_derived_text(record)
        words = len(re.findall(r"\w+", text, flags=re.UNICODE))
        if not words:
            continue
        try:
            tokens = len(encode(text))
        except Exception as error:
            _check_tokenizer_snapshot(settings)
            return {**result, "status": "unresolved", "reason": "Local tokenization failed", "error_type": type(error).__name__}
        result["examples"] += 1
        result["words"] += words
        result["tokens"] += tokens
    _check_tokenizer_snapshot(settings)
    if not result["words"]:
        return {**result, "status": "not_applicable", "reason": "No candidate words to measure"}
    result["mean_fertility"] = result["tokens"] / result["words"]
    result["packing_blocked"] = result["mean_fertility"] > 3.0
    result["status"] = "measured"
    result["reason"] = ("Mean fertility exceeds 3.0; investigate vocabulary extension with explicit approval"
                        if result["packing_blocked"] else "Packing remains disabled by default")
    return result


def _split(inputs, directory, settings):
    directory.mkdir()
    db = _database(directory / "grouping.sqlite")
    count = _load(db, inputs)
    db.execute("CREATE TABLE groups(id TEXT PRIMARY KEY,parent TEXT NOT NULL)")
    db.execute("CREATE TABLE source_groups(key TEXT PRIMARY KEY,id TEXT NOT NULL)")
    db.execute("CREATE TABLE assignments(id TEXT PRIMARY KEY,group_id TEXT NOT NULL,split TEXT NOT NULL)")
    for identity, raw in db.execute("SELECT id,record FROM records ORDER BY id"):
        record = json.loads(raw)
        meta = record["metadata"]
        db.execute("INSERT INTO groups VALUES(?,?)", (identity, identity))
        # Explicit group AND original record lineage both constrain membership.
        keys = ["declared:" + meta["split_group"], "origin:" + _json([meta["source_file"], meta["source_record_id"]])]
        for key in keys:
            previous = db.execute("SELECT id FROM source_groups WHERE key=?", (key,)).fetchone()
            if previous:
                _union(db, identity, previous[0])
            else:
                db.execute("INSERT INTO source_groups VALUES(?,?)", (key, identity))
    near = _near_groups(db, settings)
    db.execute("CREATE TABLE components(group_id TEXT NOT NULL,id TEXT PRIMARY KEY,domain TEXT NOT NULL)")
    db.execute("CREATE INDEX component_order ON components(group_id,id)")
    for identity, raw in db.execute("SELECT id,record FROM records ORDER BY id"):
        db.execute("INSERT INTO components VALUES(?,?,?)", (_find(db, identity), identity, json.loads(raw)["metadata"].get("domain", "unknown")))
    counts = {"source": Counter(), "domain": Counter(), "task_type": Counter(), "split": Counter()}
    selected_domains = Counter()
    cap_removed = 0
    with (directory / "balancing_removals.jsonl").open("x", encoding="utf-8") as removals:
        for (group,) in db.execute("SELECT DISTINCT group_id FROM components ORDER BY group_id"):
            domains = Counter(dict(db.execute("SELECT domain,COUNT(*) FROM components WHERE group_id=? GROUP BY domain", (group,))))
            capped = any(selected_domains[domain] + n > settings["domain_caps"].get(domain, math.inf) for domain, n in domains.items())
            value = int.from_bytes(hashlib.sha256(f"{settings['seed']}:{group}".encode()).digest()[:8], "big") / (1 << 64)
            split = "train" if value < settings["splits"]["train"] else "validation" if value < settings["splits"]["train"] + settings["splits"]["validation"] else "test"
            for (identity,) in db.execute("SELECT id FROM components WHERE group_id=? ORDER BY id", (group,)):
                raw = db.execute("SELECT record FROM records WHERE id=?", (identity,)).fetchone()[0]
                record = json.loads(raw)
                if capped:
                    cap_removed += 1
                    removals.write(_json({"example_id": identity, "reason": "post_dedup_domain_cap_whole_group", "group": group, "record": record}) + "\n")
                else:
                    meta = record["metadata"]
                    db.execute("INSERT INTO assignments VALUES(?,?,?)", (identity, group, split))
                    for category, key in (("source", "source_name"), ("domain", "domain"), ("task_type", "task_type")):
                        counts[category][meta.get(key, "unknown")] += 1
                    counts["split"][split] += 1
            if not capped:
                selected_domains.update(domains)
    # Explicit audit on actual final assignments, not inferred from grouping.
    cross_near = db.execute("SELECT COUNT(*) FROM near_pairs p JOIN assignments a ON a.id=p.left_id JOIN assignments b ON b.id=p.right_id WHERE a.split<>b.split").fetchone()[0]
    exact_duplicates = db.execute("SELECT COALESCE(SUM(n-1),0) FROM (SELECT COUNT(*) n FROM records r JOIN assignments a ON a.id=r.id GROUP BY r.h HAVING COUNT(*)>1)").fetchone()[0]
    group_leakage = db.execute("SELECT COUNT(*) FROM (SELECT group_id FROM assignments GROUP BY group_id HAVING COUNT(DISTINCT split)>1)").fetchone()[0]
    leakage = {**near, "cross_split_near_pairs": cross_near, "remaining_exact_duplicates": exact_duplicates,
               "cross_split_group_violations": group_leakage, "passed": not (cross_near or exact_duplicates or group_leakage)}
    if not leakage["passed"]:
        _write_json(directory / "leakage.json", leakage)
        raise DedupError("Final split leakage gate failed")
    canonical_paths = []
    for split in ("train", "validation", "test"):
        target = directory / split
        target.mkdir()
        canonical_paths.append(target / "canonical.jsonl")
        with (target / "canonical.jsonl").open("x", encoding="utf-8") as canonical, (target / "messages.jsonl").open("x", encoding="utf-8") as training:
            for raw, group in db.execute("SELECT r.record,a.group_id FROM records r JOIN assignments a ON a.id=r.id WHERE a.split=? ORDER BY r.id", (split,)):
                record = json.loads(raw)
                # Preserve raw candidates in the preceding stages; this is a new artifact.
                record["metadata"]["dedup_group"] = group
                record["metadata"]["split"] = split
                record["metadata"]["review_status"] = "pending"
                canonical.write(_json(record) + "\n")
                training.write(_json({"messages": record["messages"]}) + "\n")
    with (directory / "near_pairs.jsonl").open("x", encoding="utf-8") as stream:
        for left, right, score in db.execute("SELECT left_id,right_id,similarity FROM near_pairs ORDER BY left_id,right_id"):
            stream.write(_json({"left_id": left, "right_id": right, "jaccard": score}) + "\n")
    db.commit()
    db.close()
    fertility = _fertility(canonical_paths, settings, directory)
    stats = {"status": "pre_api_candidates_only", "release_ready": False, "entering": count,
             "surviving": count - cap_removed, "domain_cap_removed": cap_removed,
             "awaiting_api_review": count - cap_removed,
             "counts": {category: dict(value) for category, value in counts.items()},
             "leakage": leakage, "fertility": fertility,
             "domain_caps_applied_after_dedup": True,
             "export_format": "messages-only JSONL; framework compatibility requires an intended trainer",
             "notice": "Pre-API candidates. Not approved for training, distribution, or release."}
    _write_json(directory / "statistics.json", stats)
    _write_json(directory / "leakage.json", leakage)
    _write_json(directory / "fertility.json", fertility)
    return stats


def run_dedup(input_paths: list[Path], output_dir: Path, config: dict) -> dict:
    """Run pass five or reuse a verified completed invocation.

    Invalid input/configuration fails closed. No input is silently skipped.
    Every stage persists survivors, full removed records, statistics and hashes.
    Existing results are never overwritten, and resume verifies their checksums.
    """
    output = _safe_output(output_dir)
    paths = sorted((Path(p).resolve() for p in input_paths), key=str)
    if len(set(paths)) != len(paths):
        raise DedupError("An input shard was supplied more than once")
    for path in paths:
        if not path.is_file() or path.is_relative_to(output):
            raise DedupError("Input must be an existing regular file outside the output directory")
        if not path.is_relative_to(PIPELINE_ROOT.resolve()):
            raise DedupError("Dedup inputs must be derived candidates within PIPELINE_ROOT")
    settings = _settings(config)
    request = {"version": VERSION, "inputs": [{"index": i, **_hash_file(path)} for i, path in enumerate(paths)], "settings": settings}
    fingerprint = hashlib.sha256(_json(request).encode()).hexdigest()
    request_path = _reject_symlinks(output / "request.json")
    if request_path.exists():
        if json.loads(request_path.read_text(encoding="utf-8")) != request:
            raise DedupError("Existing dedup run has different inputs/configuration; use a new run")
    else:
        _write_json(request_path, request)
    final = _reject_symlinks(output / "completed")
    if final.exists():
        manifest = json.loads(_reject_symlinks(final / "manifest.json").read_text(encoding="utf-8"))
        if manifest["request_fingerprint"] != fingerprint:
            raise DedupError("Completed request fingerprint mismatch")
        for name, expected in manifest["files"].items():
            artifact = _reject_symlinks(final / name)
            if artifact.is_symlink() or not artifact.resolve().is_relative_to(final.resolve()) or _hash_file(artifact) != expected:
                raise DedupError("Completed artifact checksum mismatch")
        return json.loads((final / "statistics.json").read_text(encoding="utf-8"))
    attempt = output / ("attempt_" + uuid.uuid4().hex)
    attempt.mkdir()
    _write_json(attempt / "configuration.json", settings)
    try:
        stage_stats = []
        current = paths
        for index, stage in enumerate(STAGES, 1):
            target = attempt / f"{index:02d}_{stage}"
            # Completed stages in earlier interrupted attempts remain immutable.
            # Hardlinks reuse their verified bytes without corpus-sized copying.
            reusable = None
            for previous in sorted(output.glob(f"attempt_*/{index:02d}_{stage}")):
                _reject_symlinks(previous)
                _reject_symlinks(previous / "stage_manifest.json")
                if previous == target or not (previous / "stage_manifest.json").is_file():
                    continue
                stage_manifest = json.loads((previous / "stage_manifest.json").read_text(encoding="utf-8"))
                if stage_manifest.get("request_fingerprint") != fingerprint:
                    continue
                for name, expected in stage_manifest["files"].items():
                    artifact = _reject_symlinks(previous / name)
                    if artifact.is_symlink() or not artifact.resolve().is_relative_to(previous.resolve()) or _hash_file(artifact) != expected:
                        raise DedupError("Interrupted-stage artifact checksum mismatch")
                reusable = previous
                break
            if reusable:
                shutil.copytree(reusable, target, copy_function=os.link)
                stage_stats.append(json.loads((target / "statistics.json").read_text(encoding="utf-8")))
            else:
                stage_stats.append(_stage(stage, current, target, settings))
                _write_json(target / "stage_manifest.json", {
                    "request_fingerprint": fingerprint,
                    "files": {str(p.relative_to(target)): _hash_file(p) for p in sorted(target.iterdir()) if p.is_file()},
                })
            current = [target / "survivors.jsonl"]
        split_stats = _split(current, attempt / "pre_api", settings)
        original = stage_stats[0]["entering"]
        removed = sum(stage["removed"] for stage in stage_stats)
        if original != removed + split_stats["domain_cap_removed"] + split_stats["surviving"]:
            raise DedupError("Deduplication record counts do not reconcile")
        stats = {**split_stats, "generator_version": VERSION, "input_candidates": original,
                 "stages": stage_stats, "dedup_removed": removed, "counts_reconciled": True,
                 "required_stage_order": list(STAGES), "output_root": "completed",
                 "overdedup_audit_required": any(s["high_removal_rate"] or any(d["manual_overdedup_audit_required"] for d in s["domain_audit"].values()) for s in stage_stats)}
        _write_json(attempt / "statistics.json", stats)
        _write_json(attempt / "errors.json", [])
        # Fingerprint all artifacts, including the SQLite accounting/index files.
        files = {str(p.relative_to(attempt)): _hash_file(p) for p in sorted(attempt.rglob("*")) if p.is_file()}
        _write_json(attempt / "manifest.json", {"request_fingerprint": fingerprint, "files": files})
        if final.exists():
            raise DedupError("Another writer completed this output directory")
        attempt.rename(final)
        return stats
    except Exception as error:
        # Do not log exception strings, which may contain candidate text/secrets.
        if not (attempt / "failure.json").exists():
            _write_json(attempt / "failure.json", {"status": "processing_error", "error_type": type(error).__name__, "retry": "Use identical arguments; failed attempt is preserved"})
        raise
