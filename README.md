# Native Greek SFT pipeline

This project audits an immutable source corpus and builds source-grounded Greek SFT candidates. It does **not** certify a dataset or imply permission to redistribute source material. API review is disabled. Unknown rights, unsupported source semantics, privacy uncertainty and missing evaluation coverage remain explicit release blockers.

## Repository and setup

The repository contains pipeline code, tests, configuration, schemas, prompts, and documentation. Run outputs, runtime state, models, datasets, and secrets remain local. Documentation links into `runs/` or `runtime/` refer to local workspace history and are not included in the repository.

The existing workspace runs on Linux with Python 3.13.5. For a separate deployment, create a fresh isolated environment and install the core dependencies there; do not change the environment of an active run:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

Optional dependencies are `orjson`, `pyarrow`, `transformers`, and `tokenizers`, depending on the features used. The full test suite requires `tokenizers`. Dependencies are never installed automatically.

This checkout is configured for the existing absolute workspace: `src/greek_sft/core.py` hardcodes `PIPELINE_ROOT` as `/datadisk2/greekllm/GreekLLM_sft_pipeline`, and `safe_output` enforces that root. `configs/pipeline.yaml` also fixes source, pipeline, and model paths. A clone at another location requires deliberate code and configuration adaptation before running; changing YAML alone does not make it portable.

## Paths and source protection

- Immutable source: `/datadisk2/greekllm/GreekLLM_jsonl`
- All code, tests, temporary files, caches, checkpoints and outputs: `/datadisk2/greekllm/GreekLLM_sft_pipeline`
- Every run has a unique directory. Resume a run using its ID; change configuration only for a new run.
- Source files are opened read-only. No source scripts are executed, source permissions changed, or text rewritten in place.
- The inventory hashes all regular files, including caches, source sidecars and existing pipeline intermediates. Unsupported artifacts remain in accounting. Existing intermediate data is not treated as new independent training material.
- Source hashes and the complete regular-file set are independently checked again after Pass 5. A changed file blocks release.

## Exactly six passes, five checkpoints

| Pass | Work | Checkpoint |
|---|---|---|
| 1 | Full file inventory, SHA-256, formats/encoding, identifiable records, schemas and provenance/risk screens | `checkpoint_01_inventory` |
| 2 | Source-specific versioned task plans and derived normalization policy | `checkpoint_02_source_plans` |
| 3 | Streaming deterministic source-family candidate shards, minimal evidence, rejected candidates and row dispositions | `checkpoint_03_raw_candidates` |
| 4 | Canonical schema, exact answer reconstruction, language/privacy/license checks and contamination comparison | `checkpoint_04_validated_candidates` |
| 5 | Preserved `ExactSubstrings` → `MinhashDedup` → `SentenceDedup` stages, grouped splits, post-dedup caps, leakage and local-tokenizer fertility | `checkpoint_05_dedup_splits` |
| 6 | Separately approved independent API review, revision/revalidation/review cycle, and release audit | Review artifacts and gated `release/`; no sixth checkpoint |

Each completed checkpoint includes configuration/code snapshots, data, record accounting, statistics, error logs, a manifest and SHA-256 checksums. A file is committed durably only after its scan completes; interrupted file work is retried. Candidate generation uses separately owned family shards and immutable batch journals. Raw candidates are never edited by validation.

## Running and resuming

From this directory:

```bash
python3 -B scripts/run_pipeline.py --new-run --through 5
python3 -B scripts/run_pipeline.py --run-id RUN_ID --through 5
python3 -B scripts/status.py --run-id RUN_ID
```

The driver sets all temporary/cache directories inside this project, disables tokenizer network downloads, and holds an exclusive run lock. Do not run two orchestrators for one run. The current corpus includes over one million files and approximately 1.07 TB of raw bytes, including hundreds of GB of compressed intermediate data; a full scan can require many hours. Progress and durable completion counts are available while scanning.

A recorded user scope amendment can skip record parsing for explicitly named intermediate-data roots while keeping every file in the hash inventory. This run records the instruction “go past greek training” in `runs/RUN_ID/inventory_scope_amendment.json`: process other source collections first, then hash remaining `greek_training` files without parsing or decompressing their records. Previously committed file and record accounting is retained. Skipped record counts remain explicitly unassessed, so this scope cannot support a claim of complete corpus record coverage. The applied amendment is checksummed in the inventory checkpoint and must not be silently changed on resume.

The project uses Python 3 with installed `PyYAML`, `jsonschema`, `zstandard`, and optional `orjson`, `pyarrow`, `transformers`/`tokenizers`. No dependencies are installed automatically. The main algorithms and tests use the standard library where practical. The full test suite requires `tokenizers`, included in `requirements-test.txt`. Run the following in a fresh isolated test environment, without changing an active run's environment. Tests use synthetic data only:

```bash
python3 -m pip install -r requirements-test.txt
mkdir -p runtime/tmp
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src TMPDIR="$PWD/runtime/tmp" python3 -B -m unittest discover -s tests -v
```

## Sources and supported tasks

`configs/sources/` contains separate versioned plans for the 77 catalog families. Plans preserve the actual source schema, meanings, grounding fields, rejection criteria, rights requirements and manually inspected source examples/hash evidence. Runtime plans additionally account for uncatalogued families and non-dataset artifacts.

Task specification version 1.1.0 implements source-annotated shop sentiment, recipe category, AMNA news category, Photodentro thematic-area/education-level classification, and constrained dictionary pronunciation extraction. Each adapter requires its documented fields, retains whole input text, and rejects missing or ambiguous annotations. The 77 plans distinguish implemented tasks, missing adapters, required manual design and suitability blockers; a missing adapter is not described as proof that a source is unsuitable. Earlier specifications remain archived under `configs/sources/archive/`. MITOS raw and rendered files have separate schema dispatch and remain blocked pending verified task rules. No generic summarization, invented QA, global OCR rewriting or size-inflating echo task is used.

Only derived NFC and line-ending normalization is enabled. OCR repair is disabled; any future selective, logged repair must precede deduplication. Ancient/dialectal Greek is not silently relabelled as modern native Greek.

## Accounting and quality limits

JSONL accounting counts every physical row, including blank/malformed rows. Source-level SQLite ranges cover consecutive records and commit to their original row hashes; candidate metadata contains exact individual record hashes and lineage. JSON containers use documented whole-document units. Unknown binary record boundaries are explicitly unresolved rather than reported as zero semantically known records.

Zstandard framing is checked with bounded memory while the original encoded bytes are hashed. Recognized compressed JSONL also uses the native decoder for payload and checksum validation. Explicit frame-boundary checks detect truncated tails that the native streaming reader alone can silently accept. Incomplete framing produces `processing_error` and unresolved record boundaries while preserving all identified rows and the complete raw-byte hash. Concatenated and skippable frames are supported. Older compressed inventory results without the framing-check version require an explicit migration; they are never silently trusted.

Unicode Greek-letter/accents screens and regex PII/secret patterns are heuristics, not complete grammar checking, NER, privacy review or legal assessment. Deep language/privacy scans of excluded intermediate artifacts are marked unassessed. Original source declarations are not automatically verified training/redistribution grants. Unsupported label semantics, missing grounding, source-provided model predictions and unresolved privacy all block eligibility.

Public GreekMMLU is downloaded only for contamination comparison by `scripts/fetch_public_evaluation.py`. Its manifest pins the upstream revision and every downloaded file hash. It is never included as training input. The upstream files contain both subject-specific and aggregate configurations; reference counts must distinguish file rows from distinct questions. Lexical matching cannot rule out every paraphrase. Missing private evaluation datasets or an unconfirmed private scope remain a release blocker.

The available local tokenizer `/datadisk2/greekllm/models/google_gemma-4-E2B-it` is used read-only for fertility. No tokenizer/vocabulary changes or packing are performed. Mean fertility above 3.0 blocks packing and requires investigation of vocabulary extension; an unavailable tokenizer or empty eligible set cannot establish adequate fertility.

## API review remains inactive

Before any external review, supply and approve: provider/protocol, base URL, model, API-key environment-variable **name**, request rate, concurrency, timeout, retries, token/monetary budget, external candidate/evidence permissions, and evaluation paths/fingerprints. Never paste a credential into a tracked file. The API key is read from the environment only and excluded from logs/errors.

`src/greek_sft/review.py` implements an injected-transport review engine with strict response validation, hash-keyed caching, durable budget reservations, bounded submission, rate limiting, timeout propagation, exponential retry backoff and failure quarantine. A live provider adapter must be connected only after its protocol is approved. The engine cannot call an API while disabled or without a transport. Estimate volume/cost, select and approve a small stratified canary by exact candidate hashes, compare it against approved manually inspected gold, then obtain separate full-review approval. A canary approval cannot authorize arbitrary candidates or the full dataset.

The review rubric uses scores 0–4. Missing/invalid/failed responses never count as acceptance. A proposed revision changes the assistant text in a new preserved version, resets validation and review, and must pass both again. Cache hits are independently revalidated.

## Export and release

Rich canonical records remain separate from `messages`-only JSONL training exports. No trainer-specific packing, template or extra metadata is injected. Splits under `checkpoint_05_dedup_splits/completed/pre_api/` are **pre-API candidates**, not released data.

`runs/RUN_ID/release/` holds canonical/train/validation/test/quarantined directories, manifests, checksums, statistics, dataset card and provenance/license/quality/contamination/reproduction reports. While any gate is unresolved, it contains blocked-release reports and no approved training data. The independent release auditor must verify every required gate, including current source integrity and complete accepted API review coverage. Even after technical gates pass, the name is **release-grade Greek SFT candidate** until final human and legal approval.

Progress and worker heartbeat files are advisory atomic updates; they are excluded from authoritative checkpoint checksums. Record ledgers, completed data, manifests and audit reports retain durable writes. Each orchestrator attempt also preserves a ZIP snapshot of code, configuration, tests and agent definitions under `runs/RUN_ID/execution_attempts/`.

Source reads use read-only, nonblocking regular-file handles with symlink rejection. Linux `O_NOATIME` suppresses automatic access-timestamp updates where permitted; an EPERM-only fallback preserves ordinary read access without changing permissions. Byte hashes and file identity checks remain mandatory.

The independent inventory audit also groups **byte-identical source files** using saved SHA-256 hashes and sizes. Its streamed groups, members and source/format breakdowns live under `runs/RUN_ID/audits/inventory/source_file_duplicates/`. Sidecars, caches and empty files are reported separately; this does not claim complete record-level or semantic document duplication detection.

Inventory commits batches of up to 256 small files by default, with immediate commits after files of at least 64 MiB. SQLite retains full synchronous durability. A crash may require rereading up to 255 completed small files per worker plus its current file; committed records are reused.

## Approved Git metadata coverage exception

Run `20260907T095304Z_f315b3c9` stopped after the saved and current SHA-256 hashes of `greek_training/.git/index` differed. The user then approved excluding only `greek_training/.git/` from source coverage and resuming with that exception documented. The original failure and hashes remain under `integrity_incidents/`; `continuation_snapshots/` preserves the failed checkpoint databases, logs and state before continuation. This is a continuation of the same auditable run, not a replacement of its baseline.

`source_exclusion_amendment.json` independently pins the approval, exact subtree, original configuration, earlier record-scope amendment and integrity incident. Its frozen checkpoint copy and checksum are verified on resume. Historical inventory entries and row accounting stay intact. Current Git metadata is neither opened nor traversed, so its current contents, added/removed files and total record count remain unassessed. All files outside that exact subtree retain the existing source-protection checks; other Git directories, `.gitignore` and `greek_training_temp` are unaffected.

Successful verification after this amendment means that the **approved source scope** passed. It does not establish full-original-tree immutability, which remains failed. The earlier `greek_training` record-parsing exclusion still applies; its remaining non-Git files are hashed without record decoding. No source file is modified, restored or rebaselined. If a later attempt fails, `state.json` records the failure and preserves its prior state under `execution_failures/` instead of leaving an obsolete running status.

The user later clarified: “greek training is a mix of the others so we dont make sft from that”. The exact top-level `greek_training/` collection is now excluded from SFT generation and current source coverage, including its non-Git files. This recorded instruction authorizes the checksummed `derived_collection_exclusion_amendment.json`, which preserves and references the earlier Git-only amendment and both integrity incidents. Preserve all historical inventory, record ranges and original hashes; do not open or traverse the excluded collection. Path scope overrides historical family labels. Continue processing original collections outside this root with all source-protection checks; `greek_training_temp` remains in scope. Historical excluded counts are not current coverage, and full-original-tree integrity remains failed. No source is modified or rebaselined.

The latest continuation also excludes the exact `greek_training_temp/` collection under the user’s instruction “leave it continue with the other ones”. Both training folders are outside current source coverage and SFT generation. Existing inventory and candidate checkpoints remain preserved; a separately checksummed reconciliation must prove safe reuse under the new scope before a fresh verification of the remaining source collections. The prior integrity failures remain recorded, and excluded current contents remain unassessed. This scope decision does not approve API review or release.
