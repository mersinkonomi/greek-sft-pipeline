"""Source-specific planning, deterministic construction and conservative validation.

These passes intentionally distinguish internal construction from permission to
release. An annotation supplies an answer; it does not establish a license, gold
linguistic quality, or permission to disclose an example externally.
"""
from __future__ import annotations

from .source_scope import validate_source_exclusion, is_source_excluded

import concurrent.futures
import hashlib
import json
import os
import re
import time
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path

VERSION = "1.1.0"
PIPELINE_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = Path("/datadisk2/greekllm/GreekLLM_jsonl").resolve()
SYSTEM = "Απάντησε στα ελληνικά, ακολουθώντας την οδηγία και χρησιμοποιώντας μόνο τα στοιχεία που δίνονται. Μην προσθέτεις πληροφορίες που δεν τεκμηριώνονται."
SUPPORTED = {
    "skroutz_shop_reviews_sentiment_analysis": "shop_sentiment",
    "recipes": "recipe_category",
    "modern-greek-dictionary": "dictionary_pronunciation",
    "AMNA-press": "news_category",
    "Photodentro_all_documents": "learning_resource_classification",
}
DOMAINS = {
    "shop_sentiment": "consumer_reviews",
    "recipe_category": "cooking",
    "dictionary_pronunciation": "language_reference",
    "news_category": "news",
    "learning_resource_classification": "education",
}
LABELS = {"Positive": "θετική", "Negative": "αρνητική"}
CATEGORIES = {"Κυρίως Γεύμα", "Γλυκό", "Σαλάτα", "Ορεκτικό / Μεζές"}
NEWS_CATEGORIES = {"Πολιτική", "Κόσμος", "Ελλάδα", "Οικονομία", "Πολιτισμός", "Επιστήμη"}
EDUCATIONAL_LEVELS = {"προσχολική", "δημοτικό", "γυμνάσιο", "γενικό λύκειο", "επαγγελματικό λύκειο (ΕΠΑ.Λ)", "ειδική αγωγή"}
# Design/implementation blockers, never claims that a source has no useful tasks.
SOURCE_DESIGN = {
    "95k_deigma_ellinikis": ("manual_design", "fragment_boundaries_and_noisy_variety_labels_require_validation"),
    "ET": ("manual_design", "gazette_issue_boundaries_and_legal_answer_spans_need_design"),
    "ET_raw": ("needs_adapter", "gazette_per_issue_layout_needs_adapter_and_sidecar_dispatch"),
    "Pergamos_Sections": ("blocked", "section_is_empty_and_predicted_section_is_not_gold"),
    "Sxolika_vivlia": ("manual_design", "textbook_exercise_answer_alignment_and_language_scope_unverified"),
    "Wikisource_Greek_texts": ("manual_design", "wikisource_work_language_rights_and_answer_spans_need_design"),
    "arxaia_2": ("blocked", "lemmatized_ancient_text_requires_dedicated_linguistic_task_design"),
    "combined_books": ("manual_design", "mixed_book_domains_and_document_answer_spans_need_design"),
    "common_corpus/ell_Grek": ("manual_design", "mixed_upstream_corpus_chunks_need_provenance_specific_adapters"),
    "common_corpus/und_Grek": ("blocked", "documented_glyph_corruption_requires_language_and_recovery_review"),
    "dimodis_1": ("manual_design", "literature_teaching_scenarios_need_question_answer_alignment"),
    "eellak-articles": ("needs_adapter", "ellak_blog_body_metadata_alignment_needs_adapter"),
    "ekklesia_1": ("manual_design", "byzantine_liturgical_language_requires_explicit_task_scope"),
    "ellhnika_dedomena_europaikou_koinovouliou": ("needs_adapter", "parliament_document_section_context_needs_adapter"),
    "elsyn": ("blocked", "redundant_court_log_document_merge_requires_component_dispatch"),
    "elsyn_docs": ("manual_design", "court_of_audit_rulings_require_legal_and_privacy_task_review"),
    "elsyn_manifest": ("blocked", "conversion_log_requires_operational_task_justification"),
    "enautilia": ("manual_design", "maritime_textbook_tables_formulas_and_ocr_need_validation"),
    "ert-press": ("needs_adapter", "broadcast_announcements_need_temporal_metadata_adapter"),
    "eurlex_greek_legislation": ("manual_design", "eu_legal_act_scope_and_exact_answer_spans_need_design"),
    "finepdfs": ("manual_design", "heterogeneous_crawl_pdfs_need_domain_rights_and_ocr_dispatch"),
    "greek-political-parties-2017-2018-press-releases": ("manual_design", "party_press_statements_require_label_value_and_safety_review"),
    "greek-youtube": ("manual_design", "edited_video_transcripts_need_fidelity_and_answer_span_review"),
    "greek_dialects/v1": ("manual_design", "short_dialect_fragments_need_label_boundary_and_privacy_review"),
    "greek_dialects/v2": ("manual_design", "long_lowercased_dialect_passages_need_scope_and_label_review"),
    "greek_tragoydia__individual": ("manual_design", "lyrics_metadata_headers_require_rights_and_task_review"),
    "greek_tragoydia": ("blocked", "space_padded_lyrics_aggregate_requires_record_boundary_adapter"),
    "greekllm_additional/elocus_v2": ("needs_adapter", "crete_thesis_metadata_fulltext_alignment_needs_adapter"),
    "greekllm_additional/greek-national-theatre-corpus_v2": ("manual_design", "theatre_press_clippings_need_selective_ocr_and_label_review"),
    "greekllm_additional/libduth_v2": ("needs_adapter", "thrace_thesis_metadata_fulltext_alignment_needs_adapter"),
    "greekllm_additional/libiep_v2": ("manual_design", "historical_schoolbook_ocr_and_register_need_task_design"),
    "greekllm_additional/new-sociology_v2": ("manual_design", "journal_issue_to_article_boundaries_need_task_design"),
    "greekllm_additional/psepheda_v2": ("needs_adapter", "macedonia_thesis_and_parliament_archive_schemas_need_dispatch"),
    "gutenberg": ("manual_design", "historical_translation_work_rights_and_register_need_review"),
    "gutenberg__root": ("needs_adapter", "exploded_gutenberg_books_need_shared_work_identity_adapter"),
    "legal_hf": ("blocked", "opaque_label_codes_without_verified_taxonomy"),
    "mantinades_txt": ("manual_design", "mantinada_theme_annotations_and_verse_rights_need_review"),
    "mitos_all": ("manual_design", "mitos_raw_nested_procedures_require_verified_field_task_adapter"),
    "mitos_all_rendered": ("manual_design", "mitos_rendered_procedures_require_raw_alignment_and_task_adapter"),
    "movie_reviews": ("manual_design", "movie_star_ratings_require_scale_semantics_and_privacy_review"),
    "news_1": ("manual_design", "news_without_outlet_metadata_needs_provenance_and_answer_design"),
    "news_2": ("manual_design", "short_news_fragments_need_completeness_and_provenance_review"),
    "nsk_txts": ("manual_design", "human_rights_judgments_require_privacy_and_legal_task_review"),
    "openarchives_data": ("manual_design", "multi_repository_academic_pdfs_need_metadata_rights_dispatch"),
    "openbook.gr": ("manual_design", "openbook_work_license_and_complete_answer_spans_need_review"),
    "openbook.gr__dataset": ("needs_adapter", "exploded_openbook_files_need_shared_book_identity_adapter"),
    "openbook.gr__root": ("blocked", "openbook_provenance_sidecar_requires_metadata_task_justification"),
    "pages__individual": ("needs_adapter", "commission_page_shards_need_shared_identity_and_body_adapter"),
    "pages": ("manual_design", "commission_navigation_heavy_pages_need_body_and_task_review"),
    "parliament_speeches": ("blocked", "stopword_masked_unaccented_speeches_need_original_fidelity_review"),
    "phd-theses-corpus/contents": ("needs_adapter", "national_thesis_fulltext_metadata_alignment_needs_adapter"),
    "phd-theses-corpus/metadata": ("needs_adapter", "bilingual_thesis_abstract_metadata_needs_language_specific_adapter"),
    "phd_dascim": ("manual_design", "duplicate_thesis_extraction_needs_quality_and_identity_review"),
    "poets_gr_final": ("manual_design", "contemporary_poems_need_rights_and_nontrivial_task_review"),
    "politics_1": ("needs_adapter", "prime_ministerial_document_types_and_metadata_need_adapter"),
    "stage4c_sentdedup": ("manual_design", "already_deduplicated_web_merge_needs_provenance_language_task_dispatch"),
    "wikipedia_el_20231101": ("manual_design", "encyclopedia_articles_need_answer_span_and_attribution_task_design"),
    "1773917775047-istorima": ("manual_design", "oral_histories_need_consent_sensitive_biography_and_summary_review"),
    "reddit": ("manual_design", "reddit_comment_thread_relations_need_privacy_and_answer_review"),
    "twitter": ("manual_design", "text_only_tweets_need_provenance_privacy_and_task_review"),
    "ntua-forums": ("manual_design", "student_forum_threads_need_reply_alignment_and_privacy_review"),
    "opengov-deliberations-v2": ("manual_design", "consultation_articles_comments_need_role_and_privacy_dispatch"),
    "diavgeia": ("manual_design", "transparency_acts_need_personal_data_and_legal_task_review"),
    "greekllm_additional/diavgeia_v2": ("needs_adapter", "new_transparency_api_metadata_needs_privacy_aware_adapter"),
    "greekllm_additional/OpenCouncil_v2": ("manual_design", "council_asr_ai_summaries_need_independent_grounding_and_privacy_review"),
    "decisions": ("manual_design", "administrative_court_cases_need_exact_legal_and_privacy_review"),
    "dikastika": ("manual_design", "supreme_court_page_extraction_needs_case_and_privacy_review"),
    "curial": ("manual_design", "cjeu_document_types_need_legal_role_and_privacy_dispatch"),
}
ANCIENT_FAMILIES = {"1000_prwta_xronia_ellhnikhs", "arxaia_1", "common_corpus/grc_Grek", "klasikh_arx_ell_grammateia"}
SENSITIVE_FAMILIES = {
    "1773917775047-istorima", "reddit", "twitter", "ntua-forums",
    "opengov-deliberations-v2", "diavgeia", "greekllm_additional/diavgeia_v2",
    "greekllm_additional/OpenCouncil_v2", "decisions", "dikastika", "curial",
}
CONTACT = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|(?<!\d)(?:\+30[ -]?)?(?:69\d{8}|2\d{9})(?!\d)|\bGR\s?\d{2}(?:\s?[A-Z0-9]){23}\b", re.I)
SECRET = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16})\b|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|(?:api[_ -]?key|password|κωδικός\s+πρόσβασης)\s*[:=]\s*\S+", re.I)
PRIVATE_ID = re.compile(r"(?:ΑΦΜ|ΑΜΚΑ|ΑΔΤ|Τ\.?Κ\.?|ταυτότητα|αριθμός\s+παραγγελίας)\s*[:#=-]?\s*\d{4,}|\b(?:om|order)[ -]?\d{5,}", re.I)
ARTIFACT = re.compile(r"\{\{[^}]*\}\}|\[(?:INSERT|PLACEHOLDER|TODO)[^\]]*\]|<\|(?:assistant|user|system|endoftext|im_start|im_end).*?\|>|(?:ignore previous|αγνόησε τις προηγούμενες οδηγίες|as an ai language model)", re.I)
ACCENTS = set("άέήίόύώΐΰΆΈΉΊΌΎΏ")


def _json(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _hash(obj):
    return hashlib.sha256(_json(obj).encode("utf-8")).hexdigest()


from .source_io import open_source_readonly

def _file_hash(path):
    h = hashlib.sha256()
    with open_source_readonly(path) as stream:
        for chunk in iter(lambda: stream.read(8 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _reject_symlink_components(path):
    path = Path(path).absolute()
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ValueError("unsafe_output_path:symlink_component")


def _safe_output(path):
    _reject_symlink_components(path)
    path = Path(path).resolve()
    if not path.is_relative_to(PIPELINE_ROOT) or path.is_relative_to(SOURCE_ROOT):
        raise ValueError("unsafe_output_path")
    path.mkdir(parents=True, exist_ok=True)
    return path


def _source_file(root, relative):
    root = Path(root).resolve()
    unresolved = root / relative
    path = unresolved.resolve()
    if Path(relative).is_absolute() or not path.is_relative_to(root) or unresolved.is_symlink():
        raise ValueError("unsafe_source_path")
    return path


def _assert_write_path(path):
    _reject_symlink_components(path)
    path = Path(path)
    resolved = path.resolve()
    if path.is_symlink() or not resolved.is_relative_to(PIPELINE_ROOT) or resolved.is_relative_to(SOURCE_ROOT):
        raise ValueError("unsafe_output_path")


def _write_json(path, obj):
    path = Path(path)
    _assert_write_path(path)
    _safe_output(path.parent)
    if path.exists():
        if path.read_text(encoding="utf-8") == _json(obj) + "\n":
            return
        raise FileExistsError(f"refusing_to_overwrite:{path.name}")
    tmp = path.with_name(path.name + ".partial")
    _assert_write_path(tmp)
    with tmp.open("w", encoding="utf-8") as out:
        out.write(_json(obj) + "\n")
        out.flush()
        os.fsync(out.fileno())
    os.replace(tmp, path)


def _rows(path):
    with Path(path).open(encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def _slug(family):
    return re.sub(r"[^a-zA-Z0-9_-]", "_", family)[:80] + "_" + hashlib.sha256(family.encode()).hexdigest()[:12]


def _normal(text):
    return unicodedata.normalize("NFC", text.replace("\r\n", "\n").replace("\r", "\n")).strip()


def _greek_stats(text):
    alpha = sum(ch.isalpha() for ch in text)
    greek = sum(ch.isalpha() and ("\u0370" <= ch <= "\u03ff" or "\u1f00" <= ch <= "\u1fff") for ch in text)
    return {"alphabetic_characters": alpha, "greek_characters": greek,
            "greek_ratio": greek / alpha if alpha else 0.0,
            "accented_characters": sum(ch in ACCENTS for ch in text)}


def _risk_codes(text):
    return [name for name, pattern in (("contact_or_financial_identifier", CONTACT),
            ("secret_pattern", SECRET), ("personal_identifier_pattern", PRIVATE_ID),
            ("prompt_artifact_or_injection", ARTIFACT)) if pattern.search(text)]


def _declaration(record):
    paths = (("license",), ("license_url",), ("rights",),
             ("metadata", "license"), ("source_metadata", "license"))
    found = {}
    for parts in paths:
        value = record
        for part in parts:
            value = value.get(part) if isinstance(value, dict) else None
        if isinstance(value, str) and value.strip() and value not in {"NA", "None"}:
            found[".".join(parts)] = value
    return {"status": "unverified" if found else "unknown", "declarations": found,
            "release_permission_verified": False}


def _approval_scope(policy, file_hash, record_hash):
    if not isinstance(policy, dict):
        return False
    scope = policy.get("scope", {})
    if not isinstance(scope, dict):
        return False
    constraints = [("source_file_sha256", file_hash), ("source_record_sha256", record_hash)]
    present = False
    for key, actual in constraints:
        if key in scope:
            values = scope[key]
            if not isinstance(values, list) or not values or not all(isinstance(x, str) and re.fullmatch(r"[0-9a-f]{64}", x) for x in values) or actual not in values:
                return False
            present = True
    if not present or not isinstance(policy.get("approval_id"), str) or not policy["approval_id"].strip():
        return False
    reference = policy.get("evidence_ref")
    if not isinstance(reference, str) or not reference.strip() or Path(reference).is_absolute():
        return False
    try:
        evidence_path = _source_file(PIPELINE_ROOT, reference)
        if not evidence_path.is_file():
            return False
        if policy.get("evidence_sha256") and _file_hash(evidence_path) != policy["evidence_sha256"]:
            return False
    except (ValueError, OSError):
        return False
    return True


def _approval_fingerprints(config):
    fingerprints = {}
    def visit(value):
        if isinstance(value, dict):
            reference = value.get("evidence_ref")
            if isinstance(reference, str):
                try:
                    path = _source_file(PIPELINE_ROOT, reference)
                    fingerprints[reference] = _file_hash(path) if path.is_file() else "missing"
                except (ValueError, OSError):
                    fingerprints[reference] = "invalid_or_unreadable"
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    visit(config.get("source_policies", {}))
    return fingerprints


def _apply_approvals(family, declaration, file_hash, record_hash, config):
    """Clear no release gate without a hash-scoped, documented approval."""
    policies = config.get("source_policies", {})
    licenses = policies.get("verified_licenses", {})
    licensing = licenses.get(family, {}) if isinstance(licenses, dict) else {}
    # A separate license_evidence mapping may hold the full approval document.
    if isinstance(licensing, str):
        explicit = policies.get("license_evidence", {}).get(family, {})
        licensing = {**explicit, "license_id": licensing} if isinstance(explicit, dict) else {}
    permission = {"status": declaration.get("status", "unknown"),
        "declarations": declaration.get("declarations", {}), "release_permission_verified": False}
    allowed = licensing.get("allowed_license_ids", []) if isinstance(licensing, dict) else []
    declared = list(permission["declarations"].values())
    matched = isinstance(allowed, list) and bool(allowed) and all(isinstance(x, str) and x.strip() for x in allowed)
    if declared:
        # Every declaration must be explicitly recognized, including mixed/restrictive rights.
        matched = matched and all(value in allowed for value in declared)
    else:
        matched = matched and licensing.get("allow_missing_declaration") is True and licensing.get("license_id") in allowed
    if matched and licensing.get("training") is True and licensing.get("derived_redistribution") is True and _approval_scope(licensing, file_hash, record_hash):
        permission.update(status="verified", release_permission_verified=True,
            approval_id=licensing["approval_id"], evidence_ref=licensing["evidence_ref"],
            approved_license_ids=allowed)
    privacy_policy = policies.get("privacy_approvals", {}).get(family, {})
    privacy = {"status": "heuristic_screen_only", "resolved_issue_codes": []}
    if isinstance(privacy_policy, dict) and privacy_policy.get("approved") is True and _approval_scope(privacy_policy, file_hash, record_hash):
        privacy.update(status="approved", approval_id=privacy_policy["approval_id"], evidence_ref=privacy_policy["evidence_ref"])
        resolution = privacy_policy.get("record_resolutions", {}).get(record_hash, {})
        if isinstance(resolution, dict) and isinstance(resolution.get("resolution_id"), str) and resolution["resolution_id"].strip():
            privacy["resolved_issue_codes"] = [code for code in resolution.get("issue_codes", [])
                if code in {"contact_or_financial_identifier", "personal_identifier_pattern"}]
    return permission, privacy


def _mitos_dispatch_rules():
    return [
        {"relative_path": "mitos_all/mitos_all.jsonl", "task_specification_family": "mitos_all", "schema_variant": "raw_api_response",
         "required_fields": {"success": "boolean", "text": "string", "data": "object", "data.id": "string", "data.metadata": "object"},
         "source_document_id_field": "data.id", "adapter": None,
         "schema_validation_status": "bounded_samples_only_per_record_validation_pending",
         "manual_schema_example": {"line": 1, "raw_sha256": "edf3dfa1cc2a5fbd820fdf6b25cc06c249f80af6bad51cd982fa8e3474e7d2a5"}},
        {"relative_path": "mitos_all/mitos_all_rendered.jsonl", "task_specification_family": "mitos_all_rendered", "schema_variant": "rendered_procedure",
         "required_fields": {"text": "string", "title": "string", "mitos_id": "string", "uuid": "string", "url": "string", "ns": "string", "last_updated": "string", "org_owner": "string", "life_events": "string", "n_conditions": "integer", "n_steps": "integer", "n_evidences": "integer", "n_rules": "integer"},
         "source_document_id_field": "mitos_id", "same_document_as": "raw_api_response:data.id", "adapter": None,
         "schema_validation_status": "bounded_samples_only_per_record_validation_pending",
         "manual_schema_example": {"line": 1, "raw_sha256": "16bc55b9653c476e4c9f45fd0ca0cda8bb2753b34b40250a00b41d566ca2a7a9"}},
    ]


def _file_plan(row, plans):
    family = row.get("family") or "uncatalogued"
    plan = plans[family]
    if family not in {"mitos_all", "mitos_all_rendered"}:
        return plan, {"task_specification_family": family}
    rule = next((rule for rule in plan["file_schema_dispatch"] if rule["relative_path"] == row["relative_path"]), None)
    if rule is None:
        return {**plan, "adapter": None, "reason": "mitos_unmapped_file_requires_schema_review"}, {
            "task_specification_family": None, "schema_variant": "unmapped", "schema_validation_status": "unresolved"}
    resolved = plans.get(rule["task_specification_family"])
    if resolved is None:
        raise ValueError("mitos_dispatch_specification_missing")
    return resolved, {key: rule[key] for key in ("task_specification_family", "schema_variant", "schema_validation_status")}


EXCLUDED_SOURCE_REASON = "excluded_derived_mixture_not_an_sft_source"


def _source_exclusion_reason(source_exclusion):
    return (EXCLUDED_SOURCE_REASON if "greek_training" in source_exclusion["amendment"]["excluded_source_roots"]
            else "excluded_from_current_source_coverage")


def _eligible_file(row, plan, source_exclusion=None):
    if is_source_excluded(row["relative_path"], source_exclusion):
        return False
    family = row.get("family") or "uncatalogued"
    return (plan.get("adapter") is not None and plan["adapter"] == SUPPORTED.get(family)
        and row.get("record_boundary_complete", True) and row["relative_path"].endswith(".jsonl")
        and row.get("record_count") is not None and row.get("encoding") in {"utf-8", "utf-8-sig"}
        and not Path(row["relative_path"]).name.startswith(("dataset_dict", "dataset_info", "state")))


def make_plan(family, catalog_entry=None):
    """Return a versioned specification; unsupported means zero generated examples."""
    entry = catalog_entry or {}
    adapter = SUPPORTED.get(family)
    details = {
        "shop_sentiment": {
            "input_fields": ["text"], "answer_fields": ["label"],
            "required_schema": {"text": "nonempty string", "label": ["Positive", "Negative"]},
            "answer_rule": "Map the source annotation Positive to θετική and Negative to αρνητική, exactly. This is an annotation, not a claim of independently verified sentiment. Never infer or change labels.",
            "prompt_template": "Χαρακτήρισε τη συνολική στάση της παρακάτω κριτικής για το κατάστημα ως θετική ή αρνητική. Απάντησε μόνο με μία από αυτές τις δύο λέξεις.\n\nΚριτική:\n{text}",
            "source_example_checked": {"relative_path": "skroutz_shop_reviews_sentiment_analysis/dataset.jsonl", "line": 1,
                "raw_sha256": "abdda7dfeb1919136946c6250932b08f68dec7840c8796571563b84f71b499c1",
                "observation": "Positive annotation verified; review contains praise and delivery-time criticism. Semantic label ambiguity remains for independent review."},
        },
        "recipe_category": {
            "input_fields": ["name", "Ingredients", "Instructions"], "answer_fields": ["Category"],
            "required_schema": {"name": "nonempty string", "Ingredients": "nonempty string", "Instructions": "nonempty string", "Category": sorted(CATEGORIES)},
            "answer_rule": "Return the existing Category annotation verbatim. Do not infer ingredients, dietary suitability, cooking times, servings or quantities. Preserve whole ingredient and instruction fields; never split comma-separated ingredients.",
            "prompt_template": "Σε ποια κατηγορία ανήκει η παρακάτω συνταγή; Διάλεξε μία από τις κατηγορίες «Κυρίως Γεύμα», «Γλυκό», «Σαλάτα», «Ορεκτικό / Μεζές» και γράψε μόνο την κατηγορία.\n\nΤίτλος: {name}\n\nΥλικά:\n{Ingredients}\n\nΕκτέλεση:\n{Instructions}",
            "source_example_checked": {"relative_path": "recipes/train.jsonl", "line": 1,
                "raw_sha256": "34954ac5b6a179bb2b0a494ad8bc9a873bbdfa2590629ddcbaf4e797aee72121",
                "observation": "Soup title and complete ingredients inspected; Κυρίως Γεύμα annotation is supported. Quantities are copied whole; no culinary calculation is generated."},
        },
        "dictionary_pronunciation": {
            "input_fields": ["lemma", "text"], "answer_fields": ["pronunciation"],
            "required_schema": {"lemma": "nonempty string", "text": "nonempty string", "pronunciation": "1..64 characters, phonetic string appearing as the first bracketed pronunciation"},
            "answer_rule": "Use the exact short pronunciation field only when the entry's first square-bracket span equals it. Answer Η προφορά είναι [<pronunciation>]. Reject long etymology paragraphs and any ambiguous bracket match. Do not reconstruct definitions or pronunciation from outside knowledge.",
            "prompt_template": "Στο παρακάτω λήμμα, ποια προφορά δίνεται για το «{lemma}»; Μετέφερε ακριβώς τη φωνητική γραφή μέσα σε αγκύλες, σε μία σύντομη πρόταση.\n\nΛήμμα:\n{text}",
            "source_example_checked": {"relative_path": "modern-greek-dictionary/train.jsonl", "line": 1,
                "raw_sha256": "46937e71931ce26a2e0bfa9037b5bd7a61ddd5ed7ee14929a49c533f68592f24",
                "observation": "Entry A, α manually checked: first bracket [álfa] matches pronunciation álfa; later brackets contain other pronunciations and must not be selected."},
        },
        "news_category": {
            "input_fields": ["title", "text"], "answer_fields": ["category"], "grouping_fields": ["id", "url"],
            "required_schema": {"title": "nonempty string", "text": "complete plain-text article, at least 160 characters", "category": sorted(NEWS_CATEGORIES), "id": "numeric article ID matching url", "url": "AMNA article URL with matching numeric ID"},
            "answer_rule": "Return the source category annotation verbatim, restricted to the six documented Greek categories. Classify the full title and plain-text body. Never infer a missing category or use text_markdown/text_clean as an undocumented fallback. The category is an editorial annotation, not an independently verified factual claim.",
            "prompt_template": "Σε ποια ειδησεογραφική κατηγορία ανήκει το παρακάτω άρθρο; Διάλεξε μία από τις κατηγορίες «Πολιτική», «Κόσμος», «Ελλάδα», «Οικονομία», «Πολιτισμός», «Επιστήμη» και γράψε μόνο την κατηγορία.\n\nΤίτλος: {title}\n\nΆρθρο:\n{text}",
            "source_example_checked": {"relative_path": "AMNA-press/AMNA-press.jsonl", "line": 1,
                "raw_sha256": "a3c1392312cef4d5d45e923c31172c352cb7ad981703e1b9d4b9982319f515c0",
                "observation": "Bounded manual field check: full plain-text body is present (1801 characters), title is present, category is exactly Επιστήμη, and numeric id agrees with the article URL. Source body Greek ratio is 0.911. No raw article or personal metadata is copied into this public specification; full semantic/naturalness review remains pending."},
        },
        "learning_resource_classification": {
            "input_fields": ["title", "text"], "answer_fields": ["classification.thematic_area", "audience.educational_levels"], "grouping_fields": ["url"],
            "required_schema": {"title": "nonempty string, original accents/case preserved", "text": "whole learning-object description, at least 120 characters", "classification.thematic_area": "1..16 nonempty Greek hierarchy strings, original order retained", "audience.educational_levels": sorted(EDUCATIONAL_LEVELS), "url": "numeric Photodentro learning-object URL"},
            "answer_rule": "Return a JSON object with θεματικές_περιοχές copied from classification.thematic_area and εκπαιδευτικές_βαθμίδες copied from audience.educational_levels, retaining array order and complete hierarchy strings. These are repository annotations attached to the description, not claims about an unseen learning object. Never infer grades, ages, subject hierarchies, pedagogy or missing labels. Do not use notes (dates/durations/CEFR/prose are heterogeneous), keywords, or answer annotations in the user prompt.",
            "prompt_template": "Με βάση την παρακάτω περιγραφή εκπαιδευτικού υλικού, ταξινόμησέ το ως προς τις θεματικές περιοχές και τις εκπαιδευτικές βαθμίδες στις οποίες απευθύνεται. Γράψε μόνο ένα αντικείμενο JSON με τα κλειδιά «θεματικές_περιοχές» και «εκπαιδευτικές_βαθμίδες», καθένα με λίστα τιμών. Διατήρησε ολόκληρη τη θεματική ιεραρχία όπου υπάρχει.\n\nΤίτλος: {title}\n\nΠεριγραφή:\n{text}",
            "source_example_checked": {"relative_path": "Photodentro_all_documents/Photodentro_all_documents.jsonl", "line": 2,
                "raw_sha256": "3670aab68807308562284dee76fe95ade9cadf1c8f75dc50873dab2e5c177739",
                "observation": "Bounded manual field check: 691-character complete description and title are present; thematic_area is [Μαθηματικά > Άλγεβρα > Αξιοσημείωτες ταυτότητες] and educational_levels is [γυμνάσιο]. Numeric object URL verified. Six level strings observed in a bounded 128-record metadata scan. Exact annotation mapping is checked; independent semantic/naturalness review remains pending."},
        },
    }.get(adapter, {})
    design_status, precise_reason = SOURCE_DESIGN.get(family, ("manual_design", "uncatalogued_schema_requires_manual_design" if not entry else "catalogued_source_requires_source_specific_adapter_design"))
    if family in ANCIENT_FAMILIES or (entry.get("variety") == "ancient" and family not in SOURCE_DESIGN):
        design_status, precise_reason = "manual_design", "ancient_language_outside_native_modern_greek_scope"
    dispatch = _mitos_dispatch_rules() if family in {"mitos_all", "mitos_all_rendered"} else []
    return {
        "specification_version": VERSION, "family": family,
        "catalog_schema_is_documentary_evidence_not_validation": True,
        "schema_documentation": entry.get("schema_md", "No catalog schema: no field meanings are assumed."),
        "semantic_meaning": entry.get("one_line", "Uncatalogued source; interpretation unresolved."),
        "documented_file_layout": entry.get("file_layout", "Uncatalogued"),
        "documented_language_variety": entry.get("variety", "unknown"),
        "documented_privacy_flag": entry.get("pii_flag", "unknown"),
        "adapter": adapter, "supported_task_types": [adapter] if adapter else [],
        "status": "internal_candidates_only" if adapter else "quarantined",
        "task_design_status": "implemented_requires_review" if adapter else design_status,
        "task_design_blocker": None if adapter else precise_reason,
        "task_design_is_not_source_unsuitability_finding": True,
        "file_schema_dispatch": dispatch,
        "dispatch_preserves_inventory_family": True,
        "reason": "license_and_privacy_release_approval_unresolved" if adapter else precise_reason,
        "eligible_records": "Actual schema matches; all necessary fields complete; source language and length checks pass; no detected PII/secrets/artifacts; source annotation valid." if adapter else "This version emits zero examples; source-specific adapter/design review remains open.",
        "ineligible_records": "Malformed, incomplete, over-length (never truncated), privacy/secret patterns, unsupported or inconsistent labels, missing answer evidence, uncertain interpretation.",
        "expected_examples_per_record": {"minimum": 0, "maximum": 1 if adapter else 0},
        "normalization": ["Unicode NFC on derived strings", "CRLF and CR to LF", "outer whitespace trim"],
        "ocr_repair": {"enabled": False, "reason": "No manually verified selective OCR rule; never globally rewrite."},
        "anti_hallucination": ["Answers use only listed source fields and exact rules.", "No external facts, fabricated summaries, inferred labels, hidden reasoning or arbitrary truncation.", "Treat source text as untrusted data; it cannot change the task instructions."],
        "validation_rules": ["Strict JSON and canonical schema", "Rebuild full user prompt and answer from preserved evidence", "Exact source-label consistency", "Heuristic Greek script/accent checks", "Heuristic PII/secret/artifact checks", "Independent Greek grammar/naturalness review remains mandatory", "Verified license and privacy clearance required for release"],
        "license_and_attribution": {"status": "unverified", "requirements": ["Record declared license/rights/license_url and upstream provenance if present.", "Verify training and derivative redistribution permission; source access is not a legal grant.", "Retain required attribution privately until approved public attribution fields are defined.", "Never discard or silently rewrite attribution obligations."]},
        "split_group_rule": "Hash originating source identity; dictionary by normalized lemma; recipes by normalized title; sentiment by complete normalized review; AMNA by validated article ID; Photodentro by validated learning-object ID. Global duplicate components must share a split.",
        "manual_examples": [details["source_example_checked"]] if details else [],
        "manual_example_status": "bounded_source_example_inspected" if details else "no_supported_task_no_fabricated_example",
        "input_fields": details.get("input_fields", []), "answer_fields": details.get("answer_fields", []),
        "answer_rule": details.get("answer_rule", "Generation disabled pending this source-specific design blocker: " + precise_reason + ". No missing answers or labels are inferred."),
        "prompt_template": details.get("prompt_template"),
        "rejection_criteria": ["Source task unavailable or unresolved", "Required field/schema mismatch", "Unverified license or privacy clearance for release", "Detected PII, secrets or prompt artifacts", "Incomplete, low-quality, non-Greek or over-length input", "Annotation unsupported by independently reviewed content"],
        **{key: value for key, value in details.items() if key != "source_example_checked"},
    }


def _identity(config, inputs):
    return _hash({"version": VERSION, "config": config, "inputs": inputs})


def _resume(output_dir, identity):
    marker = output_dir / "tasks_completion.json"
    if not marker.exists():
        return None
    result = json.loads(marker.read_text())
    if result["identity"] != identity:
        raise ValueError("checkpoint_identity_changed_create_new_run")
    for name, digest in result["artifacts"].items():
        if _file_hash(output_dir / name) != digest:
            raise ValueError("completed_checkpoint_artifact_changed")
    return result["statistics"]


def _complete(output_dir, identity, statistics):
    _write_json(output_dir / "statistics.tasks.json", statistics)
    artifacts = {str(p.relative_to(output_dir)): _file_hash(p) for p in sorted(output_dir.rglob("*"))
                 if p.is_file() and not p.name.endswith(".partial") and p.name != "tasks_completion.json"}
    _write_json(output_dir / "tasks_completion.json", {"identity": identity, "statistics": statistics, "artifacts": artifacts})
    return statistics


def _jsonl_start(output, name):
    target = output / name
    _assert_write_path(target)
    _assert_write_path(target.with_name(target.name + ".partial"))
    _safe_output(target.parent)
    if target.exists():
        recovery = _safe_output(output / "recovered_uncommitted")
        os.replace(target, recovery / (target.name + "." + str(time.time_ns())))
    return target, target.with_name(target.name + ".partial")


def _finish_stream(stream, partial, target):
    stream.flush()
    os.fsync(stream.fileno())
    stream.close()
    os.replace(partial, target)


def run_plans(source_root: Path, inventory_dir: Path, output_dir: Path, config: dict) -> dict:
    source_root, output_dir = Path(source_root).resolve(), _safe_output(output_dir)
    manifest = Path(inventory_dir) / "source_manifest.jsonl"
    source_exclusion = validate_source_exclusion(inventory_dir, config)
    scope_hash = source_exclusion["sha256"] if source_exclusion else None
    catalog_path = source_root / "DATA_SOURCES.json"
    if catalog_path.exists():
        with open_source_readonly(catalog_path) as stream:
            catalog = json.loads(stream.read().decode("utf-8"))
    else:
        catalog = {}
    identity = _identity(config, {"manifest": _file_hash(manifest), "catalog": _file_hash(catalog_path) if catalog_path.exists() else None,
        "source_exclusion_amendment_sha256": scope_hash})
    resumed = _resume(output_dir, identity)
    if resumed is not None:
        return resumed
    scope_counts = Counter()
    families = defaultdict(lambda: Counter(files=0, records=0))
    for row in _rows(manifest):
        family = row.get("family") or "uncatalogued"
        families[family].update(files=1, records=row.get("record_count") or 0)
        prefix = "historical_excluded_" if is_source_excluded(row["relative_path"], source_exclusion) else "in_scope_"
        scope_counts[prefix + "files"] += 1
        scope_counts[prefix + "identified_records"] += row.get("record_count") or 0
    plan_families = set(catalog) | set(families)
    if plan_families & {"mitos_all", "mitos_all_rendered"}:
        plan_families.update({"mitos_all", "mitos_all_rendered"})
    plans = {}
    for family in sorted(plan_families):
        plan = make_plan(family, catalog.get(family))
        plan["inventory_counts"] = dict(families[family])
        plans[family] = plan
        _write_json(output_dir / "plans" / (_slug(family) + ".json"), plan)
    target, partial = _jsonl_start(output_dir, "source_dispositions.jsonl")
    with partial.open("w", encoding="utf-8") as stream:
        for row in _rows(manifest):
            family = row.get("family") or "uncatalogued"
            plan, dispatch = _file_plan(row, plans)
            eligible = _eligible_file(row, plan, source_exclusion)
            reason = plan["reason"] if not plan["adapter"] or eligible else "unsupported_file_or_record_boundaries"
            if is_source_excluded(row["relative_path"], source_exclusion):
                reason = _source_exclusion_reason(source_exclusion)
            stream.write(_json({"source_file": row["relative_path"], "family": family,
                "record_start": 1 if row.get("record_count") else None,
                "record_end": row.get("record_count"), "record_count": row.get("record_count"),
                "record_boundary_complete": row.get("record_boundary_complete", True),
                "status": "accepted" if eligible else "quarantined", "reason": reason, **dispatch,
                "source_status": row.get("status"), "source_reason": row.get("reason")}) + "\n")
        stream.flush(); os.fsync(stream.fileno())
    os.replace(partial, target)
    statistics = {"source_exclusion_amendment_sha256": scope_hash,
        "excluded_source_roots": source_exclusion["amendment"]["excluded_source_roots"] if source_exclusion else [],
        "source_scope_counts": dict(scope_counts), "families": len(plans), "catalog_families": len(catalog),
        "source_files": sum(x["files"] for x in families.values()), "source_records": sum(x["records"] for x in families.values()),
        "internal_task_families": sorted(set(families) & set(SUPPORTED)), "ocr_repairs": 0,
        "release_license_approval_is_hash_scoped_and_checked_per_candidate": True, "per_family": {k: dict(v) for k, v in sorted(families.items())}}
    return _complete(output_dir, identity, statistics)


def _field_value(record, path):
    value = record
    for key in path.split("."):
        value = value.get(key) if isinstance(value, dict) else None
    return value


def _put_field(record, path, value):
    keys = path.split(".")
    for key in keys[:-1]:
        record = record.setdefault(key, {})
    record[keys[-1]] = value


def construct(family, record, max_chars=20000, min_greek_ratio=.70, resolved_risks=()):
    """Return (minimal evidence, user prompt, answer, group hash) or a reason."""
    adapter = SUPPORTED.get(family)
    if not adapter:
        return None, "unsupported_task_family"
    plan = make_plan(family)
    fields = plan["input_fields"] + plan["answer_fields"] + plan.get("grouping_fields", [])
    if not isinstance(record, dict):
        return None, "missing_or_ambiguous_required_field"
    evidence = {}
    for key in fields:
        value = _field_value(record, key)
        if adapter == "learning_resource_classification" and key in plan["answer_fields"]:
            if not isinstance(value, list) or not 1 <= len(value) <= 16 or any(not isinstance(item, str) or not item.strip() or len(item) > 512 for item in value):
                return None, "missing_or_ambiguous_annotation_list"
            value = [_normal(item) for item in value]
            if len(value) != len(set(value)):
                return None, "duplicate_annotation_label"
        elif not isinstance(value, str) or not value.strip():
            return None, "missing_or_ambiguous_required_field"
        else:
            value = _normal(value)
        _put_field(evidence, key, value)
    if any(len(_field_value(evidence, key)) > max_chars for key in plan["input_fields"]):
        return None, "whole_field_exceeds_limit_no_truncation"
    source_text = "\n".join(_field_value(evidence, key) for key in plan["input_fields"])
    # Screen answer and grouping fields too, before emitting a raw candidate.
    risks = [code for code in _risk_codes(source_text + "\n" + _json(evidence)) if code not in resolved_risks or code in {"secret_pattern", "prompt_artifact_or_injection"}]
    if risks:
        return None, ";".join(risks)
    stats = _greek_stats(source_text)
    if stats["greek_ratio"] < min_greek_ratio or stats["greek_characters"] < 15:
        return None, "insufficient_greek_text"
    if not stats["accented_characters"]:
        return None, "missing_greek_accents_requires_review"
    if adapter == "shop_sentiment":
        if evidence["label"] not in LABELS:
            return None, "unsupported_sentiment_label"
        if len(evidence["text"]) < 50:
            return None, "insufficient_nontrivial_review_context"
        answer, group = LABELS[evidence["label"]], evidence["text"].casefold()
        if re.search(r"\b(?:Positive|Negative)\b", evidence["text"], re.I):
            return None, "source_annotation_label_leakage"
    elif adapter == "recipe_category":
        if evidence["Category"] not in CATEGORIES:
            return None, "unsupported_recipe_category"
        answer = evidence["Category"]
        group = evidence["name"].casefold()
    elif adapter == "news_category":
        if evidence["category"] not in NEWS_CATEGORIES:
            return None, "unsupported_news_category"
        if len(evidence["text"]) < 160:
            return None, "insufficient_nontrivial_article_context"
        match = re.fullmatch(r"https?://www\.amna\.gr/home/article/([0-9]+)/?", evidence["url"])
        if not re.fullmatch(r"[0-9]+", evidence["id"]) or not match or match.group(1) != evidence["id"]:
            return None, "article_id_url_mismatch_or_unknown_schema"
        if re.search(r"(?mi)^\s*(?:κατηγορία|category)\s*[:=]", source_text):
            return None, "source_annotation_label_leakage"
        answer, group = evidence["category"], "article:" + evidence["id"]
    elif adapter == "learning_resource_classification":
        levels = evidence["audience"]["educational_levels"]
        areas = evidence["classification"]["thematic_area"]
        if any(level not in EDUCATIONAL_LEVELS for level in levels):
            return None, "unsupported_educational_level"
        if any(_greek_stats(area)["greek_ratio"] < min_greek_ratio or any(not component.strip() for component in area.split(">")) for area in areas):
            return None, "invalid_or_non_greek_thematic_annotation"
        if len(evidence["text"]) < 120:
            return None, "insufficient_nontrivial_resource_description"
        match = re.fullmatch(r"https?://photodentro\.edu\.gr/aggregator/lo/photodentro-lor-8521-([0-9]+)", evidence["url"])
        if not match:
            return None, "learning_object_identity_or_url_schema_unverified"
        if re.search(r"(?mi)^\s*(?:θεματικ(?:ή|ές)\s+περιοχ(?:ή|ές)|εκπαιδευτικ(?:ή|ές)\s+βαθμίδ(?:α|ες)|classification|audience)\s*[:=]", source_text):
            return None, "source_annotation_label_leakage"
        answer = _json({"θεματικές_περιοχές": areas, "εκπαιδευτικές_βαθμίδες": levels})
        if len(answer) > 4096:
            return None, "annotation_output_exceeds_limit_no_truncation"
        group = "learning_object:" + match.group(1)
    else:
        pronunciation = evidence["pronunciation"]
        first = re.search(r"\[([^\[\]]+)\]", evidence["text"])
        lemma = evidence["lemma"]
        if not evidence["text"].startswith(lemma) or (len(evidence["text"]) > len(lemma) and lemma[-1].isalnum() and evidence["text"][len(lemma)].isalnum()):
            return None, "lemma_does_not_match_entry_headword"
        if not 1 <= len(pronunciation) <= 64 or "\n" in pronunciation or not first or first.group(1) != pronunciation:
            return None, "pronunciation_not_unambiguous_first_bracket"
        if not all(ch.isalpha() or ch in "'’ˈˌː:. -" for ch in pronunciation):
            return None, "pronunciation_has_nonphonetic_content"
        answer = f"Η προφορά είναι [{pronunciation}]."
        group = evidence["lemma"].casefold()
    prompt = plan["prompt_template"].format(**evidence)
    return (evidence, prompt, answer, hashlib.sha256((family + "\0" + group).encode()).hexdigest()), None


def _grounding_span(family, prompt, fields):
    if family in {"recipes", "AMNA-press", "Photodentro_all_documents"}:
        first_field = "name" if family == "recipes" else "title"
        start = len(make_plan(family)["prompt_template"].split("{" + first_field + "}", 1)[0])
    else:
        start = len(prompt) - len(fields["text"])
    return {"message_index": 1, "start": start, "end": len(prompt)}


def _reject_constant(value):
    raise ValueError("nonfinite_json_constant")


def _generate_family(family, files, source_root, output, config):
    shard = _safe_output(output / "shards" / _slug(family))
    identity = _identity(config, files)
    resumed = _resume(shard, identity)
    if resumed is not None:
        return resumed
    names = ("candidates.jsonl", "evidence.jsonl", "record_dispositions.jsonl", "rejected.jsonl")
    handles, paths = {}, {}
    batches_dir = _safe_output(shard / "batches")
    journals = sorted(batches_dir.glob("batch_*.json"))
    snapshots = [json.loads(p.read_text()) for p in journals]
    if any(item["identity"] != identity for item in snapshots):
        raise ValueError("batch_identity_changed_create_new_run")
    latest = snapshots[-1] if snapshots else None
    counts = Counter(latest["counts"] if latest else {})
    reasons = Counter(latest["reasons"] if latest else {})
    positions = dict(latest["positions"] if latest else {})
    committed_positions = dict(positions)
    offsets = dict(latest["output_sizes"] if latest else {name: 0 for name in names})
    sequence = len(snapshots)
    for name in names:
        target, partial = shard / name, shard / (name + ".partial")
        _assert_write_path(target); _assert_write_path(partial)
        if latest:
            if target.exists() and not partial.exists():
                os.replace(target, partial)  # interrupted atomic commit; no completion marker
            if not partial.exists() or partial.stat().st_size < offsets[name]:
                raise ValueError("resumable_batch_output_missing_or_truncated")
            with partial.open("rb") as check:
                for snapshot in snapshots:
                    segment = snapshot["segments"][name]
                    check.seek(segment["start"])
                    remaining = segment["end"] - segment["start"]
                    digest = hashlib.sha256()
                    while remaining:
                        data = check.read(min(8 << 20, remaining))
                        if not data:
                            raise ValueError("resumable_batch_segment_truncated")
                        digest.update(data); remaining -= len(data)
                    if digest.hexdigest() != segment["sha256"]:
                        raise ValueError("resumable_batch_segment_changed")
            # Only the uncommitted tail of a derived partial file may be discarded.
            with partial.open("r+b") as derived:
                derived.truncate(offsets[name])
            handles[name] = partial.open("a", encoding="utf-8")
        else:
            target, partial = _jsonl_start(shard, name)
            handles[name] = partial.open("w", encoding="utf-8")
        paths[name] = (target, partial)

    def commit_batch():
        nonlocal sequence, offsets
        segments, sizes = {}, {}
        for name, handle in handles.items():
            handle.flush(); os.fsync(handle.fileno())
            end = handle.tell(); start = offsets[name]
            digest = hashlib.sha256()
            with paths[name][1].open("rb") as check:
                check.seek(start)
                remaining = end - start
                while remaining:
                    data = check.read(min(8 << 20, remaining))
                    if not data:
                        raise RuntimeError("batch_commit_short_read")
                    digest.update(data); remaining -= len(data)
            segments[name] = {"start": start, "end": end, "sha256": digest.hexdigest()}
            sizes[name] = end
        _write_json(batches_dir / ("batch_%08d.json" % sequence), {"identity": identity,
            "positions": positions, "counts": dict(counts), "reasons": dict(reasons),
            "segments": segments, "output_sizes": sizes})
        offsets = sizes; sequence += 1

    try:
        for file_index, file in enumerate(files):
            relative = file["relative_path"]
            source = _source_file(source_root, relative)
            file_hasher = hashlib.sha256()
            lines = 0
            with open_source_readonly(source) as stream:
                for line_number, raw in enumerate(stream, 1):
                    file_hasher.update(raw); lines += 1
                    if line_number <= committed_positions.get(relative, 0):
                        continue
                    counts["source_records"] += 1
                    line_hash = hashlib.sha256(raw).hexdigest()
                    disposition = {"source_file": relative, "source_line": line_number, "source_record_hash": line_hash}
                    try:
                        record = json.loads(raw.decode(file.get("encoding") or "utf-8-sig"), parse_constant=_reject_constant)
                        license_evidence, privacy_evidence = _apply_approvals(family, _declaration(record) if isinstance(record, dict) else {}, file["sha256"], line_hash, config)
                        built, reason = construct(family, record, config.get("max_candidate_field_characters", 20000), config.get("validation", {}).get("minimum_greek_letter_ratio", .70), privacy_evidence["resolved_issue_codes"])
                    except (ValueError, UnicodeError, TypeError):
                        record, built, reason = None, None, "malformed_json_or_encoding"
                    if built:
                        evidence, prompt, answer, group = built
                        uid = _hash({"family": family, "file": relative, "line": line_number, "record_hash": line_hash,
                            "task": SUPPORTED[family], "version": VERSION})
                        candidate = {"id": uid, "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}, {"role": "assistant", "content": answer}],
                            "metadata": {"language": "el", "locale": "el-GR", "source_name": family, "source_file": relative,
                                "source_record_id": str(line_number), "source_record_hash": line_hash,
                                "task_type": SUPPORTED[family], "generation_method": "deterministic_source_annotation",
                                "generator_version": VERSION, "template_version": VERSION, "grounded": True,
                                "split_group": group, "validation_status": "pending", "review_status": "pending",
                                "grounding_span": _grounding_span(family, prompt, evidence),
                                "domain": DOMAINS[SUPPORTED[family]], "license_status": license_evidence["status"],
                                "privacy_status": privacy_evidence["status"], "source_line": line_number, "source_file_hash": file["sha256"]}}
                        handles["candidates.jsonl"].write(_json(candidate) + "\n")
                        handles["evidence.jsonl"].write(_json({"example_id": uid, "candidate_sha256": _hash(candidate), "family": family,
                            "source_file": relative, "source_line": line_number, "source_file_sha256": file["sha256"],
                            "source_record_hash": line_hash, "fields": evidence, "license": license_evidence, "privacy": privacy_evidence,
                            "normalization": "NFC_CRLF_outer_whitespace_v1", "ocr_repairs": []}) + "\n")
                        disposition.update(status="accepted", reason="internal_candidate_constructed", example_id=uid)
                        counts["candidates"] += 1
                    else:
                        status = "malformed" if reason == "malformed_json_or_encoding" else "quarantined"
                        disposition.update(status=status, reason=reason)
                        handles["rejected.jsonl"].write(_json(disposition) + "\n")
                        counts[status] += 1; reasons[reason] += 1
                    handles["record_dispositions.jsonl"].write(_json(disposition) + "\n")
                    positions[relative] = line_number
                    if counts["source_records"] % max(1, int(config.get("batch_size", 1000))) == 0:
                        commit_batch()
            if file_hasher.hexdigest() != file["sha256"]:
                raise RuntimeError("source_hash_changed:" + relative)
            if lines != file.get("record_count"):
                raise RuntimeError("source_record_count_mismatch:" + relative)
            counts["source_files"] = file_index + 1
        commit_batch()
        for name, handle in handles.items():
            target, partial = paths[name]
            _finish_stream(handle, partial, target)
    finally:
        for handle in handles.values():
            if not handle.closed:
                handle.close()
    stats = {"family": family, **dict(counts), "reasons": dict(reasons)}
    return _complete(shard, identity, stats)


def run_generation(source_root: Path, inventory_dir: Path, plans_dir: Path, output_dir: Path, config: dict) -> dict:
    output = _safe_output(output_dir)
    manifest = Path(inventory_dir) / "source_manifest.jsonl"
    plan_manifest = Path(plans_dir) / "tasks_completion.json"
    source_exclusion = validate_source_exclusion(inventory_dir, config)
    scope_hash = source_exclusion["sha256"] if source_exclusion else None
    plan_marker = json.loads(plan_manifest.read_text())
    if plan_marker["statistics"].get("source_exclusion_amendment_sha256") != scope_hash:
        raise ValueError("plan_source_exclusion_identity_changed_create_new_run")
    _resume(Path(plans_dir), plan_marker["identity"])
    identity = _identity(config, {"manifest": _file_hash(manifest), "plans": _file_hash(plan_manifest), "source_exclusion_amendment_sha256": scope_hash, "approval_evidence": _approval_fingerprints(config)})
    resumed = _resume(output, identity)
    if resumed is not None:
        return resumed
    # Bind interrupted attempts before any shard is selected or written. A
    # completion-only identity cannot protect leftover shards from an older scope.
    attempt_path = output / "generation_identity.json"
    _assert_write_path(attempt_path)
    attempt = {"identity": identity, "source_exclusion_amendment_sha256": scope_hash}
    if attempt_path.exists():
        if json.loads(attempt_path.read_text()) != attempt:
            raise ValueError("generation_attempt_identity_changed_create_new_run")
    else:
        unfinished_identity = attempt_path.with_name(attempt_path.name + ".partial")
        if any(path != unfinished_identity for path in output.iterdir()):
            raise ValueError("generation_partial_output_identity_missing_create_new_run")
        # No shard writes precede publication, so only this unfinished identity
        # temporary can be safely retried. Other unidentified output is preserved.
        _write_json(attempt_path, attempt)
    directory_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    stored_plans = {plan["family"]: plan for path in sorted((Path(plans_dir) / "plans").glob("*.json"))
        for plan in [json.loads(path.read_text())]}
    if any(plan.get("specification_version") != VERSION for plan in stored_plans.values()):
        raise ValueError("plan_version_changed_create_new_run")
    stored_dispositions = iter(_rows(Path(plans_dir) / "source_dispositions.jsonl"))
    selected = defaultdict(list)
    counts, reasons = Counter(), Counter()
    target, partial = _jsonl_start(output, "source_dispositions.jsonl")
    with partial.open("w", encoding="utf-8") as stream:
        for row in _rows(manifest):
            family = row.get("family") or "uncatalogued"
            counts["source_files"] += 1; counts["source_records"] += row.get("record_count") or 0
            prior = next(stored_dispositions, None)
            if not isinstance(prior, dict) or any(prior.get(key) != expected for key, expected in (
                ("source_file", row["relative_path"]), ("family", family), ("record_count", row.get("record_count")))):
                raise ValueError("source_plan_inventory_accounting_mismatch")
            specification_family = prior.get("task_specification_family") or family
            plan = stored_plans[specification_family]
            excluded = is_source_excluded(row["relative_path"], source_exclusion)
            prefix = "historical_excluded_" if excluded else "in_scope_"
            counts[prefix + "files"] += 1
            counts[prefix + "identified_records"] += row.get("record_count") or 0
            eligible = prior["status"] == "accepted" and _eligible_file(row, plan, source_exclusion)
            if eligible:
                selected[family].append(row)
                disposition = {"status": "accepted", "reason": "individual_statuses_in_family_shard", "shard": "shards/" + _slug(family)}
            else:
                reason = _source_exclusion_reason(source_exclusion) if excluded else prior["reason"]
                disposition = {"status": "quarantined", "reason": reason}
                counts["noncandidate_records"] += row.get("record_count") or 0; reasons[reason] += row.get("record_count") or 0
            stream.write(_json({"source_file": row["relative_path"], "family": family, "record_count": row.get("record_count"),
                "record_start": 1 if row.get("record_count") else None, "record_end": row.get("record_count"),
                "record_boundary_complete": row.get("record_boundary_complete", True),
                "plan_status": prior["status"], "plan_reason": prior["reason"],
                **{key: prior[key] for key in ("task_specification_family", "schema_variant", "schema_validation_status") if key in prior},
                **disposition}) + "\n")
        stream.flush(); os.fsync(stream.fileno())
    if next(stored_dispositions, None) is not None:
        raise ValueError("source_plan_inventory_accounting_mismatch")
    os.replace(partial, target)
    worker_limit = min(3, max(1, int(config.get("builder_workers", 3))))
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_limit) as pool:
        futures = [pool.submit(_generate_family, family, sorted(files, key=lambda f: f["relative_path"]), Path(source_root), output, config)
            for family, files in sorted(selected.items())]
        family_stats = [future.result() for future in futures]
    generated = sum(row.get("candidates", 0) for row in family_stats)
    classified = counts["noncandidate_records"] + sum(row.get("source_records", 0) for row in family_stats)
    if classified != counts["source_records"]:
        raise RuntimeError("generation_coverage_mismatch")
    stats = {**dict(counts), "source_exclusion_amendment_sha256": scope_hash,
        "excluded_source_roots": source_exclusion["amendment"]["excluded_source_roots"] if source_exclusion else [],
        "candidates": generated, "classified_records": classified, "coverage_reconciled": True,
        "per_family": family_stats, "noncandidate_reasons": dict(reasons), "workers": worker_limit,
        "external_calls": 0, "all_release_candidates_require_license_privacy_and_api_review": True}
    return _complete(output, identity, stats)


def validate_candidate(candidate, evidence, schema_validator=None, config=None):
    """Deterministic checks plus explicit unresolved quality/permission gates."""
    issues = []
    config = config or {}
    if schema_validator is not None:
        issues.extend("canonical_schema:" + str(error.validator) for error in schema_validator.iter_errors(candidate))
    if not isinstance(candidate, dict) or not isinstance(evidence, dict):
        return ["malformed_candidate_or_evidence"], {}
    messages, metadata = candidate.get("messages", []), candidate.get("metadata", {})
    if not isinstance(metadata, dict):
        return sorted(set(issues + ["malformed_metadata"])), {}
    if not isinstance(messages, list) or [m.get("role") if isinstance(m, dict) else None for m in messages] != ["system", "user", "assistant"]:
        return sorted(set(issues + ["invalid_message_roles_or_order"])), {}
    if any(not isinstance(m.get("content"), str) or not m["content"].strip() for m in messages):
        return sorted(set(issues + ["empty_or_malformed_message"])), {}
    if evidence.get("candidate_sha256") != _hash(candidate) or evidence.get("example_id") != candidate.get("id"):
        issues.append("candidate_evidence_hash_mismatch")
    if evidence.get("source_record_hash") != metadata.get("source_record_hash") or evidence.get("source_file") != metadata.get("source_file"):
        issues.append("source_lineage_mismatch")
    family = evidence.get("family")
    expected_metadata = {"source_name": family, "source_record_id": str(evidence.get("source_line")),
        "source_line": evidence.get("source_line"), "source_file_hash": evidence.get("source_file_sha256"),
        "task_type": SUPPORTED.get(family), "generator_version": VERSION, "template_version": VERSION,
        "generation_method": "deterministic_source_annotation", "domain": DOMAINS.get(SUPPORTED.get(family))}
    for key, expected in expected_metadata.items():
        if metadata.get(key) != expected:
            issues.append("metadata_evidence_mismatch:" + key)
    if type(evidence.get("source_line")) is not int or evidence["source_line"] <= 0:
        issues.append("invalid_source_line")
    expected_id = _hash({"family": family, "file": evidence.get("source_file"), "line": evidence.get("source_line"),
        "record_hash": evidence.get("source_record_hash"), "task": SUPPORTED.get(family), "version": VERSION})
    if candidate.get("id") != expected_id:
        issues.append("unstable_or_incorrect_candidate_id")
    if metadata.get("review_status") != "pending":
        issues.append("raw_review_status_must_be_pending")
    approved_license, approved_privacy = _apply_approvals(evidence.get("family"), evidence.get("license", {}), evidence.get("source_file_sha256"), evidence.get("source_record_hash"), config)
    rebuilt, reason = construct(evidence.get("family"), evidence.get("fields"), config.get("max_candidate_field_characters", 20000), config.get("validation", {}).get("minimum_greek_letter_ratio", .70), approved_privacy["resolved_issue_codes"])
    if not rebuilt:
        issues.append("source_evidence_invalid:" + str(reason))
    else:
        fields, expected_prompt, expected_answer, group = rebuilt
        if messages[0]["content"] != SYSTEM or messages[1]["content"] != expected_prompt:
            issues.append("unsupported_or_changed_prompt")
        if messages[2]["content"] != expected_answer:
            issues.append("answer_not_exactly_grounded")
        if metadata.get("split_group") != group:
            issues.append("source_group_mismatch")
        if metadata.get("grounding_span") != _grounding_span(family, expected_prompt, fields):
            issues.append("grounding_span_mismatch")
    all_text = "\n".join(m["content"] for m in messages)
    issues.extend(code for code in _risk_codes(all_text) if code not in approved_privacy["resolved_issue_codes"])
    greek = _greek_stats(messages[1]["content"])
    if greek["greek_ratio"] < config.get("validation", {}).get("minimum_greek_letter_ratio", .70) or not greek["accented_characters"]:
        issues.append("greek_script_or_accents_check_failed")
    if any("/datadisk" in str(v) or "\\home\\" in str(v) for v in metadata.values()):
        issues.append("private_absolute_path_in_metadata")
    if not approved_license.get("release_permission_verified", False):
        issues.append("license_unverified")
    # Heuristics cannot prove absence of names, sensitive biography or fluent grammar.
    if metadata.get("privacy_status") != "approved" or approved_privacy["status"] != "approved":
        issues.append("privacy_review_unresolved")
    return sorted(set(issues)), greek


def run_validation(raw_dir: Path, output_dir: Path, config: dict) -> dict:
    from jsonschema import Draft202012Validator
    output, raw = _safe_output(output_dir), Path(raw_dir)
    raw_marker = json.loads((raw / "tasks_completion.json").read_text())
    _resume(raw, raw_marker["identity"])  # verify every immutable candidate/evidence shard before validation
    schema_path = Path(config.get("canonical_schema_path", config.get("validation", {}).get("schema_path", PIPELINE_ROOT / "schemas" / "canonical-sft.schema.json")))
    if not schema_path.is_absolute():
        schema_path = PIPELINE_ROOT / schema_path
    schema = json.loads(schema_path.read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    identity = _identity(config, {"raw_completion": _file_hash(raw / "tasks_completion.json"), "schema": _file_hash(schema_path), "approval_evidence": _approval_fingerprints(config)})
    resumed = _resume(output, identity)
    if resumed is not None:
        return resumed
    handles, paths = {}, {}
    for name in ("validated.jsonl", "quarantined.jsonl", "record_decisions.jsonl"):
        target, partial = _jsonl_start(output, name)
        paths[name] = (target, partial); handles[name] = partial.open("w", encoding="utf-8")
    counts, reasons, families = Counter(), Counter(), defaultdict(Counter)
    greek_sum = 0.0
    try:
        for candidate_path in sorted(raw.glob("shards/*/candidates.jsonl")):
            evidence_iter = _rows(candidate_path.with_name("evidence.jsonl"))
            for candidate in _rows(candidate_path):
                evidence = next(evidence_iter, None)
                issues, greek = validate_candidate(candidate, evidence, validator, config)
                family = candidate.get("metadata", {}).get("source_name", "unknown")
                counts["candidates_entering"] += 1; families[family]["entering"] += 1
                counts["schema_passed"] += not any(x.startswith("canonical_schema") for x in issues)
                deterministic_issues = [x for x in issues if x not in {"license_unverified", "privacy_review_unresolved"}]
                counts["deterministic_content_checks_passed"] += not deterministic_issues
                greek_sum += greek.get("greek_ratio", 0)
                target_name = "quarantined.jsonl" if issues else "validated.jsonl"
                status = "quarantined" if issues else "accepted"
                counts[status] += 1; families[family][status] += 1; reasons.update(issues)
                # New artifact only: raw canonical candidate remains byte-for-byte unchanged.
                if issues:
                    handles[target_name].write(_json({"candidate": candidate, "status": status, "reasons": issues}) + "\n")
                else:
                    validated = {**candidate, "metadata": {**candidate["metadata"], "validation_status": "passed"}}
                    handles[target_name].write(_json(validated) + "\n")
                handles["record_decisions.jsonl"].write(_json({"example_id": candidate["id"], "source_name": family,
                    "status": status, "reasons": issues, "greek_statistics": greek,
                    "schema_passed": not any(x.startswith("canonical_schema") for x in issues),
                    "content_checks_passed": not deterministic_issues, "grammar_checked": False,
                    "benchmark_contamination_checked": False, "review_status": "pending"}) + "\n")
            if next(evidence_iter, None) is not None:
                raise RuntimeError("extra_source_evidence_without_candidate")
        for name, handle in handles.items():
            target, partial = paths[name]; _finish_stream(handle, partial, target)
    finally:
        for handle in handles.values():
            if not handle.closed:
                handle.close()
    total = counts["candidates_entering"]
    statistics = {**dict(counts), "candidates_leaving": counts["accepted"], "awaiting_api_review": counts["accepted"],
        "reasons": dict(reasons), "per_family": {k: dict(v) for k, v in families.items()},
        "mean_user_greek_ratio": greek_sum / total if total else None,
        "greek_grammar_and_naturalness": "unresolved_requires_independent_review",
        "privacy_assessment": "heuristics_only_no_release_clearance",
        "benchmark_contamination": "unresolved_pending_evaluation_data",
        "raw_candidates_modified": False, "coverage_reconciled": total == counts["accepted"] + counts["quarantined"]}
    return _complete(output, identity, statistics)
