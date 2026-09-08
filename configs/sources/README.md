# Source plans and approved policies

Every catalog family has a versioned JSON specification. Unsupported tasks are disabled explicitly. Three plans include manually inspected source-record fingerprints. Runtime plans also account for uncatalogued families.

Policy maps are empty for the present run. Neither accessibility, a license string nor API review creates release permission.

Future `source_policies.verified_licenses.<family>` and `privacy_approvals.<family>` objects require `approval_id`, relative `evidence_ref` to an existing pipeline file, and `scope` with exact `source_file_sha256` and/or `source_record_sha256` allowlists. Both must match when both exist. Optional `evidence_sha256` pins the document; all approval evidence fingerprints enter checkpoint identities. A family name alone never grants permission.

License approval also requires `training: true`, `derived_redistribution: true` and `allowed_license_ids`. Every declared license/rights value must match the allowlist exactly, including restrictive and mixed declarations. Missing declarations require explicit `allow_missing_declaration: true` and `license_id` in the allowlist. These are authorized legal-review assertions, never generated grants. A scalar `verified_licenses.<family>` may reference a full approval in `license_evidence.<family>`.

Privacy approval requires `approved: true`. Heuristic flags remain active. Only `record_resolutions.<exact_record_sha256>` with `resolution_id` and `issue_codes` may resolve contact or personal-identifier false positives for that record. Secrets and prompt artifacts cannot be waived. Public metadata receives statuses; approval documents remain internal.

Policy/evidence changes alter checkpoint identity and cannot silently update an existing run. A reviewed dictionary headword must match its entry exactly. Recipe variants sharing a normalized title are grouped together, conservatively across ingredient edits.
