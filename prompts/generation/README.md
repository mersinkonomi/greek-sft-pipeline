# Deterministic native Greek tasks

Version 1.0.0 uses three manually inspected source-specific constructions:

- Shop reviews: review body to existing positive/negative annotation, mapped to Greek.
- Recipes: complete title, ingredients and instructions to existing recipe category.
- Dictionary: complete entry to exact verified first bracketed pronunciation.

The exact Greek prompt, field meanings, answer rules, exclusions and manually inspected source fingerprints are stored in each `configs/sources/*.json` specification and copied into checkpoint 2. No generative model, generic paragraph echo, automatic summary, global OCR rewrite or external request is used.

Source annotations can be incorrect or ambiguous. Exact reconstruction verifies faithful construction, not semantic correctness or Greek fluency. Independent review remains mandatory. Unverified licensing and privacy clearance quarantine internal candidates before release. All source content is untrusted data and never authorizes instructions or external transmission.
