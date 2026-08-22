# Synthetic trace research corpus

Status: Informative research

Version: 1.0.0

Validation: `VAL-READY-012`, `VAL-READY-013`

The [machine-readable manifest](manifest.json) binds every fixture to exact
bytes, SHA-256, provenance, Apache-2.0 redistribution terms, deterministic
generation, expected behavior, privacy review, safety review, and version.
All content is project-created synthetic data. It contains no customer or
production traces, personal data, or live credentials.

The corpus covers provider-shaped events for OpenAI, Anthropic, Gemini, and
Bedrock; giant JSON and JSONL; malformed JSON and JSONL; streams; tool calls;
retries; multimodal references; late events; missing lineage; an authorized
defensive-use twin; and harmless abstract abuse-signal scenarios.

Provider-shaped files are not copied provider examples and are not
certification vectors. Abuse labels do not demonstrate detection accuracy.
These fixtures remain informative until a separate fixture-promotion decision
binds selected bytes and review evidence.

## Reproduce and verify

```sh
make generate-corpus
make verify-corpus
```

`make generate-corpus` writes deterministic bytes from the pinned generator
version and seeds. `make verify-corpus` does not rewrite files. It checks class
coverage, provider coverage, schema and metadata, file inventory, byte counts,
digests, deterministic generation, synchronized version/provenance/expectation
changes, size bounds, redistribution licenses, and secret/privacy patterns.
