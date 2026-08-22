# Privacy data inventory and trust boundaries

Status: Informative draft

Version: 0.2.0

Deliverable: `RES-STUDY-DATA-INVENTORY-001`

Validation: `VAL-READY-010`

Research date: 2026-08-21

The authoritative research record is
[`policy/threat-privacy-sovereignty.json`](../../../policy/threat-privacy-sovereignty.json).
It defines 17 data classes and 17 trust boundaries.

## Data classes

The inventory covers source bytes; decoded and parsed forms; findings and
entity links; review, appeal, and case records; identity and membership;
provider credentials; keys and wrapped roots; blind indexes; policy decisions
and receipts; audit; operational telemetry; exports and caches; and lifecycle
and recovery records. It also inventories plaintext process memory, provider
retained data, client and network metadata, parser spill, queues, support
bundles, and diagnostic artifacts.

Every class states its source, sensitivity, purpose, storage, egress,
retention, deletion behavior, and accountable boundary owner. Derived data is
not assumed to be safer than source data. Summaries, features, embeddings,
scores, and equality tokens can all reveal content or identity.

## Boundaries

The boundary inventory separates:

1. producers from ingest;
2. runtime plaintext from persistence;
3. one organization from another;
4. the runtime from KMS or vault custody;
5. the host from analyzers;
6. the deployment from external providers;
7. operator clients from query and administration;
8. decisions from actual enforcement;
9. deployment operators from tenant content;
10. backups from restore and external recovery authority;
11. source and CI from release artifacts; and
12. the static standards site from every deployment data path;
13. the host OS from each role process;
14. the identity provider from the verifier;
15. emitters from the observability destination;
16. Testament from managed database and backup operators; and
17. the host broker from isolated extension runtimes.

A boundary says where trust changes. It does not say either side is safe.
Network location alone is not treated as identity or authorization, consistent
with NIST SP 800-207.

## Plaintext and metadata

Source and content-bearing derivatives are encrypted before SQL. Plaintext
still exists in authorized process memory while being ingested, analyzed, or
shown to a user. Operational metadata can also be sensitive through timing,
size, frequency, or rare identifiers. The strict profile therefore uses a
fixed non-content metadata allowlist rather than a vague "metadata only"
exception.
