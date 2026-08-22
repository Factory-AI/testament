# Standards source status

Status: Informative index

Version: 1.0.0

This page labels the authority of public standards material. The
[machine-readable source inventory](../policy/normative-sources.json) is the
source used by the conformance-source gate.

## Normative drafts

RFC-0003 through RFC-0014 are **Normative draft** sources at version `0.1.0`
and status `proposed`. Only each RFC's `Normative contract` section is a
designated draft conformance input. These drafts are not accepted standards
and are **not certification-eligible**. Their source links, versions,
digests, and supersession fields are recorded in the inventory.

| Source | Authority | Version | Status | Supersession |
| --- | --- | --- | --- | --- |
| [RFC-0003](rfcs/0003-raw-capture.md) | Normative draft | 0.1.0 | proposed | none |
| [RFC-0004](rfcs/0004-evidence-graph.md) | Normative draft | 0.1.0 | proposed | none |
| [RFC-0005](rfcs/0005-artifacts.md) | Normative draft | 0.1.0 | proposed | none |
| [RFC-0006](rfcs/0006-findings.md) | Normative draft | 0.1.0 | proposed | none |
| [RFC-0007](rfcs/0007-analyzer-runs.md) | Normative draft | 0.1.0 | proposed | none |
| [RFC-0008](rfcs/0008-enforcement-hooks.md) | Normative draft | 0.1.0 | proposed | none |
| [RFC-0009](rfcs/0009-policy-decisions.md) | Normative draft | 0.1.0 | proposed | none |
| [RFC-0010](rfcs/0010-signed-receipts.md) | Normative draft | 0.1.0 | proposed | none |
| [RFC-0011](rfcs/0011-audit-checkpoints.md) | Normative draft | 0.1.0 | proposed | none |
| [RFC-0012](rfcs/0012-extension-namespaces.md) | Normative draft | 0.1.0 | proposed | none |
| [RFC-0013](rfcs/0013-versioning.md) | Normative draft | 0.1.0 | proposed | none |
| [RFC-0014](rfcs/0014-conformance-profiles.md) | Normative draft | 0.1.0 | proposed | none |

## Informative material

The following material is **Informative** and cannot create or change a
requirement:

- research under [`docs/research/`](research/);
- RFC summaries, motivation, rationale, examples, alternatives, and validation
  notes outside a designated `Normative contract` section;
- disposable code and results under [`prototypes/`](../prototypes/); and
- every fixture in the research corpus until an immutable, reviewed promotion
  decision binds its bytes, digest, expectation, provenance, license, and
  review.

An informative observation may support a future standards decision. It does
not become normative because conformance code cites it or because it appears
next to requirement text.

## Conformance boundary

`make verify-claims` rejects:

- a conformance input absent from the normative source inventory;
- a path, version, status, digest, or section that disagrees with the RFC
  index and source bytes;
- an informative RFC section, research path, prototype, or unpromoted fixture;
- an accepted or certification-eligible label without an accepted indexed
  source; and
- rendered status text that omits authority, version, source, or supersession.

Current conformance inputs are draft-only. The promoted fixture set is empty,
so the repository cannot award certification from the research corpus.
