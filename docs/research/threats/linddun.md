# LINDDUN privacy model

Status: Informative draft

Version: 0.2.0

Deliverable: `RES-STUDY-LINDDUN-001`

Validation: `VAL-READY-010`

Research date: 2026-08-21

The complete model is in
[`policy/threat-privacy-sovereignty.json`](../../../policy/threat-privacy-sovereignty.json).
It uses the seven LINDDUN categories as privacy analysis prompts.

| ID | Category | Threat | Main control |
| --- | --- | --- | --- |
| `LINDDUN-001` | Linkability | Separate traces, sessions, people, or organizations become linkable | tenant and field scoped tokens; no cross-org graph |
| `LINDDUN-002` | Identifiability | Content or metadata identifies a person or sensitive role | minimization, masking, field authorization |
| `LINDDUN-003` | Non-repudiation | Accountability evidence becomes disproportionate proof against a person | record delegation and uncertainty; support correction |
| `LINDDUN-004` | Detectability | Presence, absence, or activity is detectable without reading content | non-enumerating errors and opaque capabilities |
| `LINDDUN-005` | Disclosure | Protected data reaches an unintended recipient | authorization, encryption, scoped export, egress control |
| `LINDDUN-006` | Unawareness | A person or organization cannot understand processing and egress | explicit setup, attestations, notices, history |
| `LINDDUN-007` | Non-compliance | Processing violates purpose, retention, transfer, or legal duties | versioned lifecycle rules, holds, restore checks |
| `LINDDUN-008` | Disclosure | Public standards publication exposes private or deployment data | static-site separation and public artifact scans |

Privacy controls can conflict. Auditability can reduce plausible deniability.
Longer retention can support appeals while increasing linkability and
identifiability. Equality search deliberately leaks bounded equality and
frequency information inside one organization. The model records those
tradeoffs as residual risk rather than calling them solved.

Testament cannot promise anonymity, traffic-flow confidentiality, correct
identity inference, or legal compliance. Free-form traces may carry direct and
indirect identifiers in unexpected fields. A pseudonym, summary, feature, or
embedding can still reveal content or identity.

The category definitions come from LINDDUN. NIST SP 800-53 and the GDPR source
record inform the minimization, accountability, retention, erasure, processing
record, and transfer questions. Applicability still requires an accountable
organization and qualified legal review.

The machine file maps every threat to stable data-class, control, validation,
boundary, owner, treatment, and residual-risk records. Its full
boundary-by-category matrix records explicit not-applicable rationales instead
of treating category presence as complete coverage.
