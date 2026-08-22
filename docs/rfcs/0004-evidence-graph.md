# RFC-0004: Provenance-preserving evidence graph

ID: RFC-0004
Status: proposed
Version: 0.1.0
Decision date: None
Supersedes: None
Superseded by: None
Owners: @enoreyes
Reviewers: Independent interoperability reviewer pending

Normative status: Draft

## Summary

This normative draft defines the source-neutral graph that distinguishes
observations, artifacts, actors, actions, links, findings, analyzer runs,
annotations, decisions, receipts, enforcement events, and audit entries.

## Motivation

Span trees cannot faithfully represent loops, retries, fan-in, delegation,
cross-trace relations, or disagreement. A graph can, but only if derivation
and record kinds remain explicit.

## Scope and non-goals

This RFC owns graph envelopes, identities, provenance, links, order axes, and
revision history. Kind-specific payloads are owned by their RFCs. It does not
make adapter output authoritative or turn observations into policy.

## Proposed contract

### Normative contract

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

1. Canonical kinds MUST be separately discriminated schemas for `evidence`,
   `artifact`, `actor`, `action`, `link`, `finding`, `analysis_run`,
   `human_annotation`, `policy_decision`, `enforcement_receipt`,
   `enforcement_event`, and `audit_entry`. A payload of one kind MUST NOT
   validate as another kind.
2. Every record MUST bind schema version, organization, stable identifier,
   creation metadata, provenance class, and immutable revision identity.
   Tenant-owned endpoints and references MUST share the same organization.
3. An observation MUST identify an immutable source artifact and exact ranges
   in its immediate parsed representation for every represented scalar and
   relationship. Transformations MUST name ordered rule IDs and all
   contributing ranges.
4. When exact mapping is impossible, provenance MUST state
   `range_unavailable`, the nearest exact parent range, coordinate layer,
   interval and unit, and a bounded reason. It MUST NOT fabricate an offset.
5. Registered links include `parent`, `follows`, `caused-by`, `retry-of`,
   `replaces`, `resumes`, `invokes`, `returns`, `evaluates`, `approves`,
   `blocks`, and `handoff`. Other links MUST use RFC-0012 namespaces.
6. Graphs MUST preserve fan-in, fan-out, cycles, disconnected components,
   delegation, retries, resumes, streams, and authorized cross-trace links.
   Traversal MUST be bounded and report truncation; it MUST NOT delete edges
   to force a tree.
7. Source, producer, causal, event, and arrival order are independent partial
   orders. Missing values and ties remain unknown or tied. A display
   tie-breaker MUST be labeled noncanonical.
8. Corrections, late events, review, adapter upgrades, and recomputation MUST
   append linked revisions. Earlier identifiers and content MUST remain
   queryable. A revision MUST NOT mutate its predecessor.
9. Imported adapter events and analyzer output MUST NOT create policy
   decisions or assert enforcement. A decision references evidence; actual
   enforcement is a separately attributed event.
10. Namespaced extensions and source-native unknowns MUST survive according
    to RFC-0012. A projection MUST disclose unsupported or lossy material.

### Informative rationale

The graph represents provenance, not certainty. Separate kinds keep provider
safety labels, analyzer assertions, human review, deterministic policy, and
actual actions from collapsing into one misleading event.

## Compatibility and migration

Adding optional record fields or registered link types is minor when unknown
extensions survive. Merging kinds, changing link direction, changing identity
inputs, or reinterpreting an order axis is major. Migration appends new
projections and keeps old graph revisions.

## Security and privacy

Graph edges can disclose relationships even when content is encrypted.
Queries, caches, indexes, exports, and traversal limits must be
organization-scoped. Controls `CTRL-LINKAGE`, `CTRL-MINIMIZE`,
`CTRL-NONENUM`, and `CTRL-CORRECTION` apply.

## Alternatives

An OTel span tree was rejected as the authority because it cannot represent
all required relations. A generic untyped node was rejected because it allows
assertions and decisions to masquerade as observations.

## Validation

Machine checks cover cross-kind substitution, dangling and foreign links,
range resolution, cycles, partial orders, late revisions, and absence of
decisions in adapter/analyzer flows. Manual review inspects a retry and
delegation graph with multiple order axes.

## Open issues

- `RFC-0004-OI-01`: Finalize canonical identifier inputs after collision and
  reprojection experiments.
- `RFC-0004-OI-02`: Define the bounded query representation for intentionally
  disconnected graph components.

## Decision

Pending public interoperability review.

## Supersession

None.
