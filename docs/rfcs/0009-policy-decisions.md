# RFC-0009: Policy decisions

ID: RFC-0009
Status: proposed
Version: 0.1.0
Decision date: None
Supersedes: None
Superseded by: None
Owners: @enoreyes
Reviewers: Independent security and interoperability reviewer pending

Normative status: Draft

## Summary

This normative draft defines deterministic contributor-complete policy
decisions, obligations, availability, effective action, and degraded
allow-and-audit behavior.

## Motivation

Evaluation outcome, dependency availability, effective action, and later
enforcement are different facts. Combining them hides degraded operation and
allows untrusted analyzer output to select policy.

## Scope and non-goals

This RFC owns decision records and outcome semantics. It does not define CEL
syntax, policy-bundle signing, receipt encoding, or protected-server behavior.

## Proposed contract

### Normative contract

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

1. A decision MUST bind organization, decision ID, hook and phase, actor,
   action, resource, evidence/input digest, immutable policy revision and
   contributor digest, analyzer/run inputs, authorization snapshot, clock,
   idempotency identity, and schema version.
2. Evaluation outcomes are `allow`, `deny`, `challenge`, `rate_limit`,
   `quarantine`, `escalate`, and `indeterminate`. Availability is separately
   `complete`, `degraded`, or `core_unavailable`.
3. Composition MUST be deterministic, retain every contributor and
   obligation, reject incompatible equal-priority obligations, and prevent a
   lower layer from weakening an undelegated higher-layer control.
4. Analyzer results are untrusted assertions. Only the pinned deterministic
   policy program MAY choose an evaluation outcome. Raw model output MUST NOT
   select an action.
5. A normal `deny` MUST produce effective deny. It MUST NOT become degraded
   allow.
6. When a required safety check is unavailable or indeterminate and tenant
   resolution, decision durability, audit durability, and signing remain
   healthy, effective action MUST be allow with availability `degraded`.
   The decision MUST name the missing check and affected hook.
7. A degraded decision MUST NOT be labeled safe, passed, approved, or
   successfully evaluated on any surface. Setup MUST require explicit
   acknowledgement of this availability behavior.
8. `core_unavailable` MUST NOT produce a valid decision receipt. The caller
   receives an explicit dependency failure and no claim about the protected
   effect.
9. The decision, contributors, degraded audit entry, and receipt-signing
   intent MUST commit atomically before a receipt is returned.
10. Actual enforcement MUST be a later separately attributed event. Decision
    issuance MUST NOT imply `applied`.

### Informative rationale

The approved degraded behavior favors availability but preserves evidence that
evaluation was incomplete. Separating core failure avoids using degraded
semantics when Testament cannot durably prove what occurred.

## Compatibility and migration

Adding an optional obligation type is minor only if unsupported obligations
cause explicit refusal rather than being ignored. Changing the outcome
lattice, degraded preconditions, contributor digest, or atomicity is major.
Historical decisions remain immutable.

## Security and privacy

Decisions are security-sensitive and tenant scoped. Controls
`CTRL-DEGRADED`, `CTRL-AUDIT`, `CTRL-INTEGRITY`, `CTRL-IDENTITY`, and
`CTRL-NONENUM` apply. Decision metadata must not expose source content.

## Alternatives

Fail-closed on every analyzer outage was not selected by the approved
architecture. Treating indeterminate as ordinary allow was rejected because
it erases degraded evidence. Letting models decide was rejected because output
is untrusted.

## Validation

Machine checks cover all outcome and availability combinations, deterministic
composition, contributor retention, denial, degraded prerequisites, atomic
audit, core failure, and forbidden labels. Manual review follows one ordinary
denial and one degraded allow across API, CLI, console data, and audit.

## Open issues

- `RFC-0009-OI-01`: Finalize conflict resolution for stateful obligations at
  equal priority.
- `RFC-0009-OI-02`: Define the exact contributor digest canonicalization.

## Decision

Pending public review. The degraded availability principle is architecture
approved; this record's encoding and validation details are not yet accepted.

## Supersession

None.
