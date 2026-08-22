# RFC-0006: Findings

ID: RFC-0006
Status: proposed
Version: 0.1.0
Decision date: None
Supersedes: None
Superseded by: None
Owners: @enoreyes
Reviewers: Independent interoperability and analysis reviewer pending

Normative status: Draft

## Summary

This normative draft defines findings as immutable analyzer assertions with
evidence, counterevidence, uncertainty, taxonomy, and review lineage.

## Motivation

An analyzer result is neither a source observation nor a policy decision.
Reviewers need to see what supports a claim, what contradicts it, and how
uncertain the analyzer was.

## Scope and non-goals

This RFC owns finding payloads and their relation to runs and review records.
It does not define analyzer execution, policy outcomes, or case-management UI.

## Proposed contract

### Normative contract

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

1. A finding MUST bind organization, finding ID, analysis-run ID, analyzer
   revision, immutable input snapshot, taxonomy and taxonomy version, claim,
   status, created time, and schema version.
2. Status is `asserted`, `abstained`, or `invalid`. `asserted` MUST include
   one or more verified evidence references unless its taxonomy explicitly
   permits aggregate evidence with a pinned reproducible feature artifact.
3. Scores MUST state scale, direction, raw value, calibrated value when
   available, calibration revision, threshold revision, and uncertainty.
   Missing calibration MUST remain missing, not zero.
4. Evidence and counterevidence MUST resolve to graph records and exact source
   provenance under RFC-0004. A verifier failure MUST prevent the finding from
   becoming `asserted`.
5. Findings MUST distinguish observation, inference, and taxonomy mapping.
   They MUST NOT contain hidden chain-of-thought as evidence.
6. Analyzer diagnostics, malformed output, timeouts, and partial output MUST
   NOT be promoted to findings. The terminal analysis run records those states.
7. A finding MUST NOT directly select a policy outcome or claim that an action
   was enforced. Policy decisions and enforcement events are separate kinds.
8. Human labels, dispositions, suppressions, appeals, and corrections MUST be
   attributed append-only annotations. They MUST NOT rewrite the original
   finding.
9. A later finding MAY supersede an earlier finding only with an explicit
   relation and reason. Both remain queryable. Late data MUST identify the
   prior input watermark and the recomputation trigger.
10. Content-bearing claims and evidence extracts MUST be encrypted under the
    organization content path. Search and export MUST remain organization
    scoped.

### Informative rationale

Abstention is a useful result, not a weak assertion. Keeping raw and calibrated
scores avoids pretending that incomparable analyzer outputs share one scale.
Counterevidence helps reviewers assess ambiguous authorized-use twins.

## Compatibility and migration

Adding optional diagnostic or taxonomy mappings is minor. Reinterpreting score
direction, status, evidence requirements, or assertion meaning is major.
Recalibration creates new findings or linked calibration views; it does not
rewrite historical values.

## Security and privacy

Findings may reveal sensitive inferences beyond source text. Access, display,
export, retention, and deletion must cover both claims and references.
`CTRL-UNTRUSTED-IO`, `CTRL-CORRECTION`, `CTRL-MINIMIZE`, and
`CTRL-LIFECYCLE` apply.

## Alternatives

Embedding policy outcomes in findings was rejected because untrusted model
output cannot enforce. Mutating findings after review was rejected because it
destroys the evidence trail.

## Validation

Machine checks cover evidence range verification, score metadata, abstention,
cross-kind rejection, invalid-output suppression, annotation history, and
absence of decisions. Manual review follows an authorized-use twin through
finding, counterevidence, review, and appeal.

## Open issues

- `RFC-0006-OI-01`: Finalize the minimum interoperable uncertainty
  representation across deterministic and probabilistic analyzers.
- `RFC-0006-OI-02`: Define taxonomy mapping conflict representation.

## Decision

Pending analyzer evaluation and independent interoperability review.

## Supersession

None.
