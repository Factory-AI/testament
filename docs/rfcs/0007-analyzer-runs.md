# RFC-0007: Analyzer runs

ID: RFC-0007
Status: proposed
Version: 0.1.0
Decision date: None
Supersedes: None
Superseded by: None
Owners: @enoreyes
Reviewers: Independent interoperability, security, and performance reviewer pending

Normative status: Draft

## Summary

This normative draft defines one analyzer manifest, request, terminal result,
resource, provenance, replay, and host-commit contract for every analyzer
family.

## Motivation

Deterministic rules, classifiers, local models, external LLMs, ensembles,
sequences, and graph analysis need different implementations but the same
authority and audit boundaries.

## Scope and non-goals

This RFC owns analyzer registration and run records. It does not prescribe a
model, taxonomy, sandbox technology, or policy rule.

## Proposed contract

### Normative contract

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

1. An analyzer manifest MUST bind contract version, analyzer family,
   implementation and build digest, capabilities, accepted content classes,
   output schema, determinism class, isolation requirements, resource bounds,
   and sovereignty compatibility.
2. A request MUST bind invocation ID, organization, purpose, mode, immutable
   authorized evidence snapshot, ordered window and watermark, sensitivity,
   upstream run IDs, deadline, resource and cost budgets, taxonomy/output
   versions, sovereignty attestation, and idempotency key.
3. An analyzer MUST receive only host-authorized content handles and declared
   metadata. It MUST NOT receive ambient database, filesystem, environment,
   network, KMS, or provider-credential access.
4. Every admitted attempt MUST produce exactly one immutable terminal run:
   `succeeded`, `abstained`, `invalid_output`, `timed_out`, `canceled`,
   `budget_exhausted`, `dependency_unavailable`, or `failed`.
5. Only the host validates output, verifies evidence, adds authoritative
   provenance, encrypts content, and commits findings. Partial or invalid
   output MUST NOT leak findings.
6. Provenance MUST pin analyzer/build, binding revision, input-set digest,
   prompt-template and rendered-request digest when applicable, model and
   endpoint revision, weights/tokenizer or remote fingerprint, canonical
   configuration, sampling, calibration, thresholds, taxonomy, profile,
   parent runs, timing, usage, cost, and reproducibility class.
7. Reproducibility classes are `deterministic`, `seeded_best_effort`,
   `observed_remote`, and `opaque_remote`. Implementations MUST NOT label a
   remote result deterministic without reproducible evidence.
8. External calls MUST use the central egress broker, explicit organization
   authorization, an allowed destination, fixed attempts, and reserved hard
   budgets. There MUST NOT be silent provider or model fallback.
9. Replay MUST declare `recorded` or `fresh`. Recorded replay reuses committed
   output; fresh replay creates a new run. Both preserve the original and
   current authorization and profile evidence.
10. Ensemble and longitudinal runs MUST pin their dependency DAG, order,
    state/checkpoint version, watermark, and late-event policy. New results
    supersede rather than mutate prior runs.

### Informative rationale

The host is the trust boundary. Uniform terminal states prevent model-specific
exceptions from becoming hidden policy behavior. Immutable attempts preserve
uncertain sends, cost, and late responses.

## Compatibility and migration

Adding optional capabilities or terminal diagnostics is minor. Changing
terminal semantics, authorization snapshot, host authority, budget accounting,
or provenance digest inputs is major. Old runs remain readable under their
contract version.

## Security and privacy

Trace content is hostile input. Output is untrusted structured data. The
runtime must enforce `CTRL-CAPABILITY`, `CTRL-EGRESS`, `CTRL-UNTRUSTED-IO`,
`CTRL-BOUNDS`, and `CTRL-MINIMIZE`. External provider behavior is declared,
not cryptographically proven by Testament.

## Alternatives

Native Go plugins were rejected because they inherit ambient process
capabilities. Family-specific contracts were rejected because they create
inconsistent authorization, provenance, and policy mappings.

## Validation

Machine checks exercise every family, immutable snapshots, terminal
exactly-once commit, hostile output, cancellation, budget exhaustion, no
fallback, replay, and provenance completeness. Manual review compares local
deterministic and remote opaque runs over the same authorized scope.

## Open issues

- `RFC-0007-OI-01`: Choose the constrained extension transport and sandbox
  after the isolation prototype.
- `RFC-0007-OI-02`: Finalize canonical input-set digest construction.

## Decision

Pending analyzer evaluation, isolation results, and independent review.

## Supersession

None.
