# RFC-0014: Conformance profiles

ID: RFC-0014
Status: proposed
Version: 0.1.0
Decision date: None
Supersedes: None
Superseded by: None
Owners: @enoreyes
Reviewers: Independent interoperability, security, and deployment reviewer pending

Normative status: Draft

## Summary

This normative draft defines offline conformance inputs, profiles, report
evidence, certification rules, and invalidation for the trust-plane protocols.

## Motivation

A self-declared compatibility claim is not evidence. A reproducible report
must bind implementation, contracts, fixtures, environment, results, and
scope, and must fail when any bound input changes.

## Scope and non-goals

This RFC owns local protocol conformance. It does not certify deployment
security, external-provider behavior, operational enforcement, legal
compliance, or perfect safety.

## Proposed contract

### Normative contract

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

1. The conformance executable MUST run mandatory local checks without network,
   credentials, telemetry, package fetch, remote fonts, hidden analytics, or
   external inference. A network attempt MUST fail the run.
2. Inputs MUST bind executable digest, source commit, platform, profile,
   protocol/schema versions, normative fixture manifest and digests,
   configuration, test catalog version, start/end time, and resource budgets.
3. Only fixtures promoted through an immutable reviewed promotion decision MAY
   affect certification. Informative research fixtures MUST NOT silently enter
   the normative suite.
4. Profiles are cumulative:
   - `T1-custody`: RFC-0003 and RFC-0005 exactness, integrity, malformed
     custody, bounds, and artifact availability.
   - `T2-graph`: T1 plus RFC-0004 provenance, distinct kinds, links, orders,
     revisions, and extension preservation.
   - `T3-analysis`: T2 plus RFC-0006 and RFC-0007 finding/run contracts,
     provenance, isolation-visible states, budgets, and replay.
   - `T4-policy`: T3 plus RFC-0008 through RFC-0011 hook, decision, receipt,
     enforcement-separation, audit, and checkpoint contracts.
5. RFC-0012 and RFC-0013 tests apply to every profile. Profile prerequisites
   MUST NOT be waived, duplicated, or replaced by a higher-level result.
6. Reports MUST include one row per mandatory test with stable ID, status,
   input/expected/actual digests, duration, bounded diagnostics, and evidence
   locator. Status is `pass`, `fail`, `not_run`, or `unsupported`.
7. Certification MUST be awarded only when every mandatory row and
   prerequisite passes. `not_run`, `unsupported`, stale, inaccessible,
   duplicated, waived, or self-declared evidence scores zero.
8. The report MUST sign or digest-bind its canonical contents and all inputs.
   Any changed executable, contract, schema, fixture, expectation,
   configuration, environment rule, or report row MUST invalidate the result.
9. Resource-limit, malformed-input, cross-kind, tenant-scope, unknown-field,
   and mutation-negative tests are mandatory. A harness that accepts a
   deliberately corrupted oracle MUST fail its own integrity check.
10. Claims MUST name exact profile, version, implementation digest, report
    digest, platform, and limitations. A local profile MUST NOT claim
    production deployment, real cloud KMS, or actual protected-server
    enforcement without separate evidence.

### Informative rationale

Cumulative profiles allow a raw custodian to conform without claiming policy
support. Network denial makes local results reproducible and prevents a test
from leaking fixture content.

## Compatibility and migration

Adding a mandatory test changes the profile minor before 1.0 and requires a
new report. Removing or weakening a mandatory invariant is major. Old reports
remain historical but do not certify changed bound inputs.

## Security and privacy

Fixtures must be harmless, synthetic or clearly redistributable, licensed, and
free of secrets and personal data. Reports must not contain captured content,
credentials, local absolute paths, or private-only evidence.

## Alternatives

One all-or-nothing badge was rejected because it overstates partial
implementations. Online-only certification was rejected because credentials
and remote behavior harm reproducibility.

## Validation

Machine checks run under denied network, mutate each bound input, reject
unpromoted fixtures, recompute profile prerequisites, and scan reports for
secrets and private paths. Manual review follows every report row to public
normative text and fixture evidence.

## Open issues

- `RFC-0014-OI-01`: Finalize mandatory test IDs after the synthetic corpus and
  fixture-promotion contract are complete.
- `RFC-0014-OI-02`: Select report signing and public certification trust
  policy.

## Decision

Pending corpus, promotion, and independent review.

## Supersession

None.
