# RFC-0010: Signed decision receipts

ID: RFC-0010
Status: proposed
Version: 0.1.0
Decision date: None
Supersedes: None
Superseded by: None
Owners: @enoreyes
Reviewers: Independent cryptography and interoperability reviewer pending

Normative status: Draft

## Summary

This normative draft defines short-lived signed receipts that bind a durable
decision to one protected action context without claiming enforcement.

## Motivation

An enforcement point needs a compact proof that cannot be replayed for another
tenant, action, resource, input, policy, audience, or time window.

## Scope and non-goals

This RFC owns receipt claims, canonical signing input, verification order,
nonce consumption, and reporting. It does not define policy evaluation or
claim that a verifier applied the result.

## Proposed contract

### Normative contract

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

1. A receipt MUST bind receipt and decision IDs, organization, actor, hook,
   action, resource, input/evidence digest, effective policy revision and
   contributor digest, evaluation outcome, availability, effective action,
   obligations, issued-at, not-before, expiry, nonce, audience, issuer,
   signing purpose, algorithm, key ID and generation, and contract version.
2. The signed bytes MUST use one specified deterministic canonical encoding.
   Fields MUST NOT be omitted or defaulted during verification.
3. Receipts MUST be short lived. Verifiers MUST apply the RFC-0013 time
   contract and reject expired, premature, unknown-version, unknown-key,
   revoked-key, wrong-purpose, and unsupported-algorithm receipts.
4. Before effect, a verifier MUST validate signature, trust anchor, issuer,
   audience, organization, actor, hook, action, resource, digests, policy
   identity, outcome/availability, obligations, time, and nonce.
5. Nonce and idempotency consumption MUST be atomic with the protected effect
   or with a durable outcome record that safely reconciles uncertain effects.
   Twenty concurrent valid retries MUST cause at most one effect.
6. Replay, stale, malformed, cross-organization, context-mismatched, and
   changed-input receipts MUST produce no protected effect and bounded
   non-enumerating errors.
7. A degraded receipt MUST preserve evaluation `indeterminate` or the missing
   dependency, availability `degraded`, and effective allow. It MUST NOT claim
   successful safety evaluation.
8. Core-unavailable decisions MUST NOT be signed. There MUST be no unsigned or
   local fallback that looks like a valid receipt.
9. Verification and actual action outcomes MUST be separately recorded and
   linked to the receipt. Receipt issuance MUST NOT imply enforcement.
10. Private signing material MUST be organization and purpose separated from
    audit, release, identity, and transport keys. Rotation MUST preserve
    bounded historical verification without permitting retired signing.

### Informative rationale

The receipt proves what Testament durably decided for one context. Exactly-once
effects still require protected-server state; signatures alone do not prevent
replay or TOCTOU.

## Compatibility and migration

Adding a signed field changes canonical bytes and therefore requires a new
receipt minor only when negotiation guarantees old verifiers reject or safely
ignore it as specified. Removing or reinterpreting a bound field is major.
Historical verification retains the original algorithm and trust generation.

## Security and privacy

Receipts can be bearer-like capabilities. They must be minimal, short-lived,
audience-bound, never logged in full, and protected in transit. Nonces and
errors must resist cross-tenant enumeration. Cryptographic choices require
independent review and known-answer vectors.

## Alternatives

Opaque database tokens were rejected as the only form because offline
verification is required. Self-contained signatures without nonce state were
rejected because they do not stop replay.

## Validation

Machine checks mutate every signed field, exercise key and clock boundaries,
run concurrent replay, test context mismatches, verify no receipt under core
failure, and compare decision with actual action evidence.

## Open issues

- `RFC-0010-OI-01`: Select the canonical encoding and signature algorithm
  suite after cryptographic review.
- `RFC-0010-OI-02`: Set profile-specific maximum lifetimes and clock skew.

## Decision

Pending cryptography and interoperability review.

## Supersession

None.
