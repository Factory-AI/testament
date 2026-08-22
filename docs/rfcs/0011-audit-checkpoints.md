# RFC-0011: Audit chains and signed checkpoints

ID: RFC-0011
Status: proposed
Version: 0.1.0
Decision date: None
Supersedes: None
Superseded by: None
Owners: @enoreyes
Reviewers: Independent cryptography, security, and interoperability reviewer pending

Normative status: Draft

## Summary

This normative draft defines organization-scoped audit chains, signed
checkpoints, tamper localization, signer failure, rotation, and restore
anti-rollback authority.

## Motivation

A database-local hash chain can detect internal mutation but cannot by itself
prove that an attacker did not restore an older valid chain. Checkpoints need
purpose-separated signing and independent recovery authority.

## Scope and non-goals

This RFC owns audit entry and checkpoint integrity. It does not promise
immutability against a compromised runtime or prescribe an external
transparency service.

## Proposed contract

### Normative contract

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

1. Each organization MUST have an independent monotonically sequenced audit
   chain. Entries MUST bind organization, sequence, actor, action, target,
   outcome, request identity, time, canonical content-free payload digest,
   prior hash, and entry hash.
2. Canonicalization, hash algorithm, domain separator, and genesis value MUST
   be versioned. Entries MUST NOT contain source content, prompts, credentials,
   DEKs, or signing material.
3. A checkpoint MUST bind organization, chain version, covered sequence,
   covered entry hash, prior checkpoint identity, time, signer purpose, key ID
   and generation, algorithm, and signature.
4. Checkpoint progress MUST become visible only after successful signing and
   durable commit. Signer or KMS failure MUST NOT advance progress and MUST
   surface degraded readiness.
5. Verification MUST detect and report the first mutation, deletion,
   insertion, duplication, reorder, truncation, wrong-organization entry,
   field mutation, broken checkpoint link, or signature change. It MUST NOT
   silently repair history.
6. Audit-root rotation MUST create a linked signer-generation transition.
   Historical entries and checkpoints MUST NOT be rehashed or resigned.
7. Backup and restore MUST preserve entry bytes, heads, checkpoints, and
   signer lineage. Rewrap MUST NOT rewrite history.
8. Before restored data is served, Testament MUST compare organization epoch,
   audit/checkpoint head, key generations, and tombstone watermark with a
   separately protected signed recovery authority not reconstructed from the
   candidate backup.
9. Missing, older, forked, wrong-organization, or untrusted recovery authority
   MUST keep affected data unreadable and readiness false.
10. Claims MUST say `tamper-evident`. They MUST NOT claim immutable or
    rollback-proof without current independently controlled authority.

### Informative rationale

Per-organization chains avoid cross-tenant ordering and disclosure. External
recovery authority supplies the state a self-contained backup cannot know.

## Compatibility and migration

Adding optional non-hashed display metadata is minor only when canonical entry
bytes do not change. Changing canonicalization, hash/signature algorithms, or
genesis semantics requires a new version and linked transition. Historical
verification remains available.

## Security and privacy

Audit is sensitive even without content. Actor, timing, and action metadata
require organization-scoped access. Signing and recovery keys must be purpose
separated. Runtime compromise remains an honest limitation.

## Alternatives

A single global chain was rejected because it leaks cross-organization
activity and couples availability. Backup-contained authority was rejected
because it cannot detect rollback of itself.

## Validation

Machine checks recompute chains, mutate each structure, verify first-failure
location, inject signer failure, rotate roots, restore old backups, and test
stale/forked recovery authorities. Manual review checks limitation wording.

## Open issues

- `RFC-0011-OI-01`: Select the checkpoint signature suite and external
  recovery-authority packaging.
- `RFC-0011-OI-02`: Set checkpoint cadence and maximum uncheckpointed window
  from durability benchmarks.

## Decision

Pending cryptography, security, and interoperability review.

## Supersession

None.
