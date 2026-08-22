# RFC-0005: Artifacts

ID: RFC-0005
Status: proposed
Version: 0.1.0
Decision date: None
Supersedes: None
Superseded by: None
Owners: @enoreyes
Reviewers: Independent interoperability and security reviewer pending

Normative status: Draft

## Summary

This normative draft defines exact, derived, inline, locally retained,
external-reference, missing, incomplete, corrupted, and unauthorized
artifacts.

## Motivation

Empty content, an inaccessible locator, and a zero-byte artifact are different
facts. Conflating them loses integrity and can cause accidental network
fetches or false completeness.

## Scope and non-goals

This RFC owns artifact identity, integrity, provenance, availability, and
access semantics. It does not define a storage engine, decryption envelope, or
external object-store integration.

## Proposed contract

### Normative contract

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

1. Every artifact MUST bind organization, artifact ID, kind, authority,
   media type, optional encoding, exact byte count when known, digest
   algorithm and digest when bytes are authoritative, completion, provenance,
   availability, and version.
2. Kinds are `exact`, `derived`, and `external_reference`. Availability is
   independently one of `available`, `missing`, `incomplete`, `corrupted`, or
   `unauthorized`. A status MUST NOT be represented by substituting empty
   bytes.
3. Exact artifacts MUST point to an immutable raw-capture manifest. Derived
   artifacts MUST identify every direct parent, transformation rule and
   revision, and whether reproduction is deterministic.
4. Inline and chunked storage are encoding choices and MUST NOT change
   artifact identity or authority. Retrieval MUST verify the authenticated
   manifest and digest before emitting any plaintext.
5. External references MUST preserve the supplied locator as governed data,
   identify its source range, and declare whether bytes were ever captured.
   Testament MUST NOT automatically fetch, preview, resolve, or dereference a
   locator.
6. Authorization failure MUST use non-enumerating semantics and MUST NOT
   reveal whether bytes, names, sizes, or locators exist in another
   organization.
7. A completed exact artifact is immutable. Redaction, transcoding, summary,
   thumbnail, or repair MUST create a derived artifact. Deletion changes
   governed availability through a tombstone; it MUST NOT rewrite history.
8. Unknown media types and invalid text MUST remain byte-addressable. Display
   layers MUST render arbitrary content as data, never trusted markup.
9. Exports MUST bind the selected artifact identities, representations,
   digests, authorization revision, and generation time. Partial export MUST
   report failure and MUST NOT claim a complete manifest.

### Informative rationale

Kind and availability are orthogonal. The model supports an available external
reference record whose target was never fetched, and a locally retained exact
artifact that later becomes unavailable after governed deletion.

## Compatibility and migration

Adding availability detail is minor when old values retain meaning. Changing
digest scope, authority, or the no-fetch rule is major. Historical artifacts
and tombstones remain queryable after migration.

## Security and privacy

Locators, media metadata, and digest equality can be sensitive. Access,
exports, caches, and logs must follow `CTRL-IDENTITY`, `CTRL-INTEGRITY`,
`CTRL-MINIMIZE`, and `CTRL-NONENUM`. Locators require SSRF-safe rendering and
must not become active links by default.

## Alternatives

Treating all artifacts as byte blobs was rejected because references and
missing content require honest states. Automatic remote hydration was rejected
because it creates unapproved egress and provider-side retention.

## Validation

Machine checks verify independent kind/availability combinations, exact
digests, no empty substitution, corruption before plaintext, tenant isolation,
and zero network access for external references. Manual review compares a
zero-byte exact artifact with missing and unauthorized records.

## Open issues

- `RFC-0005-OI-01`: Define the optional locator-display profile for the
  console without creating automatic requests.
- `RFC-0005-OI-02`: Decide whether digest disclosure is suppressed for
  unauthorized and equality-sensitive contexts.

## Decision

Pending public review.

## Supersession

None.
