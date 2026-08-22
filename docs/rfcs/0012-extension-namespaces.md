# RFC-0012: Extension namespaces

ID: RFC-0012
Status: proposed
Version: 0.1.0
Decision date: None
Supersedes: None
Superseded by: None
Owners: @enoreyes
Reviewers: Independent interoperability reviewer pending

Normative status: Draft

## Summary

This normative draft defines registered and reverse-domain extension
namespaces, ownership, collision handling, recursive preservation, and limits
on core behavior.

## Motivation

Strict core schemas and future interoperability require a safe place for
unknown data. Unnamespaced additions collide; silently discarded additions
destroy round-trip fidelity.

## Scope and non-goals

This RFC owns Testament document extensions. Provider-native unknown data also
remains recoverable through raw custody and native sidecars. This RFC does not
standardize every provider field.

## Proposed contract

### Normative contract

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

1. Core Testament objects MUST reject unknown unnamespaced fields when they
   claim a supported schema. Permitted extensions MUST appear in the declared
   extension container under a registered name or a reverse-domain name
   controlled by the producer.
2. A namespace registration MUST identify owner, contact, purpose, status,
   schema/version locator, security and privacy considerations, collision
   policy, and supersession history.
3. Extension values MUST use JSON-compatible values within declared depth,
   member, scalar, and byte limits. Names and values MUST NOT be interpreted
   as executable code, markup, filesystem paths, callbacks, or network
   destinations by default.
4. Import, storage, query, and export MUST preserve unknown permitted
   extensions recursively, including key spelling, arrays and order, numeric
   representation where the encoding preserves it, and value bytes or exact
   source provenance.
5. An unknown extension MUST NOT change core validation, authorization,
   policy, identity, signature, conformance, or capability. Behavior-changing
   extensions require explicit negotiated capability and their own normative
   contract.
6. Namespace collision MUST fail explicitly. Implementations MUST NOT choose
   one colliding meaning based on load order.
7. A namespaced value that conflicts with a core field MUST remain extension
   data and MUST NOT override the core field.
8. Sensitive extensions inherit the enclosing record's organization,
   encryption, retention, deletion, export, and authorization controls.
9. Provider-native unknown fields and protobuf unknowns MUST remain
   recoverable at source locations even when not promoted into this extension
   container.
10. A future-major Testament document MUST remain raw and unsupported unless
    that major is negotiated. Extension preservation MUST NOT be used to
    partially accept an unknown core schema.

### Informative rationale

The extension container balances strict envelopes with round trips. Reverse
domain ownership avoids a central registration dependency for experiments,
while registration supports widely shared semantics.

## Compatibility and migration

Adding a non-behavioral extension is compatible. Promoting an extension to
core requires a mapping, collision rule, version change, and preservation of
the old representation. Making an unknown extension behavior-changing without
negotiation is major and forbidden.

## Security and privacy

Extensions are hostile input and can hide large, sensitive, or active values.
Limits, plain-data rendering, content classification, encryption, and export
review are mandatory. Namespace ownership is not a security endorsement.

## Alternatives

Allowing arbitrary top-level fields was rejected because it prevents strict
validation. Dropping unknowns was rejected because it breaks future and
provider round trips.

## Validation

Machine checks recursively round-trip unknown extensions, reject
unnamespaced/core collisions, enforce limits, preserve provider-native
sidecars, and prove extensions cannot grant capabilities or affect policy.

## Open issues

- `RFC-0012-OI-01`: Finalize the registry governance and namespace-name syntax.
- `RFC-0012-OI-02`: Define canonical byte preservation for extension numbers
  across JSON and optional protobuf bindings.

## Decision

Pending public interoperability review.

## Supersession

None.
