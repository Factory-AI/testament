# RFC-0003: Raw capture

ID: RFC-0003
Status: proposed
Version: 0.1.0
Decision date: None
Supersedes: None
Superseded by: None
Owners: @enoreyes
Reviewers: Independent interoperability and security reviewer pending

Normative status: Draft

## Summary

This normative draft defines exact-byte custody, transport layers, bounded
chunking, finalization, and parse-independent capture for authorized inputs.

## Motivation

Provider and observability formats lose detail when a receiver starts from a
parsed object. Testament needs one authority that survives malformed, unknown,
binary, and future formats without implying semantic understanding.

## Scope and non-goals

This RFC owns accepted entity bytes, representation layers, capture sessions,
chunk manifests, and custody states. It does not define provider semantics,
encryption primitives, authorization policy, or retention periods.

## Proposed contract

### Normative contract

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

1. The authoritative source for HTTP ingest MUST be the entity bytes after
   TLS and transfer framing are removed and before `Content-Encoding` is
   decoded. CLI and file authority MUST be exactly the bytes read.
2. Original, content-decoded, parsed-record, materialized-message, and semantic
   projection layers MUST have separate identities, byte counts, digests, and
   derivation links. A derived layer MUST NOT replace its parent.
3. A capture MUST bind organization, source identity, declared media metadata,
   accepted time, exact byte count, digest algorithm and digest, completion,
   and authority layer. Organization context MUST be server-derived.
4. Capture MUST accept zero bytes, binary data, invalid UTF-8, malformed
   structured data, and unknown formats when authorization and quota permit.
   Parse failure MUST NOT revoke finalized raw custody.
5. Streaming ingest MUST use bounded independently authenticated chunks.
   Ordinals begin at zero and are contiguous. A final authenticated manifest
   MUST bind organization, object, schema, media type, ordered chunk digests,
   total bytes, exact-source digest, key generation, and completion.
6. Incomplete sessions MUST NOT be exposed as finalized evidence. Durable
   acknowledgements MUST identify the next accepted offset. Resume tokens MUST
   bind organization, session, prior-byte digest, offset, expiry, and state.
7. Idempotency MUST bind organization, operation, authorization, declarations,
   and exact input digest. Same-scope replay returns the prior result; changed
   input conflicts.
8. Limits MUST be declared for entity bytes, decoded expansion, chunks,
   session duration, diagnostics, and concurrent work. Crossing a semantic
   parse limit MAY retain raw bytes with an explicit `raw-retained` result.
9. Capture states are `receiving`, `finalizing`, `finalized`, `aborted`, and
   `expired`. Terminal states MUST be immutable. Finalization MUST atomically
   publish the manifest, custody receipt, and audit effect or publish none.
10. Implementations MUST preserve content type, content encoding, source and
    arrival order, producer identifiers when supplied, parse status, warnings,
    completeness, adapter revision, and lossiness without inventing values.

### Informative rationale

The authority boundary reflects what an application can recover reliably.
TLS records and transfer-frame bytes are intentionally outside the promise.
Separate decoded artifacts allow useful parsing without changing the source.
Authenticated chunks bound memory and isolate corruption.

## Compatibility and migration

This is a new wire and storage contract. Additive optional metadata is
minor-compatible. Changing authority boundaries, digest meaning, state
transitions, or manifest authentication is major. Historical source and
manifest identities remain readable and MUST NOT be rewritten during upgrade.

## Security and privacy

Capture crosses producer, ingest, runtime, storage, and operator boundaries.
Implementations must apply `CTRL-IDENTITY`, `CTRL-INTEGRITY`, `CTRL-ENCRYPT`,
`CTRL-BOUNDS`, and `CTRL-LINKAGE` from the threat research. Exact content is
sensitive; logs, metrics, diagnostics, and temporary storage must exclude it.
A compromised authorized runtime can still observe plaintext.

## Alternatives

Parsing before retention was rejected because malformed and unknown material
would be lost. Storing only decoded content was rejected because it changes
authority. One authenticated blob was rejected because it frustrates bounded
streaming and corruption localization.

## Validation

Machine checks cover byte equality, layer separation, partial invisibility,
chunk reorder/truncation/substitution, resume offsets, idempotency, and bounded
resources. Manual review confirms authority wording does not promise TLS or
transfer-frame recovery.

## Open issues

- `RFC-0003-OI-01`: Set the exact default, minimum, and maximum chunk sizes
  from the precommitted storage benchmark.
- `RFC-0003-OI-02`: Decide whether trailers accepted by an HTTP integration
  require a separate metadata artifact.

## Decision

Pending public review. Acceptance requires non-author interoperability and
security review, plus resolution or explicit deferral of every open issue.

## Supersession

None.
