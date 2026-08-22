# RFC-0013: Protocol and schema versioning

ID: RFC-0013
Status: proposed
Version: 0.1.0
Decision date: None
Supersedes: None
Superseded by: None
Owners: @enoreyes
Reviewers: Independent interoperability reviewer pending

Normative status: Draft

## Summary

This normative draft defines independent version domains, compatibility
classes, negotiation, support windows, lineage, and historical readability.

## Motivation

Protocol, schema, implementation, database, adapter, fixture, and conformance
versions evolve at different rates. One product version cannot safely stand
in for all of them.

## Scope and non-goals

This RFC owns public contract versioning. It does not define release cadence,
database migrations, or a compatibility promise before a contract reaches
1.0.

## Proposed contract

### Normative contract

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

1. Version domains for HTTP API, CLI JSON, each canonical schema, raw capture,
   graph, artifacts, findings, analyzer runs, hooks, decisions, receipts,
   checkpoints, extensions, adapters, fixtures, and conformance MUST be
   explicit and independently identifiable.
2. Versions use `major.minor.patch`. Major means a breaking semantic or wire
   change; minor means an additive compatible change; patch means a
   clarification or fixture correction that changes no semantics.
3. An implementation version, Git commit, database migration, or release tag
   MUST NOT substitute for a protocol or schema version.
4. Negotiation MUST name the contract domain and supported versions or range.
   Selection MUST be deterministic and returned explicitly. There MUST NOT be
   silent downgrade or fallback across domains.
5. A future major MUST be retained as raw unsupported input when custody is
   authorized; it MUST NOT be partially interpreted as the current major.
   Same-major higher-minor behavior MUST be declared per domain.
6. Unknown permitted RFC-0012 extensions MUST survive import and export.
   Unsupported core fields MUST NOT be treated as extensions.
7. After 1.0, the current and previous stable major of every persisted
   protocol/schema MUST remain readable. Write support MAY be narrower but
   MUST be published.
8. Breaking changes require a new RFC, migration and compatibility analysis,
   fixtures, conformance updates, and supersession links. Accepted historical
   artifacts MUST NOT be edited in place.
9. Every projection and adapter output MUST pin source digest, schema,
   adapter/revision, configuration/detection inputs, and creation metadata.
   Reprojection appends a new version.
10. Compatibility claims MUST be generated from a machine-readable matrix
    covering read, write, import, export, negotiate, preserve, and reject
    behavior. Untested combinations MUST be `unverified`, not compatible.

### Informative rationale

Independent domains let an adapter improve without forcing a receipt major.
Raw retention of unknown future majors preserves custody without pretending
the current implementation understands them.

## Compatibility and migration

This RFC is itself pre-1.0. Once accepted at 1.0, changes to major/minor/patch
meaning, support window, or negotiation are breaking. Historical RFC files,
schemas, fixtures, reports, and projection versions remain immutable.

## Security and privacy

Downgrade and parser-confusion attacks are security concerns. Negotiation must
be authenticated with the enclosing request or artifact and included in
receipts, audit, and conformance reports where relevant.

## Alternatives

One repository or product version was rejected because it hides independent
contract change. Best-effort interpretation of future majors was rejected
because it can silently change security meaning.

## Validation

Machine checks enumerate the compatibility matrix, test independent
negotiation, reject downgrade and unknown majors, preserve extensions, and
prove current/previous stable readability after 1.0.

## Open issues

- `RFC-0013-OI-01`: Define domain-specific same-major higher-minor defaults.
- `RFC-0013-OI-02`: Set the support and security-fix window for a previous
  stable major.

## Decision

Pending public interoperability review.

## Supersession

None.
