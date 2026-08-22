# ADR-0002: Immutable indexed decision log

ID: ADR-0002
Status: accepted
Version: 1.0.0
Decision date: 2026-08-21
Supersedes: ADR-0001
Superseded by: None
Owners: @enoreyes
Reviewers: @enoreyes

## Context

Accepted decisions must remain inspectable after the project changes course.
A mutable "current decision" file loses old rationale and makes review links
ambiguous.

## Decision

Accepted on 2026-08-21 by @enoreyes under the bounded single-maintainer
bootstrap exception: use numbered ADR files, controlled statuses, a
machine-readable index, SHA-256 binding, and reciprocal index supersession
links. Final ADR files remain unchanged. There was no independent reviewer.

## Alternatives

Git history alone was rejected because a newcomer should not have to infer
status and lineage from commits. A mutable wiki was rejected because it would
not travel with an anonymous clone.

## Compatibility

This is a repository process decision. Existing ADR-0001 remains available and
is marked superseded. Future tooling may render the index but must not replace
it as the source record.

## Security and privacy

The public log contains no embargoed vulnerability details, credentials, or
personal data beyond public attribution. Security-sensitive decisions use a
private advisory until coordinated disclosure.

## Consequences

Each changed decision requires a new file and reciprocal links. That costs
some maintenance but gives reviewers explicit status and history.

## Validation

`make verify-governance` checks IDs, statuses, required sections, digests,
decision metadata, reciprocal lineage, and orphan files. Mutation tests change
a final byte and break a lineage link to prove both checks fail.

## Supersession

This ADR supersedes ADR-0001. The ADR-0001 file remains unchanged; its index
entry points to this record.
