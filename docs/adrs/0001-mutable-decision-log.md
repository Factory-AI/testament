# ADR-0001: Mutable decision log

ID: ADR-0001
Status: accepted
Version: 1.0.0
Decision date: 2026-08-21
Supersedes: None
Superseded by: None
Owners: @enoreyes
Reviewers: @enoreyes

## Context

The repository needed a compact way to keep architecture decisions during its
foundation stage.

## Decision

Accepted on 2026-08-21 by @enoreyes: keep one current decision file and edit
it when the choice changes. The single-maintainer bootstrap exception applied;
there was no independent reviewer.

## Alternatives

Append-only numbered ADRs were rejected initially as more ceremony than a new
repository needed.

## Compatibility

The mutable file had no wire or runtime effect, but links to older rationale
could become inaccurate after edits.

## Security and privacy

No sensitive content belonged in the log. Editing in place created integrity
and accountability risk because old security reasoning could disappear.

## Consequences

The approach was simple but could not preserve rationale or prove
supersession. That defect caused its immediate replacement.

## Validation

Review compared the approach with the requirement to preserve immutable
history and found it incompatible.

## Supersession

None at publication. A successor must declare this ADR's ID without changing
this file.
