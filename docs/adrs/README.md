# ADR lifecycle

An ADR records one architecturally significant choice, its context, rejected
alternatives, and consequences. Use an RFC when proposing a public protocol,
governance rule, compatibility promise, or cross-cutting contract. An ADR
cannot override a higher authority.

## Start an ADR

1. Copy `TEMPLATE.md` to the next unused `NNNN-short-name.md`.
2. Set the matching `ADR-NNNN`, status `proposed`, and version `0.1.0`.
3. Add complete metadata and SHA-256 to `index.json`.
4. Open a pull request with an owner and non-author reviewer.
5. Run `make verify-governance`.

## Status and decision

Allowed states are `proposed`, `in-review`, `accepted`, `rejected`,
`withdrawn`, and `superseded`. Review follows the quorum and conflict rules in
[GOVERNANCE.md](../../GOVERNANCE.md). Accepted and superseded ADRs include
compatibility, security and privacy, validation, decision, and lineage.

## Immutable history

Final ADR files are not edited. A replacement gets a new ID and names the
prior decision in its immutable `supersedes` header. After accepting the
replacement, update only the old index entry's lifecycle `status` and
`superseded_by`. Preserve its original `record_status`, lineage headers, file,
and SHA-256. `make verify-governance` checks IDs, both status forms, required
sections, decision metadata, digest, reciprocal lineage, and orphan files.

## Appeals

An appeal follows [GOVERNANCE.md](../../GOVERNANCE.md). If the decision
changes, add a superseding ADR. Never erase the original rationale.
