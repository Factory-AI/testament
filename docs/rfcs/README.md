# RFC lifecycle

RFCs propose governance, normative contracts, compatibility rules, and
cross-cutting designs. An RFC is not accepted merely because a file exists.

## Start an RFC

1. Copy `TEMPLATE.md` to the next unused `NNNN-short-name.md`.
2. Set `ID` to the matching `RFC-NNNN`, `Status` to `proposed`, and `Version`
   to `0.1.0`.
3. Add the file and all metadata to `index.json`, including its SHA-256.
4. Open a pull request and name an owner and non-author reviewer.
5. Run `make verify-governance`.

## Status and review

Allowed states are `proposed`, `in-review`, `accepted`, `rejected`,
`withdrawn`, and `superseded`. The owner may revise a proposed or in-review
RFC in its pull request and must update its version, index metadata, and
digest. Moving to `in-review` starts the public review window defined in
[GOVERNANCE.md](../../GOVERNANCE.md).

The relevant maintainers record votes and either accept, reject, or leave the
RFC in review. Final records include decision date, deciders, reviewers, and
the decision rationale. An accepted RFC is normative only within the authority
of the charter, approved architecture, and validation contract.

## Immutable history

Do not edit an accepted, rejected, or withdrawn RFC file. Clarification that
changes no requirement still needs a new RFC if it changes final text. A
replacement gets a new ID and declares the prior ID in its immutable
`supersedes` header. Keep both files.

After accepting the replacement, change only index metadata for the old
record: set lifecycle `status` to `superseded` and `superseded_by` to the new
ID. Preserve the old file, original `record_status`, original lineage headers,
and SHA-256. The successor's `supersedes` and the old index entry's
`superseded_by` must be reciprocal.

`index.json` is the machine-readable index. It distinguishes the current
lifecycle `status` from immutable `record_status` and `record_supersedes`
headers. `make verify-governance` rejects unknown status, duplicate IDs,
missing metadata, digest drift, broken lineage, and orphaned RFC files.

## Appeals

Appeals follow [GOVERNANCE.md](../../GOVERNANCE.md). An appeal may affirm,
remand, or produce a superseding RFC. It cannot rewrite the appealed record.
