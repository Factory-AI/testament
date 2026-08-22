# Retention, deletion, and legal holds

Status: Informative draft

Version: 0.2.0

Deliverable: `RES-STUDY-RETENTION-DELETION-001`

Validation: `VAL-READY-010`

Research date: 2026-08-21

Retention is organization-scoped and versioned. Preview and apply use the same
fixed clock, rule revision, lineage snapshot, hold snapshot, and candidate
digest. A stale preview conflicts instead of silently selecting a new set.
Every rule must name its clock origin, duration or event, timezone, purpose,
precedence, owner, approval, and version. There is no universal hidden
retention default.

The model tracks source; projections; findings and cases; jobs and caches;
exports; blind indexes; credentials and key material; audit and tombstones;
and backups, replicas, and external providers. These components have separate
completion states.

Deletion first denies active reads and new governed work. It then runs as one
resumable operation. Each phase records counts and residual state. "No longer
readable in the active system," "cryptographically erased," "provider deletion
requested," and "physically removed from every backup" are different claims.

## Legal holds

A hold has an organization, actor, authority, reason, scope expression,
resolved snapshot, effective time, version, history, and release authority.
It blocks scheduler expiry, manual deletion, key destruction, cryptographic
erasure, and decommission for its whole resolved lineage. Holds overlap.
Releasing one cannot bypass another.

Changing labels, reprojection, export, backup, or key generation cannot move
data out of hold scope. Hold checks run at preview, at the deny-read point,
during each destructive phase, before key destruction, during decommission,
and on restore.

Checks alone are not enough. Each organization has a monotonic hold epoch.
Hold changes and destructive operations serialize against it. A destructive
operation pins the epoch and resolved lineage under a serializable transaction
or equivalent fence, then reacquires the fence before an irreversible provider
or key action. A changed epoch aborts the action. Active prospective holds are
evaluated before new or relabeled records become deletable, so matching
descendants join the hold. Uncertain external actions remain `unknown` and
block completion until reconciled.

## Restore

An older backup does not become authoritative by itself. Before reads, restore
must compare it with a separately protected signed recovery authority, replay
current tombstones, verify current hold state, and check required key
generations. Missing, stale, forked, backup-derived, or wrong-organization
authority keeps the affected organization unreadable and readiness false.

NIST SP 800-88 informs sanitization and cryptographic-erasure caution. GDPR
articles on storage limitation and qualified erasure motivate lifecycle
questions where they apply. This model is not legal advice.
