---
name: release
description: Prepare and verify releases only after all research and release gates pass.
version: 1.0.0
---

# Release

## Scope

Use for release artifacts, checksums, SBOM, signatures, provenance, rollout,
health verification, and exact rollback after explicit authorization.

## Entry points

Run the five root gates, the applicable conformance gate, then `make release`.
In the research milestone this emits an intentional structured block.

## Recovery

Use `make rollback` only for an existing declared release. Follow the
structured blocker and never create an ad hoc tag, archive, or deployment.

## Boundaries

No push, tag, publication, deployment, promotion, signing, or remote mutation
is implied by this skill. A valid research seal and explicit authority are required.
