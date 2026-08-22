---
name: readiness
description: Reconcile deterministic repository contracts and honest readiness evidence.
version: 1.0.0
---

# Readiness

## Scope

Use for setup, environment, command, guidance, evidence-matrix, and formal
readiness work owned by the assigned feature.

## Entry points

Run `make setup`, `make verify-readiness`, the five root gates, and finally
`make agent-ready`. Use the formal remote report only when the feature assigns it.

## Recovery

Parse the actionable JSON failure, run its remediation, regenerate with
`make generate` if needed, and reconcile the same criterion again.

## Boundaries

Unsupported, stale, private, local-only, pending, waived, or self-declared
evidence scores zero. Never add native Droid dependencies or fabricate Level 5.
