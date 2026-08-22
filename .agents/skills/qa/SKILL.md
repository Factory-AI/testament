---
name: qa
description: Validate public contracts with deterministic positive and negative evidence.
version: 1.0.0
---

# QA

## Scope

Use for unit, contract, integration, conformance, browser, fault, mutation, and
clean-clone verification.

## Entry points

Run the narrowest focused check first. At handoff run `make lint`,
`make typecheck`, `make test-gate`, `make build`, and `make agent-ready` in
that order.

## Recovery

Record the exact exit, structured failure, and state. Apply only its declared
remediation, rerun the same case, and confirm unrelated file digests persist.

## Boundaries

Do not widen limits, delete state, substitute mocks for required real
boundaries, expose secrets, or parallelize heavy gates.
