---
name: analyzers
description: Implement bounded analyzers through the universal analyzer contract.
version: 1.0.0
---

# Analyzers

## Scope

Use for deterministic, statistical, classifier, local-model, external-model,
ensemble, sequence, and longitudinal analyzer behavior.

## Entry points

Locate the analyzer manifest/request/result contract, add a failing
provenance, budget, or hostile-output case, then run focused tests and
`make test-gate`.

## Recovery

Preserve the failed run as a terminal status, correct the pinned input or
implementation, and create a new run. Use `make doctor` for environment faults.

## Boundaries

Analyzer output is an untrusted assertion. No ambient capability, cross-tenant
state, hidden reasoning retention, silent fallback, or undeclared egress.
