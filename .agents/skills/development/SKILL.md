---
name: development
description: Make bounded contract-first repository and implementation changes.
version: 1.0.0
---

# Development

## Scope

Use for ordinary source, schema, command, and local-service work after locating
the governing contract and validation IDs.

## Entry points

Run `make setup`, add a failing focused test, implement the smallest change,
run `make generate` when needed, then run `make test-gate`.

## Recovery

Run `make doctor`, follow the emitted remediation, and rerun the interrupted
entry point. Preserve unrelated work and never use reset or clean as repair.

## Boundaries

Do not weaken exact-byte authority, encryption, tenant isolation, resource
bounds, degraded semantics, approved ports, or the research gate.
