---
name: policy
description: Build deterministic policy and verifiable enforcement contracts.
version: 1.0.0
---

# Policy

## Scope

Use for strict policy parsing, canonical IR, decisions, rollout, receipts,
enforcement evidence, and degraded availability behavior.

## Entry points

Locate the accepted policy and hook RFCs, add a failing negative or replay
case, then run focused policy tests and `make conformance`.

## Recovery

Retain last-known-good policy, correct the rejected source or dependency, and
rerun compilation or evaluation without mutating prior decisions.

## Boundaries

Normal denial denies. Only approved check unavailability with healthy core
trust may allow with a durable degraded audit; never label that result safe.
