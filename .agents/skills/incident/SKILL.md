---
name: incident
description: Preserve evidence and follow bounded incident response entry points.
version: 1.0.0
---

# Incident

## Scope

Use for declared security, integrity, availability, sovereignty, or release
incidents and exercises.

## Entry points

Run `make incident`, capture its machine status, identify the affected
contract, and follow the published security escalation path when applicable.

## Recovery

Preserve logs and evidence without content or secrets, stop only owned
services, run `make doctor`, and verify recovery before closing an incident.

## Boundaries

Do not destroy evidence, rotate or revoke credentials, contact external
parties, change cloud resources, or publish incident details without authority.
