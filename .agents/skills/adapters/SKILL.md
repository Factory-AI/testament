---
name: adapters
description: Build source-linked trace adapters while preserving exact raw custody.
version: 1.0.0
---

# Adapters

## Scope

Use for provider, framework, OTLP, OpenInference, and generic-format adapters.
Treat every semantic record as a versioned projection from immutable source.

## Entry points

Locate the accepted adapter RFC and fixture manifest, add a failing golden or
lossiness case, then run the focused adapter check and `make conformance`.

## Recovery

Retain malformed or unknown raw bytes, record bounded diagnostics, fix the
adapter source, regenerate through `make generate`, and rerun the exact case.

## Boundaries

Never rewrite raw bytes, fabricate missing semantics, collapse ordering axes,
or let imported data create policy decisions or enforcement events.
