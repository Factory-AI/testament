# Testament project charter

Status: Active
Version: 1.0.0
Last updated: 2026-08-21

## Purpose

Testament is an open, organization-controlled evidence, analysis, and policy
plane for authorized LLM and agent traces. It is intended to let organizations
retain exact trace evidence in infrastructure they control, analyze that
evidence online and over time, and make local policy decisions without making a
model provider the custodian of the source record.

## Scope

The project covers:

- exact-byte capture of authorized traces and arbitrary input;
- provenance-preserving evidence and derived projections;
- application-layer encryption before content reaches durable storage;
- multi-organization isolation, including the single-organization profile;
- versioned analyzer contracts for deterministic, statistical, local-model,
  external-model, sequence, ensemble, and longitudinal methods;
- deterministic policy decisions, verifiable enforcement contracts, and
  explicit degraded audit records;
- public API, CLI, operational console, conformance tools, and standards
  documentation.

OpenTelemetry, OTLP, OpenInference, provider formats, framework events, and
observability exports are supported through adapters. They do not replace the
raw source as authority.

## Non-goals

Testament is not:

- a model provider, model gateway, or general observability vendor;
- a managed SaaS control plane or a custodian of deployment data;
- a SIEM, ticketing system, or full case-management product;
- a source of automatic policy enforcement without a cooperating enforcement
  point;
- a guarantee that abuse, misuse, or policy violations will be detected;
- a system for native Droid integration;
- a v1 system for cross-organization content correlation, searchable encrypted
  full text, model training, or multi-region active-active operation.

## Authority and change control

This charter and accepted project architecture define project direction. Once
established, accepted, current, non-superseded RFCs and ADRs define normative
technical decisions within that direction. Maintainers approve those records
through the public governance process and may not use examples, research notes,
prototypes, or analyzer output to silently create normative requirements.

The raw-source authority, tenant isolation, pre-storage encryption,
sovereignty, bounded-resource, and honest degraded-decision invariants may not
be weakened merely to make an implementation or test pass.

Detailed maintainer roles, voting, appeals, security response, contribution,
RFC, and ADR procedures are separate lifecycle deliverables. Until those
documents are accepted, this charter grants no undocumented release or
standards authority.

## Milestone boundaries

1. **Research and standards foundation.** Charter, governance, research,
   threats, protocols, synthetic corpus, prototypes, reviews, claims evidence,
   repository controls, formal Level 5 readiness, and a signed research seal.
2. **Secure evidence foundation.** The smallest production-grade custody,
   encryption, isolation, API, CLI, KMS, retention, and audit paths.
3. **Trace standard and adapters.** Source-neutral evidence contracts, raw
   parsers, semantic adapters, fixtures, fuzzing, and offline conformance.
4. **Analysis engine.** Versioned analyzer execution, local and approved
   external inference, longitudinal analysis, evaluations, and reviews.
5. **Policy and enforcement.** Typed policies, signed decisions and receipts,
   integration hooks, degraded semantics, and bypass testing.
6. **Product and public release.** Complete console and standards site,
   deployment and release artifacts, operations evidence, and final readiness.

Milestones 2 through 6 may not add production implementation until the
immutable research candidate, evidence manifest, formal Level 5 readiness
report, and external research seal satisfy the public validation contract.

## Project commitments

Testament will keep normative specifications separate from informative
research, preserve exact source bytes and historical projections, require an
explicit analyzer-sovereignty choice, and publish evidence for compatibility,
security, conformance, and performance claims. Unknown or malformed input may
be retained safely without claiming semantic understanding.

See the [claims policy](docs/claims-policy.md) for mandatory limitations.
