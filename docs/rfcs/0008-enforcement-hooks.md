# RFC-0008: Enforcement hooks

ID: RFC-0008
Status: proposed
Version: 0.1.0
Decision date: None
Supersedes: None
Superseded by: None
Owners: @enoreyes
Reviewers: Independent interoperability and security reviewer pending

Normative status: Draft

## Summary

This normative draft defines typed decision hook points, exact pre/post effect
boundaries, required context, advisory versus enforceable evidence, and
failure reporting.

## Motivation

A named hook is not enforceable unless every protected path reaches it before
the effect and the resource server verifies and applies the result.

## Scope and non-goals

This RFC owns hook vocabulary and interception evidence. RFC-0009 owns
decisions and RFC-0010 owns receipts. This RFC does not claim transparent
network interception or automatic integration coverage.

## Proposed contract

### Normative contract

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

1. Standard hooks are `input_acceptance`, `model_request`,
   `model_response`, `tool_request`, `tool_result`, `retrieval_read`,
   `memory_read`, `memory_write`, `identity_delegation`,
   `artifact_publication`, `network_egress`, `trace_export`, and
   `administrative_change`.
2. Each protected operation MUST declare hook, phase (`pre_effect` or
   `post_effect`), resource, action, actor, organization, input/evidence
   digest, policy scope, idempotency identity, deadline, and whether the
   integration can prevent the effect.
3. A pre-effect hook MUST complete before the named side effect begins. A
   post-effect hook records an observation and MUST NOT be labeled blocking.
4. Valid hook/effect pairs MUST be enumerated. An unknown hook or mismatched
   effect MUST fail contract validation and MUST NOT silently map to a generic
   hook.
5. `enforceable` requires a protected resource server that obtains and
   verifies a fresh RFC-0010 receipt, prevents replay and alternate paths,
   applies obligations, and reports actual outcome. Otherwise the integration
   MUST be labeled `advisory`.
6. Streaming, batch, retry, background, admin, storage, and internal paths
   MUST appear in the generated coverage inventory. An unannotated protected
   path MUST fail the build or conformance profile.
7. Hook evaluation and actual enforcement MUST have separate graph and audit
   events. Issuance MUST NOT imply that the action happened.
8. An unavailable or indeterminate safety check follows RFC-0009 degraded
   semantics only while tenant resolution, core durability, audit, and
   receipt signing are healthy. Core failure MUST NOT issue a valid receipt.
9. A normal deterministic policy denial remains denial. Integrations MUST NOT
   reinterpret denial as degraded unavailability.
10. Actual outcomes include `applied`, `not_applied`, `partially_applied`,
    `failed`, and `unknown`, with actor, time, resource, receipt, and bounded
    reason.

### Informative rationale

Pre/post phase is part of the hook identity because a later observation cannot
retroactively prevent a tool call or export. Coverage inventories turn broad
claims into enumerable integration evidence.

## Compatibility and migration

Adding a new hook is minor only for consumers that reject or preserve unknown
namespaced hooks without changing behavior. Reinterpreting phase, effect, or
enforceability is major. Existing integration evidence remains historical.

## Security and privacy

Hook context can contain sensitive identifiers and digests. It must be
minimal, organization-scoped, authenticated, and non-enumerating. Alternate
routes, TOCTOU, replay, spoofed context, and misleading labels are primary
threats.

## Alternatives

One generic `request` hook was rejected because it cannot bind effects.
Treating every decision API call as enforcement was rejected because the
resource server may ignore or bypass it.

## Validation

Machine checks generate route-to-hook coverage, reject invalid pairs, exercise
alternate and background paths, and compare issued decisions with actual
outcomes. Manual review traces one advisory and one enforceable integration.

## Open issues

- `RFC-0008-OI-01`: Finalize the mandatory path-inventory format for stream
  suboperations.
- `RFC-0008-OI-02`: Define obligation application receipts for partially
  successful multi-effect operations.

## Decision

Pending public review.

## Supersession

None.
