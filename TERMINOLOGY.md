# Testament terminology

Status: Active
Version: 1.0.0
Last updated: 2026-08-21

These terms keep observations, inferences, decisions, and actions distinct.

## Core records

**Source bytes**
The exact octets accepted at an ingest authority boundary. They are immutable
and authoritative. Parsing never replaces them.

**Evidence**
An immutable observation or imported source record. Evidence is not a finding
or policy decision.

**Artifact**
Exact or derived content, or a governed reference to content, with identity,
integrity, availability, and provenance metadata.

**Projection**
A versioned derived representation of source evidence. A projection identifies
its source, transformation, and lossiness and never rewrites source bytes or an
older projection.

**Actor**
A human, service, agent, model, provider, or delegated principal represented in
the evidence graph.

**Action**
A represented operation, such as a model call, tool use, retrieval, memory
access, publication, or network egress.

**Link**
A typed relationship between graph records. Links may represent causality,
ordering, retries, delegation, replacement, evaluation, or enforcement without
forcing the graph into a tree.

## Analysis and policy

**Analyzer**
A versioned component that evaluates an authorized, immutable evidence scope
and returns untrusted structured assertions. An analyzer does not make policy.

**Finding**
An analyzer assertion with cited evidence, uncertainty, provenance, and status.
A finding is not an observation, policy decision, or proof of enforcement.

**Human annotation**
An attributed, append-only review, disposition, suppression, or appeal record.

**Policy decision**
A deterministic evaluation result produced from a pinned policy and evidence
scope. It remains distinct from what an external system later does.

**Enforcement receipt**
A signed, short-lived proof binding a policy decision to a tenant, action,
resource, context, policy revision, expiry, and nonce. A receipt is not proof
that the protected system acted on it.

**Enforcement event**
An independently attributed record of the action actually taken by a protected
system.

**Degraded decision**
A result used when a safety check is unavailable or indeterminate while the
required trust and durability systems remain healthy. Under the approved
availability model, the action proceeds and an explicit degraded audit record
is written. The result is not labeled safe, passed, or approved.

## Trust and compatibility

**Sovereignty profile**
An organization's explicit declaration of where analysis may run and which
content classes may cross a trust boundary. There is no implicit external
inference profile.

**Adapter**
A versioned interpretation of an external transport, schema, provider, or
framework format. Adapter output is derived and must state unknown-field
retention and lossiness.

**Normative**
Material that defines requirements and can feed conformance when designated by
the applicable manifest.

**Informative**
Research, rationale, examples, and prototypes that may explain or test ideas
but cannot silently change requirements or certification.

**Conformance**
Evidence that a named implementation and version passed a specified,
versioned, scoped test profile. It is not a general security or safety claim.
