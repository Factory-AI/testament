# Trace-format landscape

Status: Informative draft

Version: 0.2.0

Deliverable: `RES-STUDY-TRACE-LANDSCAPE-001`

Validation: `VAL-READY-008`

Research date: 2026-08-21

This study separates four things that are often called a "trace": transport
bytes, a parsed provider or protocol object, a framework or telemetry
projection, and a record stored by an observability product. They are not
interchangeable.

The complete, sourced matrix is
[`policy/trace-landscape.json`](../../../policy/trace-landscape.json). Its
[JSON Schema](../../../schemas/trace-landscape.schema.json) and the research
verifier require one row for every ecosystem below, dated sources, structural
samples, conclusions, limitations, and open questions.

## Method

The review used publisher specifications and documentation available on the
research date. Each row records:

1. where transport bytes can be captured and how messages are framed;
2. the semantic model exposed after parsing;
3. documented behavior for fields a parser does not know; and
4. information lost when a transport is projected into that model.

`Not-specified` is a finding. It means the reviewed source gives no retention
promise. It does not mean that an implementation drops or preserves a field.
Claims about exact bytes require capture before parsing, a digest, and
provenance.

## Coverage summary

| Ecosystem | Transport and framing | Semantic projection | Unknown fields | Loss |
| --- | --- | --- | --- | --- |
| OpenAI | HTTPS; streaming Responses use SSE events | Typed response, item, content, and delta events | Not specified for SDK reserialization | Medium: typed objects lose wire encoding and may lose unmodeled members |
| Anthropic | HTTPS SSE with message/content-block events | Message and content-block lifecycle | Unknown event types should be handled gracefully; retention is not promised | Medium: aggregation loses SSE boundaries |
| Gemini | REST/RPC; streaming responses can use SSE | candidates, content parts, usage, citations, safety data | Not specified | Medium: SDK aggregation loses chunks and encoding |
| Bedrock | HTTPS with AWS event-stream envelopes | AWS chunk/exception envelope around model-specific content | Inner model-field retention is not specified | Medium: unifying the envelope can lose AWS and provider detail |
| OpenAI-compatible APIs | Implementation-specific OpenAI-shaped HTTP/SSE subset | Chat/message compatibility adapter | Implementation dependent | High: tools, errors, usage, finish reasons, and extensions vary |
| MCP | JSON-RPC over newline-framed stdio or Streamable HTTP | Methods, tools, resources, prompts, and content | Implementation dependent | Medium: parsing and cross-transport conversion lose encoding and metadata |
| A2A | JSON-RPC, gRPC, and HTTP+JSON bindings | agents, tasks, messages, parts, and artifacts | Implementation dependent | Medium: cross-binding conversion loses binding detail |
| LangGraph | In-process or service stream modes | graph steps, state, messages, tasks, checkpoints | Not specified | High: a chosen stream mode is only one execution view |
| CrewAI | In-process lifecycle event bus | crews, agents, tasks, tools, flows, and LLM events | Not specified | High: events summarize provider exchange |
| AutoGen | Python events and structured logging | messages, model calls, tools, usage, runtime events | Not specified | High: logs do not retain provider wire data |
| Semantic Kernel | OpenTelemetry logs, metrics, and traces | kernel/function and AI-operation telemetry | Exporter dependent | High: content may be suppressed and wire data is absent |
| LlamaIndex | In-process instrumentation events and spans | queries, retrievals, LLMs, agents, tools, workflows | Not specified | High: component events omit provider transport |
| OTLP | Protobuf over gRPC/HTTP or ProtoJSON over HTTP | resources, scopes, traces, metrics, logs, profiles | Runtime dependent; ProtoJSON rejects unknown fields by default | Medium: conversion and collectors can sample, batch, or transform |
| OpenTelemetry GenAI | No separate transport; uses OTel signals | standardized model, agent, and tool operations | Extra attributes can exist, but pipelines may filter them | High: deliberate abstraction and opt-in content |
| OpenInference | OpenTelemetry spans and attributes | LLM, chain, tool, retriever, agent, and guardrail spans | Extra attributes can exist, retention varies | High: semantic spans cannot reconstruct provider bytes |
| Langfuse | SDK/API ingestion | traces, observations, scores, sessions | Metadata is extensible; top-level retention varies | High: backend entities normalize the source |
| MLflow | tracing SDK and tracking storage | trace metadata, span tree, events, assessments | Backend dependent | High: instrumentors choose what to record |
| LangSmith | SDK/API run ingestion | nested runs with input, output, timing, error, tags, metadata | Metadata is extensible; top-level retention varies | High: runs omit network encoding |
| Phoenix | OpenTelemetry/OpenInference ingestion | OpenInference span trees and evaluations | Pipeline and backend dependent | High: inherits instrumentor and OTel projection limits |
| Raw Envoy/NGINX logs | Configured access-log records; bodies absent by default | selected request/response variables | Unconfigured data is dropped | High: access logs usually contain metadata, not application messages |

The matrix cites the current OpenAI, Anthropic, Gemini, Bedrock, MCP, A2A,
OpenTelemetry, OpenInference, framework, platform, Envoy, and NGINX sources
row by row. The OpenAI-compatible row uses Hugging Face Text Generation
Inference as a concrete compatibility implementation. It is not treated as a
universal profile.

## Observations and inferences

Observation: Anthropic asks clients to tolerate new SSE event types. That is a
forward-compatibility instruction. The source does not say an SDK must retain
or re-emit an unknown event.

Inference: Testament needs distinct fields for "accepted by parser," "exposed
to caller," "stored," and "re-emitted." A single `unknown_fields_preserved`
flag would hide real differences.

Observation: OTLP supports protobuf and ProtoJSON. The Protocol Buffers
ProtoJSON guide says unknown fields are not supported and parsers reject them
by default unless configured otherwise.

Inference: Binary and JSON OTLP need separate conformance cases. A successful
round trip in one encoding says nothing about the other.

Observation: framework and platform records add useful run, graph, tool,
retrieval, and evaluation context. Their public data models do not claim to be
transport archives.

Inference: Testament should link these projections to a transport artifact and
record the projection version. It should not overwrite the source artifact
with a normalized span.

Observation: Envoy and NGINX access logs contain configured operators or
variables. They do not contain arbitrary headers, bodies, or SSE frames unless
operators add those surfaces.

Inference: "Raw gateway log" must mean the exact configured log-record bytes,
not a complete request or response.

## Contradictions and uncertainty

- "OpenAI-compatible" products can accept the same common request while
  returning different errors, stream events, usage, tool behavior, and
  extensions. Compatibility must be stated against a tested profile.
- Protocol extensibility and an attribute map permit new data, but collectors,
  SDK types, exporters, and stores may still reject or drop it.
- Content omission is sometimes a fidelity loss and sometimes an intentional
  privacy control. A trace must say which one occurred.
- Documentation cannot establish exact behavior for every SDK and hosted
  release. Versioned fixtures and round-trip tests remain necessary.

## Structural sample plan

No provider payload is copied into this study. The matrix instead describes
harmless sample shapes for later synthetic fixtures:

- a short SSE lifecycle with one text delta;
- a Bedrock event-stream payload envelope;
- MCP stdio and Streamable HTTP JSON-RPC exchanges;
- an A2A task with one update and one harmless artifact;
- equivalent OTLP protobuf and ProtoJSON trace batches with an extension;
- a framework run linked to a separate provider capture; and
- a gateway access record with only synthetic hosts and identifiers.

The fixture corpus owns generated bytes, provenance, licenses, and expected
behavior. This study does not promote those fixtures into conformance.

## Open questions

1. Which maintained provider SDKs expose raw events before typed conversion?
2. Which SDK, protobuf runtime, collector, and backend combinations retain
   unknown fields through parse, storage, and export?
3. What bounded capture point works for encrypted streaming without recording
   credentials or unrelated tenant content?
4. How should a trace show intentional redaction, truncation, sampling, or
   content suppression without implying that data never existed?
5. Which versions and extensions define a useful OpenAI-compatibility test
   profile?

## Limits

This is documentation research, not packet-level conformance testing.
Implementations can change after the recorded date. Hosted settings, sampling,
redaction, and retention can change results without changing an API schema.

The study is informative. It does not define a normative adapter contract, and
it does not establish semantic equivalence between ecosystems.

No system can provide perfect safety. Exact capture can improve auditability,
but it cannot prove that a model output was correct or that a later decision
was justified.
