# Claims and limitations policy

Status: Active
Version: 1.0.0
Last updated: 2026-08-21

## Purpose

Public statements about Testament must be no broader than their cited,
reproducible evidence. A passing test supports only the implementation,
version, environment, input class, and behavior that the test covers.
Research observations remain observations. Analyzer findings remain
assertions. Neither becomes a policy or enforcement claim by wording alone.

## Required limitations

These limitations must remain visible in public project documentation:

- No system can provide perfect safety.
- Testament does not claim universal semantic understanding.
- Application-layer encryption is not end-to-end protection against a compromised runtime.
- Testament does not automatically enforce decisions.
- Real GCP Cloud KMS and Azure Key Vault end-to-end conformance is unverified.

Additional limitations apply:

- A compromised host, root user, or authorized Testament process can observe
  plaintext while it is processed.
- PostgreSQL row-level security is defense in depth, not protection from
  arbitrary SQL executed by a compromised privileged runtime.
- Analyzer isolation reduces risk but is not a perfect hostile multi-tenant
  security boundary.
- Hash chains are tamper-evident only relative to a trusted checkpoint and do
  not make storage immutable.
- Decision receipts cannot force a resource server to verify or honor them.
- Provider declarations describe configured behavior; they do not prove hidden
  provider internals.
- Blind indexes reveal bounded equality and frequency information within an
  organization.
- Unknown, malformed, or future formats may have exact custody without a
  successful semantic projection.

## Evidence rules

Architecture-shaping and release-blocking claims must identify:

1. the exact observation and any separate inference;
2. a dated primary source or reproducible result;
3. the tested commit, version, environment, and scope;
4. contradictory evidence, uncertainty, and limitations;
5. an owner, independent reviewer, status, and supersession history.

Pending, inaccessible, expired, unsupported, waived, self-declared, or
local-only evidence does not support a public pass claim. A contract test does
not support a real-cloud interoperability claim. A mock does not support a
production integration claim. A configured policy does not support an
enforcement claim without evidence from the protected resource server.

## Language rules

Use bounded statements such as “passed the named conformance profile on the
identified build” or “retains exact accepted bytes for the listed fixtures.”
State what remains untested.

Do not turn “supports adapters for listed formats” into a claim of understanding
all models or traces. Do not call a degraded decision safe, passed, approved, or
successfully evaluated. Do not describe application-layer encryption as
end-to-end protection against the runtime. Do not describe an issued decision
or receipt as an enforced action without separate enforcement evidence.

The machine-readable [claims policy](../policy/claims.json) supplies mandatory
limitation text and forbidden positive-claim patterns. The
[claims-evidence ledger](../policy/claims-ledger.json) traces every
architecture-shaping and release-blocking claim to its source pointer,
dated/versioned primary or reproducible evidence, contradiction, uncertainty,
limitations, owner, review, status, and supersession. `make
verify-foundation` checks public language and `make verify-claims` checks the
ledger and reverse coverage.
