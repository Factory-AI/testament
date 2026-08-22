# Testament

Testament is the open sovereign intelligence trust-and-safety plane.

It is a public project for retaining authorized LLM and agent traces in
organization-controlled infrastructure, analyzing that evidence, and applying
local policy. Exact accepted source bytes remain authoritative. Formats such as
OpenTelemetry, OpenInference, provider events, and framework traces are
adapters rather than the canonical record.

The project is in its research and standards foundation milestone. Production
implementation is blocked until the research exit criteria, independent
reviews, formal readiness report, and external research seal pass.

## Quick start

Install the exact bootstrap versions in
[`policy/toolchain.json`](policy/toolchain.json), then run:

```sh
make setup
make agent-ready
```

Setup verifies pinned tools and starts no service. Use `make dev` only when
PostgreSQL is needed. The complete command and recovery map is in
[docs/workflows.md](docs/workflows.md); unfamiliar agents should also read
[AGENTS.md](AGENTS.md), the [agent guide](docs/agent-guide.md), and the scoped
[repository skills](.agents/skills/).

## Start here

- [Project charter](CHARTER.md): purpose, scope, non-goals, authority, and
  milestone boundaries.
- [Terminology](TERMINOLOGY.md): the terms used by project contracts.
- [Claims and limitations](docs/claims-policy.md): what public project
  statements may and may not say.
- [Licensing](docs/licensing.md): Apache-2.0 policy and artifact inventory.
- [Machine-readable artifact inventory](policy/artifact-licensing.json)
- [Machine-readable claims policy](policy/claims.json)
- [Governance](GOVERNANCE.md): authority, decisions, appeals, amendments, and
  releases.
- [Maintainers](MAINTAINERS.md): current roles and contact paths.
- [Security](SECURITY.md): private reporting, response targets, disclosure,
  safe harbor, and emergencies.
- [Contributing](CONTRIBUTING.md): sign-off, branches, tests, documentation,
  generated files, and review.
- [RFC lifecycle and index](docs/rfcs/README.md)
- [ADR lifecycle and index](docs/adrs/README.md)
- [Governance source record](docs/governance-sources.md)
- [Machine-readable governance lifecycle](policy/governance-lifecycle.json)
- [Naming search and conditional decision](docs/research/naming-clearance.md)
- [Milestone 1 research registry](docs/research/README.md)
- [Machine-readable research manifest](policy/research-manifest.json)
- [Threat, privacy, and sovereignty research](policy/threat-privacy-sovereignty.json)
- [Machine-readable repository contracts](policy/repository-contracts.json)
- [Generated contract index](generated/contract-index.json)
- [Pinned environments and services](policy/toolchain.json)

## Verify this foundation

```sh
make test-gate
```

The command validates the Apache-2.0 text, checks that all artifact classes are
accounted for, rejects prohibited core dependency licenses, confirms required
limitations are public, scans for forbidden overclaims, and validates
governance, security, contribution, RFC, ADR, naming, and research lifecycle
records.

## License

Testament is licensed under the [Apache License 2.0](LICENSE). Third-party
materials retain their own compatible terms and required notices.
