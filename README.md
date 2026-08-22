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

## Start here

- [Project charter](CHARTER.md): purpose, scope, non-goals, authority, and
  milestone boundaries.
- [Terminology](TERMINOLOGY.md): the terms used by project contracts.
- [Claims and limitations](docs/claims-policy.md): what public project
  statements may and may not say.
- [Licensing](docs/licensing.md): Apache-2.0 policy and artifact inventory.
- [Machine-readable artifact inventory](policy/artifact-licensing.json)
- [Machine-readable claims policy](policy/claims.json)

## Verify this foundation

```sh
make test-gate
```

The command validates the Apache-2.0 text, checks that all artifact classes are
accounted for, rejects prohibited core dependency licenses, confirms required
limitations are public, and scans for forbidden overclaims.

## License

Testament is licensed under the [Apache License 2.0](LICENSE). Third-party
materials retain their own compatible terms and required notices.
