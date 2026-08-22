# No-content-egress contract

Status: Informative draft

Version: 0.2.0

Deliverable: `RES-STUDY-NO-CONTENT-EGRESS-001`

Validation: `VAL-READY-010`

Research date: 2026-08-21

This contract applies to `isolated-sovereign`.

Source, decoded content, projections, findings, prompts, identities,
credentials, keys, review records, decisions, exports, and lifecycle scope
must not reach an external service destination, except for the explicitly
selected cloud-KMS root-custody exchange described below. The prohibition
includes LLM,
embedding, moderation, classifier, callback, browsing, tool, telemetry, crash
upload, package call-home, support bundle, remote font, CDN, hidden analytics,
auto-fetch, redirect, retry, and fallback paths.

There are five exact egress schemas. `EGRESS-AWS-KMS-01`,
`EGRESS-GCP-KMS-01`, and `EGRESS-AZURE-KMS-01` define the actual method,
service path, query parameters, header allowlist, request fields, conditional
rules, and response fields for each provider. `EGRESS-IDP-01` permits public
issuer metadata and verification keys. `EGRESS-OBS-01` permits bounded
content-excluding health fields only when the monitoring endpoint is inside
the declared boundary.

Each schema sets request and response bytes, calls, destinations, DNS, TLS,
proxy, redirects, retention, field types, cardinalities, sensitivity,
provider-specific limits, and unknown-field handling. Organization roots are
exactly 32 bytes. AWS uses `Encrypt` or `Decrypt` with
`SYMMETRIC_DEFAULT` and exact encryption context. GCP uses `rawEncrypt` or
`rawDecrypt` against one exact CryptoKeyVersion with AAD and CRC checks. Azure
`rawDecrypt` against one exact CryptoKeyVersion with AAD and CRC checks. The
GCP result retains the provider-generated initialization vector and tag length
and sends them back with the ciphertext for raw decryption. Azure uses
versioned `wrapkey` or `unwrapkey` with `RSA-OAEP-256` and a separately
authenticated binding package. Identity responses are capped at 1 MiB and 100
public keys. Observability events are capped at 64 KiB and prohibit free text
and content-derived labels. A user export is not "non-content egress"; it is a
separate governed operation.
An operator client counts as inside the boundary only when the organization
controls the endpoint, path, proxy, DNS, and storage. Delivery to an
uncontrolled client is an export outside this contract.

## Required proof

- Deny outbound network by default at the deployment and analyzer layers.
- Route optional external calls through one broker.
- Classify fields before serialization and reauthorize every attempt.
- Put harmless unique canaries in every protected class.
- Capture DNS, socket, HTTP, telemetry, crash, and provider-mock traffic.
- Exercise redirects, endpoint confusion, callbacks, tools, retries, and
  fallback.
- Revalidate resolved IP, hostname, port, TLS identity, proxy, IPv4/IPv6, and
  link-local policy at connection time and after retries. Redirects are denied.
- Fail validation on any undeclared runtime network path.

External analyzer work that conflicts with this profile is denied. There is no
local or alternate-provider fallback. KMS failure is a custody failure and
fails closed. An unavailable policy safety check follows the separately
approved degraded allow-and-audit behavior only when core durability, tenant
resolution, audit, and signing remain healthy.

This is an application and deployment contract. It does not contain host root,
the kernel, hypervisor, firmware, privileged network administrators,
authorized copying, or a malicious replacement binary.
