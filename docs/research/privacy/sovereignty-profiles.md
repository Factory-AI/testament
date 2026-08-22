# Sovereignty profiles

Status: Informative draft

Version: 0.2.0

Deliverable: `RES-STUDY-SOVEREIGNTY-001`

Validation: `VAL-READY-010`

Research date: 2026-08-21

Setup must select exactly one profile. There is no external-inference default
and no silent provider or model fallback.

| Profile | Content boundary | External destination |
| --- | --- | --- |
| `isolated-sovereign` | trace content stays in the inventoried deployment | no external inference; selected cloud KMS is a critical-keying-material boundary |
| `boundary-sovereign` | content may reach an organization-controlled endpoint inside a declared boundary | pinned organization endpoint |
| `metadata-redacted-external` | only enumerated transformed fields may leave | pinned external provider |
| `cloud-assisted` | explicitly authorized plaintext parts may leave | pinned provider, model, endpoint, region, and account |

Each profile record enumerates allowed and prohibited data, destinations,
controls, signed attestation fields, provider behavior, and limits. Moving to
a broader profile is a new attributable attestation. Queued and retried work
must be reauthorized against the current profile.

An attestation records what the organization declared and what Testament
observed at its interface. It cannot prove hidden provider storage, support
access, subprocessors, legal compulsion, or internal model behavior. A region
setting is not proof that every control plane and support path stays in that
region. A redacted payload can still identify someone. `store=false` or a
zero-retention arrangement does not make remote processing local.

Cloud KMS needs a precise exception. AWS and GCP Encrypt receive a plaintext
organization root and return ciphertext. Their Decrypt operations return the
root. Azure `wrapKey` and `unwrapKey` do the equivalent with a versioned RSA
key. Those exchanges happen inside the selected provider API over TLS. They
are critical-keying-material egress, not trace-content egress. A deployment
that requires no key material to cross an external provider must use an
approved local custody design.

The machine contract does not hide this behind a generic SDK call. It has
separate AWS, GCP, and Azure method, path, header, request, response, binding,
size, and failure rules. Unknown provider fields, headers, query parameters,
redirects, algorithms, or versions are denied.

The model also separates three analyzer trust tiers. Trusted built-ins run in
a role process with inventoried capabilities. Extensions run in WASM or a
subprocess behind bounded handles and get no ambient capability. External
analyzers receive only profile-authorized fields through the egress broker.
Each tier has stable capability, profile, provenance, control, and validation
IDs.

The exact fields and validation expectations are in
[`policy/threat-privacy-sovereignty.json`](../../../policy/threat-privacy-sovereignty.json).
