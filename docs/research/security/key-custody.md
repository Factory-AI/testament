# Key custody model

Status: Informative draft

Version: 0.2.0

Deliverable: `RES-STUDY-KEY-CUSTODY-001`

Validation: `VAL-READY-010`

Research date: 2026-08-21

Each organization has four purpose-separated roots:

- data wrapping for source and derived content DEKs;
- search tokens for field-scoped equality indexes;
- secrets for provider and service credentials; and
- audit integrity for chains and checkpoints.

Payload DEKs are random and stay in process memory for a bounded time. They
are wrapped under a versioned organization data root. The organization roots
are sealed by the selected cloud key, so KMS is not called per content chunk.
Cloud sealing sends a plaintext organization root through the selected
provider API and receives a wrapped root. Unsealing returns the root through
that API. Trace plaintext and payload DEKs do not cross this boundary.

| Provider | Root operation | Binding | Current evidence |
| --- | --- | --- | --- |
| AWS KMS | symmetric encrypt/decrypt or wrap | canonical ARN and non-secret encryption context | real conformance is required later |
| GCP Cloud KMS | encrypt/decrypt with exact symmetric key version | AAD and CRC verification | contract cases specified; no implementation or real E2E yet |
| Azure Key Vault | RSA-OAEP-256 wrap/unwrap with versioned RSA key | application-verified binding package | contract cases specified; no implementation or real E2E yet |
| Development | ephemeral or explicit local file provider | same logical context | refused in production |

Runtime identities may use only the root operations required by their role.
They cannot create, administer, disable, schedule deletion, or purge cloud
keys. There is no provider fallback.

Rotation affects new writes first. Data-root rewrap changes wrapped DEK
material, not source digests or payload ciphertext. Search-root rotation uses
dual write, reindex, cutover, and retirement. Secret rotation has no readback.
Audit rotation creates a linked signer-generation transition.

Destruction needs current dependency and hold closure, step-up, quorum,
separation of duties, and an attributable operation. Provider states such as
pending, scheduled, disabled, destroyed, purged, unsupported, and unknown stay
distinct.

The inventory also covers receipt, sovereignty-attestation,
recovery-authority, release, TLS, capability-token, identity/session, and Azure
binding-package keys. Each has custody, algorithm policy, storage, cache,
rotation, revocation, recovery, destruction, compromise response, and a
validation matrix. TLS server keys, mTLS client identities, and trust anchors
are separate custody records. The Azure binding authenticator is
purpose-separated from the RSA wrapping key.

Cloud custody does not protect plaintext from an authorized runtime. Memory
zeroization is best effort. Destroying a key can make content unrecoverable,
but it does not remove residual ciphertext or prove that no prior plaintext
copy exists.
