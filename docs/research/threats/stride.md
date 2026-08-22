# STRIDE threat model

Status: Informative draft

Version: 0.2.0

Deliverable: `RES-STUDY-STRIDE-001`

Validation: `VAL-READY-010`

Research date: 2026-08-21

The complete machine-readable model is
[`policy/threat-privacy-sovereignty.json`](../../../policy/threat-privacy-sovereignty.json).
Its schema and verifier require stable threat IDs and complete links to assets,
actors, trust boundaries, preconditions, mitigations, validation, an owner,
residual risk, and disposition.

## Scope and method

The model applies STRIDE to the mission architecture assumptions and named data
flows. Those technical details remain proposed until accepted public RFCs and
ADRs make them normative. The model assumes malicious tenants, stolen
credentials, hostile trace content, fallible administrators, unavailable
dependencies, and a possible runtime compromise. STRIDE is a prompt for
analysis. A category is not proof that a system is vulnerable.

| ID | Category | Threat | Main boundary | Owner |
| --- | --- | --- | --- | --- |
| `STRIDE-001` | Spoofing | Foreign organization or actor identity is accepted | producer, tenant, client | identity and isolation |
| `STRIDE-002` | Tampering | Evidence, ciphertext, manifest, or history is altered | persistence and recovery | storage, audit, recovery |
| `STRIDE-003` | Repudiation | A consequential action lacks attributable durable evidence | client and enforcement | audit and policy |
| `STRIDE-004` | Information disclosure | Plaintext or secrets reach persistence or observability | runtime to persistence | storage and observability |
| `STRIDE-005` | Denial of service | Hostile content or workload exhausts shared resources | ingest and analyzers | ingest, analysis, scheduler |
| `STRIDE-006` | Elevation of privilege | A role, analyzer, or operator gains excessive capability | KMS, analyzer, operator | authorization and extensions |
| `STRIDE-007` | Tampering | Prompt injection changes trusted control flow | analyzer, client, policy | analysis and console security |
| `STRIDE-008` | Information disclosure | External inference exceeds the selected profile | external egress | sovereignty and egress |
| `STRIDE-009` | Repudiation | A degraded allow is labeled as a successful safety result | enforcement | policy and product |
| `STRIDE-010` | Tampering | A supply-chain or release input substitutes malicious code or contracts | source and release | release security |

The JSON record contains stable `CTRL-*` and `VAL-*` mappings for every threat,
plus likelihood, impact, treatment deadline, and risk authority. It also has a
boundary-by-category matrix. Each cell links a threat or gives a specific
reason why the category does not add a distinct scenario in this version.
Important tests include alternating-tenant pools, ciphertext and manifest
mutation, transactional audit faults, canary scans, resource budgets,
capability denial, prompt injection, network-denied egress, supply-chain
verification, and forbidden labels for degraded decisions.

## Limits

Application encryption does not protect plaintext from the process that must
handle it. RLS cannot contain arbitrary SQL from a sufficiently privileged
runtime. Sandboxing reduces extension risk but is not a perfect hostile
multi-tenant boundary. A signed receipt proves a recorded decision, not that a
resource server enforced it.

The taxonomy follows Microsoft's STRIDE material. The control choices also
draw on NIST SP 800-53 and SP 800-207. Exact source records and supported claims
are in the machine-readable research file.
