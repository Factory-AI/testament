# Attack trees

Status: Informative draft

Version: 0.2.0

Deliverable: `RES-STUDY-ATTACK-TREES-001`

Validation: `VAL-READY-010`

Research date: 2026-08-21

The attack trees connect attacker goals to the stable STRIDE and LINDDUN
records. They are not step-by-step exploitation guides.

| Tree | Goal | Example branches | Linked threats |
| --- | --- | --- | --- |
| `TREE-01` | Read another organization's content | spoof tenant; retain pooled context; forge cursor or export; bypass RLS; misuse keys | `STRIDE-001`, `004`, `006`; `LINDDUN-005` |
| `TREE-02` | Make false evidence appear authoritative | alter chunks; rewrite projection; substitute assertion; replay receipt; restore stale backup | `STRIDE-002`, `003`, `007` |
| `TREE-03` | Send content outside the declared boundary | widen profile; redirect or fallback; leak telemetry; grant analyzer network; misuse export | `STRIDE-004`, `006`, `008`; `LINDDUN-005`, `006` |
| `TREE-04` | Make held data unavailable | destroy a key; race hold and deletion; miss lineage; restore without dependencies | `STRIDE-002`, `005`, `006`; `LINDDUN-007` |
| `TREE-05` | Turn hostile content into a trusted action | prompt injection; fake citations; active rendering; direct model enforcement | `STRIDE-007`, `009`; `LINDDUN-002` |
| `TREE-06` | Infer activity without content access | compare tokens; time errors; observe provider calls; correlate sizes and timestamps | `LINDDUN-001`, `002`, `004` |
| `TREE-07` | Publish a trusted-looking malicious or privacy-leaking release | substitute build input; publish secret or deployment path | `STRIDE-010`, `LINDDUN-008` |

Each branch is a stable `TREE-..-L..` leaf with its own preconditions, threat,
control, validation, owner, and residual risk. The current trees use OR roots.
Later RFC work may add nested AND nodes if a goal needs a multi-step condition.

The main unresolved paths are host-root compromise, authorized copying,
traffic analysis, current runtime-key compromise, and external provider
behavior. Application controls can reduce those risks but cannot remove them.
