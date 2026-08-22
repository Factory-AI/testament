# Milestone 1 research registry

Status: Active

Version: 1.0.0

Milestone: `research-foundation`

The [research manifest](../../policy/research-manifest.json) is the public,
machine-readable index for every Milestone 1 study, corpus, prototype,
benchmark, RFC, review, and decision. Each entry has a stable ID, owner,
dependencies, acceptance criteria, version, source commit, artifact path,
public evidence, reviewer, decision, state, and supersession links.

For in-review, accepted, or superseded work, `commit` is the immutable commit
containing the reviewable artifact. For draft work, it is the last source
commit on which the plan depends.

The only allowed states are `draft`, `in-review`, `accepted`, `blocked`, and
`superseded`. Draft work may point to its planned artifact path, but accepted
and superseded work must resolve to a public artifact. Accepted work also
needs a completed dated review and an accountable decision.

## Deliverable catalog

The manifest currently registers 50 stable deliverables:

- 12 studies;
- 1 synthetic corpus;
- 9 disposable prototypes;
- 9 reproducible benchmarks;
- 12 protocol RFCs;
- 3 independent reviews; and
- 4 decisions.

The naming study and naming decision are accepted. The trace-format,
abuse/misuse, STRIDE, LINDDUN, attack-tree, data-inventory, sovereignty,
no-content-egress, retention/deletion, and key-custody studies are in review.
The [analyzer evaluation plan](analysis/evaluation-plan.md) is also in review,
with its complete family matrix in
[`policy/analyzer-evaluation.json`](../../policy/analyzer-evaluation.json).
The [synthetic trace research corpus](corpus/README.md) is complete as an
informative corpus and awaits independent security, privacy, and licensing
review. The nine prototype and benchmark pairs are complete informative
evidence and await independent review. The remaining deliverables are drafts.
Each deliverable gets its own artifact rather than sharing one file with an
incompatible deliverable.

Current studies:

- [Trace-format landscape](studies/trace-landscape.md), with its
  [machine-readable ecosystem matrix](../../policy/trace-landscape.json);
- [Abuse and misuse research](studies/abuse-misuse.md), with its
  [machine-readable harm matrix](../../policy/abuse-misuse-research.json); and
- [STRIDE threat model](threats/stride.md);
- [LINDDUN privacy model](threats/linddun.md);
- [Attack trees](threats/attack-trees.md);
- [Privacy data inventory and trust boundaries](privacy/data-inventory.md);
- [Sovereignty profiles](privacy/sovereignty-profiles.md);
- [No-content-egress contract](privacy/no-content-egress.md);
- [Retention, deletion, and legal holds](privacy/retention-deletion.md);
- [Key custody model](security/key-custody.md), all backed by the
  [machine-readable threat, privacy, and sovereignty matrix](../../policy/threat-privacy-sovereignty.json);
- [Analyzer evaluation plan](analysis/evaluation-plan.md), backed by the
  [family-to-fixture, metric, and threshold matrix](../../policy/analyzer-evaluation.json);
  and
- [Naming clearance](naming-clearance.md).

Use the JSON manifest when exact IDs or lifecycle data matter. This page is the
stable public evidence link for planned entries until their own artifact is
published.

## Prototype evidence

The [prototype claim ledger](../../policy/prototype-claims.json) links exactly
nine informative claims to their disposable prototype, precommitted plan,
benchmark result, observation, inference, uncertainty, limitation, and pending
review. The active
[version 2 clean-clone reproduction report](benchmarks/v2/reproduction.json)
contains all 27 rerun samples and comparisons from one committed successor
candidate. The preserved
[version 1 reproduction report](benchmarks/reproduction.json) remains
queryable only as superseded evidence. Neither file is a normative conformance
input.

All results bind the canonical precommit plan at
`cfdf43bb49f3802137dc0ae887314ab7a8a01f58`. Five early local result files
contained the non-resolving transcription
`cfdf43b1d85024ad5475f5c2afe41978f9fc2a01`. Their reconciliation metadata
records that identifier and a digest of the preserved raw samples; no sample
was rewritten.

The [version 2 successor plan](benchmarks/precommit-v2.json), committed at
`0f3dce5b9418a50eb031ec3fd561282462533bd3`, explicitly supersedes the
canonical version 1 plan for active measurements. It precommits the F-001
workload accounting, F-002 independent key-rotation capture, and F-003
backend-disconnect fault methods. It does not replace or rewrite the version 1
plan, results, or reproduction report. All sample counts, elapsed budgets,
tolerances, and the 536,870,912-byte RSS budgets remain unchanged.

All nine active result files are under
[`benchmarks/v2/`](benchmarks/v2/) and bind tested implementation commit
`297e14b14a41582d914c33cda8ea61f1b92bca29`. Exactly three samples per
prototype passed without changing a precommitted budget or tolerance. Every
result preserves the matching version 1 path and SHA-256 as superseded
evidence.

Version 2 local samples run in fresh worker process groups. An observer outside
the worker recursively sums resident bytes for the worker and descendants, so
Go and analyzer subprocesses are included and the long-lived coordinator is
not. PostgreSQL samples start, healthcheck, and stop the `postgres` service for
each sample through the supplied mission `services.yaml`; Docker container
statistics measure that container's cgroup during the worker run. Missing,
parent-only, non-isolated, or internally inconsistent accounting fails closed.

## Claims and standards authority

The [claims-evidence ledger](../../policy/claims-ledger.json) gives each
architecture-shaping and release-blocking claim a stable trace to its source
pointer, dated/versioned evidence, contradiction, uncertainty, limitation,
owner, reviewer, status, and supersession record. All 21 current claims remain
`in-review`; pending review does not support a public pass claim.

The [standards status page](../standards-status.md) renders authority, version,
source, and supersession labels. Its
[normative source inventory](../../policy/normative-sources.json) is the only
allowlist for conformance inputs. Research, rationale, examples, prototypes,
and unpromoted fixtures remain informative. The twelve proposed RFC contracts
may drive draft checks, but none is certification-eligible and no research
fixture is promoted.

To repeat the measurement in a fresh clone, check out the report's
`source_commit`, run `make setup`, start PostgreSQL with `make dev`, confirm
`docker compose exec -T postgres pg_isready -p 5440`, then run:

```sh
python3 scripts/run_prototypes.py \
  --root . \
  --plan-commit cfdf43bb49f3802137dc0ae887314ab7a8a01f58 \
  --postgres \
  --output-dir /tmp/testament-prototype-results \
  --report /tmp/testament-prototype-reproduction.json \
  --clean-clone
make dev-stop
make verify-prototypes
```

The comparison deliberately requires the same plan fields, sample counts, and
acceptance outcome. It does not require elapsed time, randomized cryptographic
bytes, or process RSS to be byte-identical across runs. Any plan widening
invalidates all bound results. A future tolerance change must include an
attributable approval plus digest-bound prior-baseline and new-rerun artifacts
in `tolerance_history`; otherwise verification fails.

The version 2 runner requires an explicit output directory and refuses every
version 1 result path. For PostgreSQL cases it also requires the governing
mission lifecycle manifest:

```sh
python3 scripts/run_prototypes.py \
  --root . \
  --plan-commit 0f3dce5b9418a50eb031ec3fd561282462533bd3 \
  --postgres \
  --services-manifest <mission-services.yaml> \
  --output-dir /tmp/testament-prototype-v2-results \
  --report /tmp/testament-prototype-v2-results/reproduction.json \
  --clean-clone
```

The runner performs the PostgreSQL start, healthcheck, cgroup observation, and
stop sequence once per sample. Do not start PostgreSQL separately for a
version 2 run.

The [version 2 key-rotation result](benchmarks/v2/key-rotation.json) contains
three resource-bounded samples from the shared clean-clone candidate. Each
sample records two distinct
reads of separately persisted payload ciphertext, before rewrap and after the
new wrapped DEK and checkpoint, plus capture identities, methods, ordinals,
digests, byte counts, wrapped-DEK digests, generations, and checkpoint.
Acceptance is recomputed from those fields. The
[version 1 result](benchmarks/key-rotation.json) remains byte-for-byte
preserved and is retained only as superseded evidence.

The [version 2 decision-durability result](benchmarks/v2/decision-durability.json)
contains three resource-bounded PostgreSQL 17 samples from the shared
clean-clone candidate. In every sample,
a uniquely named fault session emitted an in-transaction readiness marker and
blocked without explicit rollback. A separate control connection matched and
terminated that exact backend. The client lost its connection and exited
nonzero. A fresh verification connection observed backend disappearance, one
committed decision/audit/receipt triplet, zero faulted rows, zero orphans, and
automatic rollback.

This evidence demonstrates backend-disconnect rollback only. Process death,
host crash, storage loss, WAL corruption, and fsync faults remain unproven.
The [version 1 result](benchmarks/decision-durability.json) remains
byte-for-byte preserved and is retained only as superseded evidence.

## Verification

```sh
make verify-research
```

The verifier emits machine-readable sections for:

- schema validation inputs;
- one-to-one coverage against all 50 required IDs;
- resolved repository references and declared HTTPS source links (the local
  verifier checks syntax, not remote network availability); and
- lifecycle state and supersession counts.

It also validates exact trace-ecosystem and abuse-domain coverage. Every trace
row needs transport, projection, unknown-field, and lossiness findings. Every
harm row needs online, nearline, and offline signals, an authorized-use twin,
false-positive factors, reviewer and appeal paths, limitations, and open
questions. Threat and privacy validation requires complete STRIDE and LINDDUN
categories, stable mappings to mitigation, validation, owner, and residual
risk, all four sovereignty profiles, and explicit data, boundary, egress,
lifecycle, hold, and key-custody sections.

`make verify-analyzer-evaluation` validates the analyzer evaluation plan. It
rejects a missing family, dataset, fixture mapping, metric, threshold, source,
required evaluation dimension, or lifecycle agreement.

The same command verifies the executable analyzer data partitions and the
harmless prompt-injection fixtures. The
[injection manifest](analysis/injection-manifest.json) binds seeds 1401 through
1420 to generated bytes, source fixtures, byte counts, SHA-256 digests, inert
expectations, and prohibited outcomes. The
[split manifest](analysis/split-manifest.json) records each case and group,
family applicability, required partitions, and the exact SHA-256 bucket
algorithm. Injection cases are holdout-only, and the paired authorized-use
twins share one group assignment. This is a candidate input to the separately
versioned successor analyzer plan. It does not rewrite the immutable version
1.0.0 plan in place.

Run `make generate-analyzer-evaluation` to reproduce these files. Verification
rejects a missing or duplicate case, changed digest, unknown fixture, group
leakage, empty family partition, injection leakage, or algorithm drift.

The version 2.0.0 [analyzer evaluation successor](analysis/evaluation-plan.md)
supersedes candidate
`e5391c64f3e504cab4cda22a2d2155422a82af0d`, which remains preserved and
ineligible for freeze. Every family now binds the exact split, injection,
registry, evaluator, and golden-vector versions and digests, plus positive
unit-bearing wall-time, CPU, peak-RSS, output, attempt, and family-specific
resource budgets. The
[deterministic injection evidence](analysis/injection-control-evidence.json)
records twenty of twenty successful holdout attempts, zero prohibited
outcomes, and no external inference. The
[candidate evidence](analysis/evaluation-candidate-evidence.json) binds the
successor artifact commit and all input digests.

The [analyzer metric registry](../../policy/analyzer-metric-registry.json)
gives every family metric an executable formula, sample rule, aggregation
rule, rounding rule, and fail-closed undefined result. Its versioned
[golden vectors](analysis/metric-golden-vectors.json) cover every metric plus
micro and macro aggregation, repeats, zero denominators, percentiles,
abstention, calibration bins, cost overruns, and each prohibited injection
outcome. Run `make generate-analyzer-metrics` to reproduce the registry and
vectors.

`make verify-claims` validates `VAL-READY-016` and `VAL-READY-017`. It checks
schema and digest integrity, exact architecture and release reverse coverage,
claim source pointers, evidence accessibility, contradiction and review
metadata, normative RFC inventory agreement, conformance section allowlisting,
fixture promotion, and rendered authority labels.

`make verify-prototypes` validates exact nine-pair coverage, canonical
precommit and tested-commit resolution, preserved historical observations,
claim links, research-manifest agreement, clean-clone rerun comparisons,
reviewed tolerance history, and the informative disposable boundary.

`make verify-corpus` separately verifies `VAL-READY-012` and
`VAL-READY-013`, including required class and provider coverage, exact byte
digests, deterministic regeneration, synchronized byte/provenance/expectation
versioning, fixture inventory, size bounds, licenses, and secret/privacy
patterns.

It rejects missing or duplicate IDs, unknown states, private-only evidence,
orphaned research files, missing accepted artifacts, accepted items without
review and approval, broken supersession, and two deliverables sharing one
artifact.
