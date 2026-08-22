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
review. The [clean-clone reproduction report](benchmarks/reproduction.json)
contains all 27 rerun samples and comparisons. Neither file is a normative
conformance input.

All results bind the canonical precommit plan at
`cfdf43bb49f3802137dc0ae887314ab7a8a01f58`. Five early local result files
contained the non-resolving transcription
`cfdf43b1d85024ad5475f5c2afe41978f9fc2a01`. Their reconciliation metadata
records that identifier and a digest of the preserved raw samples; no sample
was rewritten.

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
