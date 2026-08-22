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

The naming study and naming decision are accepted. The trace-format and
abuse/misuse studies are in review. The other deliverables are drafts. Each
deliverable gets its own artifact rather than sharing one file with an
incompatible deliverable.

Current studies:

- [Trace-format landscape](studies/trace-landscape.md), with its
  [machine-readable ecosystem matrix](../../policy/trace-landscape.json);
- [Abuse and misuse research](studies/abuse-misuse.md), with its
  [machine-readable harm matrix](../../policy/abuse-misuse-research.json); and
- [Naming clearance](naming-clearance.md).

Use the JSON manifest when exact IDs or lifecycle data matter. This page is the
stable public evidence link for planned entries until their own artifact is
published.

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
questions.

It rejects missing or duplicate IDs, unknown states, private-only evidence,
orphaned research files, missing accepted artifacts, accepted items without
review and approval, broken supersession, and two deliverables sharing one
artifact.
