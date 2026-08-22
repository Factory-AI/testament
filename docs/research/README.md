# Milestone 1 research registry

Status: Active

Version: 1.0.0

Milestone: `research-foundation`

The [research manifest](../../policy/research-manifest.json) is the public,
machine-readable index for every Milestone 1 study, corpus, prototype,
benchmark, RFC, review, and decision. Each entry has a stable ID, owner,
dependencies, acceptance criteria, version, source commit, artifact path,
public evidence, reviewer, decision, state, and supersession links.

For accepted or superseded work, `commit` is the immutable commit containing
the reviewed artifact. For draft work, it is the last source commit on which
the plan depends.

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

The naming study and naming decision are accepted. All later deliverables are
drafts. A draft gets its own artifact rather than sharing one file with an
incompatible deliverable.

Use the JSON manifest when exact IDs or lifecycle data matter. This page is the
stable public evidence link for planned entries until their own artifact is
published.

## Verification

```sh
make verify-research
```

The verifier emits four machine-readable sections:

- schema validation inputs;
- one-to-one coverage against all 50 required IDs;
- resolved repository and public source links; and
- lifecycle state and supersession counts.

It rejects missing or duplicate IDs, unknown states, private-only evidence,
orphaned research files, missing accepted artifacts, accepted items without
review and approval, broken supersession, and two deliverables sharing one
artifact.
