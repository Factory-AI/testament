# Contributing to Testament

Status: Active
Version: 1.0.0
Last updated: 2026-08-21

Start with an issue that states the problem, scope, non-goals, affected
contracts, acceptance criteria, and validation. Keep a pull request small
enough to review. Security reports follow [SECURITY.md](SECURITY.md), not the
public contribution path.

## Legal sign-off

Testament uses Developer Certificate of Origin 1.1 sign-off, not a separate
contributor license agreement. Every commit must contain:

```text
Signed-off-by: Your Name <your-email@example.com>
```

Create it with `git commit -s`. By signing, you certify the DCO 1.1 terms at
<https://developercertificate.org/>. In particular, you certify that you have
the right to submit the contribution under the indicated open source license
and understand that the public contribution record is retained.

Before review, inspect the submitted range with:

```sh
git log --format='%H%n%(trailers:key=Signed-off-by)' origin/main..HEAD
```

Every commit hash must be followed by its sign-off. The current local
governance gate validates this instruction, not the commit range. Required
remote DCO enforcement belongs to the later repository-workflow feature, so a
reviewer must check the range until that control is active.

Do not sign for another person. If an agent helped, a human contributor remains
accountable for the submission and DCO sign-off. Record material agent
authorship with an accurate `Co-authored-by` trailer when applicable. Do not
invent a human author or signer.

## Branch and commit rules

Fork the repository or create a branch from current `main`. Use a descriptive
name such as `docs/rfc-capture-limits` or `fix/index-lineage`. Do not push
directly to `main`, force-push shared review branches without coordination, or
mix unrelated cleanup into the change.

Rebase or merge current `main` before final review. Preserve unrelated local
work. Commits should explain one coherent change and include DCO sign-off.

## Tests and validation

Run the narrowest check while working. Before requesting review, run these
commands in order:

```sh
make lint
make typecheck
make test-gate
make build
make agent-ready
```

Add a test or machine check before fixing a behavior. A documentation contract
needs mutation coverage for missing fields, invalid status, broken lineage, or
other failure it claims to prevent. Do not weaken an invariant, budget, or
expected result to make a test pass.

## Documentation

Update public explanations with the contract they describe. State status,
version, owner, compatibility effect, limitations, evidence, and
supersession where applicable. Use primary sources for external factual
claims, with publisher, title, publication or version date, URL, access date,
and the exact claim supported.

Do not put private context, local absolute paths, secrets, customer data, or
unsupported safety and conformance claims in public material.

## Generated files

Do not edit a generated file directly. Change its designated source and run
the documented generator. Commit the source, generated output, and drift
evidence together. If no generator or source is documented, stop and ask in
the issue rather than guessing.

RFC and ADR indexes are machine-readable records, not hand-waved tables.
Follow their lifecycle guides and run `make verify-governance` after any
record or index change.

## Review

A pull request must link its issue, describe scope and non-goals, list contract
and compatibility effects, show tests and manual observations, identify
security or privacy impact, and note generated files and documentation.

At least one eligible non-author maintainer reviews a routine change. The
bounded single-maintainer bootstrap exception in
[GOVERNANCE.md](GOVERNANCE.md) applies only while its stated conditions hold
and is not independent review. Governance, normative standards, releases, and
security changes also follow the role, quorum, conflict, and appeal rules.
Authors resolve comments with code, evidence, or a recorded disagreement. Only
a maintainer closes review and merges.

## RFCs and ADRs

Use an [RFC](docs/rfcs/README.md) for a public contract, governance rule,
compatibility promise, or cross-cutting design proposal. Use an
[ADR](docs/adrs/README.md) to record an architecturally significant choice
within accepted authority. An ADR cannot silently override an RFC, charter,
architecture invariant, or validation contract.
