# Agent guidance

This file applies to the whole Testament repository. A deeper `AGENTS.md`, if
one is later added, may narrow these rules for its subtree but cannot weaken a
root contract, security boundary, or accepted RFC.

## Orient

1. Read [the charter](CHARTER.md), [the repository contracts](policy/repository-contracts.json),
   and [the workflow guide](docs/workflows.md).
2. Read the issue acceptance criteria and identify the governing RFC, schema,
   policy manifest, and validation IDs before editing.
3. Run `make setup`, then `make agent-ready`. Setup starts no service.
4. Select the smallest applicable repository skill under `.agents/skills/`.

The root `Makefile` is the repository command source. The mission service
manifest is the lifecycle source during managed work. Do not invent alternate
commands, ports, credentials, or repair steps.

## Work

- Use red-green-refactor. Add a focused failing test or machine check first.
- Preserve exact source bytes and historical projections. Never repair
  authoritative evidence in place.
- Keep organization context on every tenant-owned operation and record.
- Change a contract source before generated output. Run `make generate`; never
  hand-edit `generated/contract-index.json`.
- Use only harmless synthetic or clearly redistributable fixtures.
- Keep stdout machine-readable when a command promises JSON. Diagnostics go to
  stderr.
- Treat existing changes as someone else's work. Never clean, reset, move, or
  overwrite them.

## Validate and recover

Run focused tests first. Before handoff run, in order:

```sh
make lint
make typecheck
make test-gate
make build
make agent-ready
```

Every intended agent failure must match
[`schemas/actionable-error.schema.json`](schemas/actionable-error.schema.json)
and include a remediation command. Start recovery with `make doctor`; detailed
interruption and rerun procedures are in [docs/workflows.md](docs/workflows.md).

## Boundaries

- Approved listeners are API/console `4700`, standards site `4701`,
  PostgreSQL `5440`, and isolated integration services `4710-4799`.
- Never expose secrets, customer data, production traces, plaintext content,
  data-encryption keys, or provider credentials.
- No cloud resource creation or external inference is implicit.
- Native Droid integration is out of scope.
- Do not push, publish, release, deploy, alter repository controls, or create
  external records unless the assigned work explicitly authorizes that action.
