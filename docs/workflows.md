# Repository workflows

Status: Active  
Version: 1.0.0  
Machine registry: [`policy/repository-contracts.json`](../policy/repository-contracts.json)

## Workflow index

| Workflow | Only entry point | Safe rerun or recovery |
|---|---|---|
| Setup | `make setup` | Atomic state write; correct the structured error and rerun |
| Development | `make dev` | Repeated Compose startup converges; use the declared service stop command |
| Validation | `make test-gate` | Correct the first structured failure and rerun |
| Contract and fixture generation | `make generate` | Generation is deterministic and atomic |
| Migration | `make migrate` | Reports not applicable until migration state exists |
| Build | `make build` | Read-only validation of the research foundation |
| Release | `make release` | Intentionally blocked until the research seal exists |
| Rollback | `make rollback` | Intentionally blocked until a release exists |
| Doctor and recovery | `make doctor` | Rechecks setup and returns a machine-readable status |
| Incident response | `make incident` | Reports no runtime incident state in this milestone |
| Readiness | `make agent-ready` | Reconciles all current local readiness contracts |
| Conformance | `make conformance` | Validates only the current research profile |

## Setup

`make setup` compares each bootstrap tool to
[`policy/toolchain.json`](../policy/toolchain.json) and atomically writes ignored
state to `.testament/setup-state.json`. It does not install host-wide packages,
contact a cloud service, or start a listener. Host operators install the exact
declared bootstrap versions; the unprivileged devcontainer provisions those
versions from digest-pinned inputs. Local service lifecycle remains host-owned;
the devcontainer includes the pinned Docker and Compose clients for contract
rendering without mounting a host daemon or starting a nested daemon.

To exercise safe interruption:

```sh
TESTAMENT_SETUP_FAILPOINT=after-version-check make setup
unset TESTAMENT_SETUP_FAILPOINT
make setup
```

The first command exits with a schema-versioned failure and commits no setup
state. The second command recovers without deleting unrelated work.

## Development

`make dev` starts the current declared stack, PostgreSQL 17 only, through
Compose. PostgreSQL binds loopback port `5440`; the container also listens on
`5440`. Repeated startup is idempotent. During managed mission work, run the
exact start, health, and stop commands from the mission `services.yaml`.

The API/console port `4700`, standards-site port `4701`, and integration range
`4710-4799` are reserved. No placeholder process binds them.

## Contracts and generation

[`policy/repository-contracts.json`](../policy/repository-contracts.json) is the
machine registry for architecture, services, commands, schemas, conformance,
and readiness entry points. `make generate` rebuilds
[`generated/contract-index.json`](../generated/contract-index.json) with
content digests. `make verify-readiness` rejects missing links, drift,
unversioned images, port changes, incomplete skills, or a stale generated
index.

## Structured failures

Agent-actionable failures follow
[`schemas/actionable-error.schema.json`](../schemas/actionable-error.schema.json):
`schema_version`, `criterion_id`, `code`, `path`, `message`, and
`remediation_command`. Do not discard the original location or substitute an
ad hoc repair. Run the remediation exactly, then rerun the same entry point.

## Recovery without collateral changes

1. Stop only services named in the lifecycle manifest.
2. Run `make doctor` and preserve its JSON output.
3. Inspect `git status --short`; do not reset, clean, or stash unrelated work.
4. Run the reported remediation command.
5. Rerun the interrupted entry point and its focused test.
6. Confirm the unrelated-file digest or status is unchanged.

Release and rollback remain deliberate structured failures in the research
milestone. Do not bypass them with tags, archives, ad hoc scripts, or remote
actions.
