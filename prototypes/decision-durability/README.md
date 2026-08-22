# Decision-durability prototype

Informative, disposable research for
`RES-PROTOTYPE-DECISION-DURABILITY-001`. The version 2 harness first commits
one synthetic decision, audit, and receipt. A uniquely named second PostgreSQL
session inserts faulted decision and audit rows, emits a readiness marker from
inside its open transaction, and blocks without issuing `ROLLBACK`.

A separate control connection confirms that exact backend has an active
transaction and then calls `pg_terminate_backend` for its PID. The fault client
must lose its connection and exit nonzero. Only after the backend disappears
does a fresh connection verify one committed triplet, no faulted rows, no
orphans, and automatic rollback.

The active evidence is
[`docs/research/benchmarks/v2/decision-durability.json`](../../docs/research/benchmarks/v2/decision-durability.json).
It is one of the nine results produced from the shared
[clean-clone rerun](../../docs/research/benchmarks/v2/reproduction.json) at
the committed successor implementation.
The immutable version 1 result at
[`docs/research/benchmarks/decision-durability.json`](../../docs/research/benchmarks/decision-durability.json)
is retained only as superseded evidence.

This demonstrates backend-disconnect rollback only. It does not demonstrate
process death, host crash, storage loss, WAL corruption, or fsync faults.
