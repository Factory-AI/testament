# PostgreSQL storage prototype

Informative, disposable research for `RES-PROTOTYPE-POSTGRES-STORAGE-001`.
The runner creates and drops a temporary schema with PostgreSQL 17 range
partitions and synthetic `bytea` ciphertext. It runs only after the mission
`services.yaml` start and healthcheck commands on port 5440 and before the
matching stop command. The active
[version 2 result](../../docs/research/benchmarks/v2/postgres-storage.json)
contains three container-cgroup-accounted samples from the shared
[clean-clone rerun](../../docs/research/benchmarks/v2/reproduction.json).
The [version 1 result](../../docs/research/benchmarks/postgres-storage.json)
remains queryable only as superseded evidence.
