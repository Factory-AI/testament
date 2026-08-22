# PostgreSQL storage prototype

Informative, disposable research for `RES-PROTOTYPE-POSTGRES-STORAGE-001`.
The runner creates and drops a temporary schema with PostgreSQL 17 range
partitions and synthetic `bytea` ciphertext. It runs only after the mission
`services.yaml` start and healthcheck commands on port 5440 and before the
matching stop command.
