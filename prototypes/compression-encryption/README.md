# Compression and encryption prototype

Informative, disposable research for
`RES-PROTOTYPE-COMPRESSION-ENCRYPTION-001`. The Go helper instruments zlib
compression before standard-library AES-256-GCM, verifies exact readback, and
rejects a one-bit mutation. Its deterministic one-shot nonce is deliberately
unsafe for reuse and must not be copied into production. The active
[version 2 result](../../docs/research/benchmarks/v2/compression-encryption.json)
contains three externally resource-accounted samples from the shared
[clean-clone rerun](../../docs/research/benchmarks/v2/reproduction.json).
The [version 1 result](../../docs/research/benchmarks/compression-encryption.json)
remains queryable only as superseded evidence.
