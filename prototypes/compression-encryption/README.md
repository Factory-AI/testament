# Compression and encryption prototype

Informative, disposable research for
`RES-PROTOTYPE-COMPRESSION-ENCRYPTION-001`. The Go helper instruments zlib
compression before standard-library AES-256-GCM, verifies exact readback, and
rejects a one-bit mutation. Its deterministic one-shot nonce is deliberately
unsafe for reuse and must not be copied into production.
