# Key-rotation prototype

Informative, disposable research for `RES-PROTOTYPE-KEY-ROTATION-001`.
The version 2 runner persists payload ciphertext separately from wrapped-DEK
material. It reads the payload from that persisted file immediately before
rewrap, writes the generation 2 wrapped DEK and checkpoint, and then performs a
second file read. Acceptance is recomputed from the two capture identities,
methods, ordinals, byte counts, and SHA-256 digests, the two wrapped-DEK
digests, generations `[1,2]`, and checkpoint `1`.

The active evidence is
[`docs/research/benchmarks/v2/key-rotation.json`](../../docs/research/benchmarks/v2/key-rotation.json).
It is one of the nine results produced from the shared
[clean-clone rerun](../../docs/research/benchmarks/v2/reproduction.json) at
the committed successor implementation.
The immutable version 1 result at
[`docs/research/benchmarks/key-rotation.json`](../../docs/research/benchmarks/key-rotation.json)
is retained only as superseded evidence. Version 2 does not make a cloud KMS
conformance claim.
