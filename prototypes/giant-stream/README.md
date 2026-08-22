# Giant-stream prototype

Informative, disposable research for `RES-PROTOTYPE-GIANT-STREAM-001`.
`scripts/run_prototypes.py` reads the pinned giant fixture in fixed 64 KiB
blocks, preserves byte count and digest, and records raw samples against the
committed [version 2 plan](../../docs/research/benchmarks/precommit-v2.json).
The active [version 2 result](../../docs/research/benchmarks/v2/giant-stream.json)
contains three externally resource-accounted samples from the shared
[clean-clone rerun](../../docs/research/benchmarks/v2/reproduction.json).
The [version 1 result](../../docs/research/benchmarks/giant-stream.json)
remains queryable only as superseded evidence. This code is not importable as
a production package.
