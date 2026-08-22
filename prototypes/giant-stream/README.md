# Giant-stream prototype

Informative, disposable research for `RES-PROTOTYPE-GIANT-STREAM-001`.
`scripts/run_prototypes.py` reads the pinned giant fixture in fixed 64 KiB
blocks, preserves byte count and digest, and records raw samples against
[`precommit.json`](../../docs/research/benchmarks/precommit.json). This code is
not importable as a production package.
