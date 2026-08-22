# Offline-replay prototype

Informative, disposable research for `RES-PROTOTYPE-OFFLINE-REPLAY-001`.
PostgreSQL records two identical pinned replay digests, then appends a
superseding digest after a late event. Prior runs remain queryable. Larger
fairness and crash-recovery tests remain later work. The active
[version 2 result](../../docs/research/benchmarks/v2/offline-replay.json)
contains three container-cgroup-accounted samples from the shared
[clean-clone rerun](../../docs/research/benchmarks/v2/reproduction.json).
The [version 1 result](../../docs/research/benchmarks/offline-replay.json)
remains queryable only as superseded evidence.
