# Coordinate all background work through one bounded maintenance scheduler

Release 1 routes segment rolling, compaction, retention, reclamation, scrub, schema optimization, audit checkpoints, key work, repository work, backups, exports, and lease expiry through one Storage Kernel Maintenance Coordinator. Every Maintenance Task has stable identity, scope, immutable inputs, preconditions, priority, reservations, checkpointed progress, and idempotent outcome. An explicit conflict graph prevents overlapping mutations, and output becomes current only through Catalog Transactions. The Resource Governor schedules tasks fairly across tenants, signals, and shards while protecting durability, foreground traffic, eventual maintenance progress, and the Recovery Reserve. Urgent work is event-driven; periodic work uses the Lifecycle Clock with jitter. `ClockUncertain` pauses age-derived destruction but not safe integrity or reclamation work. Maintenance Windows and audited expiring pauses defer only optional classes, never correctness, purge, retention obligations, security deadlines, or emergency work. Tasks resume after restart, orphan unpublished output remains unreachable, the operator requests rather than implements maintenance, CLI and APIs expose actionable status, and release stress tests prove bounded interference and eventual progress.

The server owns one initial no-durable-progress SLO for eligible Running tasks:
60 seconds from the durable Running transition or a later durably committed
checkpoint that increases `completed_inputs`. Checkpoint sequence changes,
opaque cursor rewrites, and failed or ambiguous Catalog publication do not
reset it. Terminal, queued, paused, window-deferred, conflict-blocked, and
capacity-refused tasks are not running stalls. A restart recovers a prior
Running task as queued and establishes a fresh deadline only on its next
durable admission. `ClockUncertain`, a missing legacy timestamp, or a
non-monotonic server instant produces an unknown deadline fact, never a
fabricated healthy result. This deadline is distinct from the existing
60-second lower-class queued-work priority escalation.
