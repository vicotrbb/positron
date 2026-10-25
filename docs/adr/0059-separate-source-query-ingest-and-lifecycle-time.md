# Separate source, query, ingest, and lifecycle time

Release 1 preserves producer Event Time exactly and assigns every accepted record a kernel Ingest Time, while commit position—not timestamp—defines durable ordering. Signal-specific Query Time selects a valid source timestamp, then an observed timestamp where the signal defines one, then Ingest Time, and always exposes its provenance; invalid or contradictory source values remain searchable without producing fabricated durations. Retention and physical lifecycle use Ingest Time only, and extreme producer values use bounded outlier structures. A persisted non-decreasing Lifecycle Clock controls retention, expiry, and destructive schedules. Large unreconciled wall-clock movement enters `ClockUncertain`: ingestion and safe queries may continue from the durable clock anchor, while destructive time-driven actions pause until unambiguous recovery or explicit audited acceptance. Deadlines, budgets, leases, and elapsed durations use monotonic clocks. Integration and fuzz tests cover malformed telemetry time, NTP movement, restart regressions, forward jumps, timezone changes, and daylight-saving transitions.

Bounded offline Backup and Verification turns retain genuine trusted elapsed
time through a Clock-owned Catalog checkpoint before releasing the offline
owner. This checkpoint preserves every non-clock object and refuses an existing
prepared transaction. Its transaction binds the exact predecessor and anchor;
publication cannot replace a newer anchor with an older one or clear
`ClockUncertain`. If acknowledgement is ambiguous, the owner must confirm the
exact transaction and records; unresolved publication requires canonical Catalog
and clock recovery before further mutation. Operation timestamps and wall time
never substitute for a trusted observation.

Successful Drain retains genuine trusted elapsed time in the same final
authenticated Catalog transaction as its Graceful Shutdown Record. Clock
staging rolls back before visibility on interruption; exact confirmed
visibility commits the staged anchor. This does not clear `ClockUncertain`,
add a separate publication, or extend the Drain deadline.
