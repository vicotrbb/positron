# Use one process lifecycle for readiness, drain, and shutdown

Release 1 uses `Starting`, `Recovering`, `Serving`, `Draining`, `Fenced`, and `Stopping` Process Phases across native, Docker, systemd, Kubernetes, and operator execution. Only the owner-only Control Listener and minimal Operations Listener are available before configuration, storage ownership, key verification, recovery, catalog validation, and Resource Governor initialization make data listeners ready; neither admits telemetry, ordinary query, or mutating network administration. Invalid configuration exits nonzero; recoverable dependencies remain alive and not-ready with bounded retry, while identity or integrity ambiguity fences. The first termination signal fails readiness, closes admission, finishes admitted durability, drains bounded reads, terminates tails with cursors, seals segments, publishes frontiers and catalogs, checkpoints governance, writes a Graceful Shutdown Record, zeroizes keys, releases ownership, and exits successfully. A second signal or orchestrator kill uses crash recovery and never fabricates graceful completion; acknowledged data remains recoverable. Deployment grace settings must cover the configured drain deadline, `SIGHUP` only reloads configuration transactionally, and every health, status, condition, event, and exit code derives from the same state machine.


Drain completion uses the authenticated final Catalog commit marker defined in
ADR 0069 as its irreversible boundary. Task and listener cleanup, final segment
sealing, frontier publication, the signed governance checkpoint, sole instance
ownership, and reconciliation of earlier Resource Governor reservations precede
that marker. The final transaction uses the existing protected
`DurabilityCompletion` admission after ordinary work closes. Deadline and second
signal checks continue through unpublished writes and immediately before marker
visibility. Interruption before visibility leaves no new Graceful Shutdown
Record. Once the exact final transaction is confirmed visible, Drain has
completed; a later signal cannot retroactively undo it. Only deterministic key
and ownership drops follow confirmed completion. An acknowledgement error is
resolved by bounded inspection of that same transaction and immutable proposal,
without replaying it or initiating another publication after interruption.
Unresolved publication is a typed non-graceful failure and remains subject to
canonical Catalog recovery.
