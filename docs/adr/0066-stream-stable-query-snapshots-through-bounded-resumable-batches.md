# Stream stable Query Snapshots through bounded resumable batches

Release 1 query responses contain a typed header, deterministic Result Batches, and one mandatory terminal status. Cursor pagination requires a total order and uses opaque authenticated Query Cursors bound to Tenant ID, plan and parameters, API version, Query Snapshot, cumulative Query Budget, last key, Snapshot Lease, and expiry rather than numeric offsets. Bounded persistent Snapshot Leases pin required immutable objects under tenant quota and survive restart without delaying Tenant Purge. Budgets accumulate across pages and reconnects. Each batch has a deterministic sequence and digest; ambiguous reconnect may repeat the last batch with the same identity, allowing CLI and Generated SDK helpers to deduplicate without gaps. Resume never switches snapshots, and expiry, authorization change, quarantine, or reclamation is explicit. `Complete` appears only after all work and batches finish, with a terminal Result Digest over the logical output. Large exports use the same contract as a bounded Durable Operation with a signed manifest. If a protected terminal artifact reaches stable storage before its descriptor update, Kernel may promote it only after authenticating the corresponding cursorless final payload, or for an empty export after proving that the descriptor contains no payload or batches. This recovery preserves the original snapshot, lease, budget, and receipts and never re-executes the query; malformed, mismatched, or truncated artifacts fail closed. Release tests cover interruption, restart, rotation, tampering, lifecycle races, integrity failure, authorization change, and cumulative limits.

The generated Rust SDK and canonical `LogQueryService/Session` expose bounded
historical pages, authenticated resume, and native Tail polls. `Cancel` uses the
original authenticated cursor to release its leases without re-executing or
advancing the query. These additions retain the native Query owner and current
principal, tenant, authorization-generation, and expiry checks.

Each Tail HTTP poll returns a header, at most one unacknowledged batch, and the
native explicit incomplete terminal. A delivery cursor retains the ambiguous
batch boundary. Only a subsequent caller-supplied sequence/digest receipt may
acknowledge that batch. The SDK tracks one receipt and fixed digest state,
discards verified repeats, and rejects changed contents, sequence gaps, schema
changes, and terminal-statistic contradictions without advancing client state.
Tail terminal counters describe acknowledged logical progress. Transport loss
is explicitly ambiguous and never triggers an automatic retry.

Session and Tail budgets use the existing 3,600-second hard Snapshot Lease
ceiling. The baseline finite Execute transport retains its five-second ceiling.
Every connection, response, cursor, page, and poll remains bounded separately.
Capability negotiation runs before added operations and is uncached, so peer
identity or version changes cannot retain stale feature authorization.

Explicit cursor cancellation uses one native release attempt. Session cleanup
retains its existing RAII behavior. Native queued cleanup, partial paired
release, and uncertain publication or installation preserve the original error
cause with Ambiguous completion and Never retry at the public boundary. Definite
pre-effect refusals remain Rejected; callers reconcile the original cursor.
