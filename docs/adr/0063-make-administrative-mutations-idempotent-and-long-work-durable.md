# Make administrative mutations idempotent and long work durable

Every Release 1 administrative mutation accepts an Administrative Idempotency Key bound to Principal, operation type, and canonical request digest; identical retries resolve the original result, while changed content returns `IDEMPOTENCY_CONFLICT`. Mutable resources require expected Resource Generation preconditions. Backup, restore, purge, key lifecycle, verification, format migration, and upgrade create Durable Operations with stable IDs, persisted `Pending`, `Running`, `Succeeded`, `Failed`, or `Cancelled` state, bounded progress, safe retry guidance, and explicit Irreversible Boundaries. Timeouts make the caller's outcome unknown and are resolved by key or Operation ID rather than being treated as failure. Cancellation never claims to undo a published irreversible stage. Active operation records do not expire, completed lookup retention is disclosed, and every transition commits with governance evidence. CLI and generated SDKs share wait and cancellation behavior, while the operator derives deterministic keys from resource UID, generation, and operation type. This contract does not deduplicate at-least-once telemetry ingestion.

For a Query-export terminal failure before protected output or a signed manifest,
the same Durable Operation retains one bounded typed Query failure outcome. An
exact retry reauthenticates its current caller and request binding before
returning that original outcome, without starting another query or emitting a
new transition. Persisted operation readers retain prior terminal-reason
formats; the typed outcome is specific to Query export and does not create a
general handler-result registry.

For an API-key create or rotation that fails before its Catalog marker, the Catalog Writer retains one encrypted, authenticated transaction-owned prepared record before the immutable transaction digest. It binds the canonical administrative request digest to the exact generated credential verifier, audit entry, object set, commit record, and predecessor. Only the identical request may complete that exact predecessor; changed requests conflict. A missing, unauthenticated, incomplete, or no-longer-current predecessor resolves unavailable without mutation. Completion returns the original principal but never persists, derives, reconstructs, or redisplays the raw secret.

For a verified fresh restore, only the signed snapshot's exact captured Backup
Snapshot operation can receive historical publication evidence. Governance uses
a deterministic successor transaction bound to the authenticated restore origin,
manifest, capture/request binding, restore intent, administrative idempotency key,
and resulting operation revision. The transaction atomically replaces the exact
Kernel task, completes that operation, and appends ordinary governance audit.
An exact retry returns this evidence without another transition; another key or
request conflicts, including after a crash before restore acceptance. A generic
terminal operation cannot authorize this reconciliation.

The historical receipt identifies the authenticated registry head observed at
first reconciliation, rather than inventing original publication statistics.
Retries reauthenticate current membership, retention, purge and revocation rules,
and both the source trust floor and the recorded head's antirollback floor.
An unrelated authenticated registry append preserves the original receipt and
audit. Prior durable-operation and audit formats remain readable; readers that
do not recognize the added historical-evidence tag fail closed. Other active
operations retain their ordinary recovery and admission rules.
