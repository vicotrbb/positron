# Rotate and migrate keys through multiple envelopes

Every KEK has immutable Key Epochs and may temporarily retain multiple valid Key Envelopes. Root-key rotation and migration between Key Providers are one online, resumable rewrap workflow; Tenant KEK rotation activates a new epoch for new segment DEKs and first rolls active segments. A copy-on-write Envelope Catalog adds envelopes for existing DEKs without rewriting immutable encrypted frames, and old and new envelopes coexist while each idempotent publication advances the migration. Failure preserves the last committed active epoch and restart resumes unfinished work. Rotation cannot complete or authorize old-key retirement until every live object and retained Backup Snapshot has a verified new envelope. Signed append-only Backup Envelope Overlays add new recovery paths without modifying immutable backup data. Progress, verification, completion, and attempted premature retirement are Governance Audit Records.

Root-provider migration rewraps the stable SYSTEM KEK. Tenant KEKs, segment DEKs,
encrypted frames, and the original bootstrap identity remain unchanged. The
authenticated Catalog root journal owns the exact immutable source and target
Provider Key URIs and the prepared, cutover, verification, and retirement phases.
Its version 2 encoding retains the nonsecret source URI after retirement and
records cancellation; version 1 local-rotation journals remain readable. The
bootstrap recovery bridge retains at most two verified root envelopes during
overlap. It supplies bounded recovery locators before decryption; only the
authenticated Catalog can authorize the active route.

Preflight admits source and target resources before provider access, verifies
the destination envelope against the stable SYSTEM KEK, and rechecks the exact
Catalog generation and source admission receipt before publication. Cutover
selects the target for subsequent object-key admission. Cancellation retains
the committed routes and fences further phase transitions; cancellation after
cutover does not restore the predecessor. Resume clears that fence. Uncertain
publication fences data admission until the committed Catalog route is
confirmed; source recovery uses fresh exact-envelope provider verification.

Retirement requires independent target recovery and the existing managed
reference owners' proof: ledger and maintenance references, retained snapshots
and export leases, recovery artifacts, and authenticated repository inspection.
Unavailable or unproved owners block retirement. A created recovery artifact
remains a managed reference even before verification. Its created receipt is
part of the recovery inventory. A signed audit-retention suffix cannot prove
that artifacts recorded in the pruned prefix are absent; retirement requires
the complete initial audit chain unless another canonical recovery owner can
prove their absence. The current repository
schema has no persisted repository bindings; that fact does not authorize any
future repository or replace its eventual reference proof. External retirement
removes only Positron's predecessor route and envelope, never an external key.
Local retirement retains the mandatory independently verified Age recovery
policy. Configuration provides protected provider access under ADR 0055 and
cannot change the authenticated encryption identity by restart.

The maintenance persistence owner may reclaim a bounded set of terminal task
descriptors through a removal-only Catalog transaction before retirement's
reference check. Exact authenticated predecessor records and unreserved task
transitions are required. Durable removal precedes in-memory removal; ambiguous
publication retains the existing owner fences until the exact Catalog receipt
is reconciled. Live work, artifacts, and leases remain subject to the same
retirement guards.

Eligibility requires positively established reference safety: a reference-free
terminal descriptor; a canonical digest-only Integrity Scrub descriptor without
inputs, outputs, or checkpoints; an exact Snapshot Lease Expiry descriptor whose
lease object is absent; a successful Retention Publication with its validated
typed frontier; or a dedicated completed Retention Reclamation whose canonical
input bindings leave exactly one authenticated retired continuity marker and
whose segment and frontier files are absent in both active and sealed storage.
The latter relies on the existing atomic reclamation completion owner for the
other removed input metadata bindings. The continuity marker remains intact.
Digest-only descriptor expiration does not prove historical scrub success.
Generic success, cancellation, or failure cannot establish that opaque inputs,
outputs, or checkpoints are safe to retire. Unavailable storage fails closed.

The authenticated administrative HTTP projection owns online phase admission;
the CLI uses its canonical descriptor-derived client rather than acquiring an
exclusive stopped-instance lease. Each phase is a principal-bound Durable
Operation under ADR 0063 with an expected Catalog generation, stable Operation
ID, and exact request-conflict semantics. Its existing operation record stores
bounded protected server-local configuration provenance and a semantic digest,
never plaintext credentials. The root Catalog journal remains the sole phase
authority. Restart attaches the same persisted Migration maintenance task,
including reconciliation of the operation-acceptance/task-publication gap.
Current authorization is rechecked for these root operations before provider
access, without changing other Durable Operation authorization policies.
Migration audit records bind the actual requesting Principal and Operation ID;
legacy local rotation audit records keep their existing decoding.

A typed reference-free root-migration association may be excluded from the
maintenance checkpoint fence only by the exact running coordinator dispatch.
Its opaque proof binds the Task ID, resource authority, and authenticated Catalog
basis, and the ledger independently checks that proof before inspecting managed
references. Other Migration tasks and stale dispatches remain fences. Terminal
association reclamation removes only the maintenance descriptor, preserving
Durable Operation outcomes and governance audit history.

Completed Governance Audit checkpoint task descriptors may be reclaimed by the
existing Maintenance owner only when their System scope, typed position/hash/
Integrity binding, exact inputs and outputs, and current signed checkpoint
coverage are verified against Catalog. The signed checkpoint artifact and audit
history retain their existing owners; opaque or unproved descriptors still
block retirement. Migration's local recovery preflight preserves admission and
storage failures as unavailable proof, distinct from authenticated absence of
independent recovery.
