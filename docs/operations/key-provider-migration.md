# Migrate root key providers

Migration rewraps the existing SYSTEM KEK under an independently verified
destination. Existing tenant keys and encrypted frames retain their identity
and bytes. Provider key locators and versions must identify immutable keys;
aliases cannot establish migration authority.

Keep a protected canonical configuration for the current active provider and
another for the destination. The documents must differ only in
`security.provider_access`. Omit that table for a local destination. Keep the
original local key path as the bootstrap anchor even after migrating away from
it; a local successor is provisioned by the existing local rotation owner.
Provider access is a closed typed table in the generated configuration schema.
Credential values are never configuration fields or command-line options.
Protected credential files must satisfy the native adapter's file policy.
Azure managed identity accepts exactly one optional `client_id`, `object_id`, or
`resource_id`; omitting all three selects system-assigned identity. Transit
protected-token authentication uses `token_file` without an authentication
`mount`. JWT and Kubernetes authentication additionally select their role,
protected JWT file, and native authentication mount.

The running instance owns the workflow. Use an authenticated System
Administration credential on the administrative HTTP listener. Supply it on
standard input through `--credential-stdin`; use the listener's TLS server name
and trust file. `--allow-plaintext` is explicit opt-in for a plaintext listener.
The configuration reference is an absolute protected path on the server, read
through the canonical configuration owner. It never transfers credentials in
operation parameters.

```console
positron keys migrate status --endpoint localhost:4319 --credential-stdin --server-name positron.local --trust-file trust.pem
positron keys migrate prepare --endpoint localhost:4319 --credential-stdin --server-name positron.local --trust-file trust.pem --target-config /protected/target.toml --expected-generation 42 --idempotency-key 11111111-1111-4111-8111-111111111111
```

Each mutating phase (`prepare`, `activate`, `cancel`, `resume`, `verify`, `retire`)
accepts an Administrative Idempotency Key and the current Catalog generation.
Prepare, activate, verify, and retire also require `--target-config`. Inspect
status for the current generation before submitting a new phase. An identical
retry returns the original stable Operation ID; changed parameters conflict.
The accepted operation atomically retains its bounded configuration reference
and semantic digest, while the root Catalog journal remains phase authority.
The existing persisted Maintenance coordinator owns execution and recovery.
Ingestion remains available across preparation and cutover. Activation commits
the destination as the route for new keys and invalidates provider caches.

Use `lookup --idempotency-key UUID`, `status --operation-id ID`, or
`wait --operation-id ID --wait-seconds N` with the same connection and
credential flags to resolve the outcome. Wait is bounded to at most 60 seconds.
A timeout or transport failure leaves the caller's outcome unknown; inspect
that operation before resubmitting. Temporary admission backpressure is an
explicit unavailable response. `cancel-operation --operation-id ID
--expected-generation N --idempotency-key UUID` requests durable operation
cancellation. The separate `cancel` and `resume` phases suspend and resume the
root migration journal. Cancellation preserves the last committed route and
never rolls back an activated destination.

Restart reconstructs an accepted operation's missing task and resumes the
same task/operation association. The exact accepted configuration digest must
still match. Root phase execution rechecks the original requesting principal's
current System Administration grant; root audit records retain that principal
and Operation ID. Start a restarted server with the canonical access
configuration for the committed active provider. A differing immutable URI or
version is refused, and configuration alone cannot perform migration.

Verification and retirement use independent target recovery and the existing
managed reference owners. Retained recovery artifacts, snapshot and export
leases, ledger and maintenance references, or unproved repository inspection
block retirement. A pruned signed audit history also blocks native retirement:
its retained suffix cannot prove that older unverified recovery artifacts are
absent. A local destination additionally requires the existing
verified Age recovery workflow. Do not delete retained artifacts merely to make
retirement succeed. The current repository owner has no persisted repository
bindings; migration does not claim backup repository or overlay support beyond
that authenticated schema fact.

Retirement performs a bounded Catalog transaction to reclaim completed
maintenance descriptors before checking the unchanged reference guards. Only
reference-free descriptors, canonical digest-only scrubs, released lease descriptors
whose exact lease object is absent, successful Retention Publications with their
typed frontier, typed terminal root-migration associations, and dedicated completed Retention Reclamations with an exact
retired continuity binding and absent segment/frontier files are eligible.
Continuity metadata is retained. Expiring a digest-only scrub descriptor does
not assert that a historical scrub succeeded. Opaque inputs, outputs, or
checkpoints remain managed references even after generic task completion. It
does not discard live work, retained artifacts, or leases. If publication is
ambiguous, its existing maintenance owner retains the reclamation fences until
the exact Catalog transaction is reconciled; retrying the operation completes
the same removal once.

Successful external retirement removes Positron's old envelope and route. It
does not disable or delete the provider's key. Local predecessor files are
removed only by the guarded local retirement owner. Keep externally retained
recovery material according to its own lifecycle. Native fixtures establish
adapter and recovery behavior; they do not establish live-provider compatibility
or FIPS validation.
