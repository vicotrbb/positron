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

Stop the serving owner before using the exclusive-owner CLI. Preserve access to
both immutable roots throughout overlap. Start with status and prepare:

```console
positron keys migrate status --config source.toml
positron keys migrate prepare --config source.toml --target-config target.toml
positron keys migrate activate --config source.toml --target-config target.toml
positron keys migrate status --config target.toml
```

Preparation admits resources and verifies custody before recording a prepared
route. Activation commits the destination as the route for new object keys.
Restart the server using the canonical destination access configuration after
cutover. A configuration URI or version that differs from the authenticated
active route is refused; configuration cannot perform a migration.

Cancellation preserves both routes. After cutover it preserves the committed
destination for new writes. Use the configuration of the committed active route:

```console
positron keys migrate cancel --config target.toml
positron keys migrate resume --config target.toml
positron keys migrate verify --config target.toml
positron keys migrate retire --config target.toml
```

Before cutover, use the source configuration for cancel and resume. Retrying a
prepared operation requires the same immutable destination. After interruption,
inspect authenticated status before continuing; failed publication may require
reconfirmation of the committed route. Status reports exact nonsecret source,
active, and target identities, epochs, and phase, including historical source
identity after retirement.

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
typed frontier, and dedicated completed Retention Reclamations with an exact
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
