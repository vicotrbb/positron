# Local-key epoch rotation

Local Root KEK rotation preserves the original bootstrap identity, Instance
Integrity Key and stable System KEK. The authenticated Catalog selects the active
root epoch. Owner-only successor custody and its verified System KEK envelope
are published before new writes use the successor. The predecessor remains
available until retirement finishes.

The offline filesystem owner can inspect and advance this lifecycle after
stopping Positron:

```console
positron keys local status --data-dir /srv/positron/data --secrets-dir /srv/positron/secrets
positron keys local prepare --data-dir /srv/positron/data --secrets-dir /srv/positron/secrets
positron keys local activate --data-dir /srv/positron/data --secrets-dir /srv/positron/secrets
```

Preparation preserves the same protected successor on retry. Activation returns
the committed active epoch; a storage failure requires inspecting durable state
before retry. Root custody is `local-root-key.v1` for epoch 1 and
`local-root-key.epoch-N.v1` for successor epoch N. The initialized bootstrap is
immutable. The early System KEK envelope file contains ciphertext and supplies
bootstrap recovery routes; it does not select the active epoch.

Create and independently verify a successor Recovery Bundle using the
[recovery commands](local-key-recovery.md), then retire its managed predecessor
bundle. Root retirement requires that verified recovery state, authenticated
backup configuration and the existing snapshot and maintenance reference
authorities:

```console
positron keys local retire --data-dir /srv/positron/data --secrets-dir /srv/positron/secrets
```

Retirement durably records preparation, validates the exact predecessor through
a held descriptor, unlinks it and synchronizes the secrets directory, then
removes its early bootstrap envelope and records completion. A retry that finds
custody absent still confirms parent-directory durability. Present corrupt,
foreign, symbolic-link or substituted custody refuses removal. A prepared
retirement can resume after restart; an unrelated Catalog transaction cannot
confirm it.

Tenant KEK rotation uses the existing authorized service interface. Preparation
creates one protected successor epoch. Each advancement rolls at most one active
scope; activation follows the final roll. New segments receive fresh DEKs under
the successor, while old immutable frames remain unchanged. Envelope migration
adds one authenticated successor DEK envelope per step. Target-only verification
uses the existing EnvelopeVerification maintenance task and coordinator, with
bounded traversal and durable continuation. Source changes invalidate its proof;
the same authenticated task can be reset for a new source basis.

Tenant retirement requires complete verification against the exact current
source, independent verified recovery and no predecessor references. Live
readers, durable Snapshot Leases, encrypted retained capabilities and opaque
maintenance bindings can prevent retirement. Cancellation or terminal task
status alone does not remove references. Existing bounded terminal reclamation
provides their supported removal path; unknown bindings remain a refusal.

Backup Snapshot creation is not implemented by this workflow. An authenticated
Catalog proving that no backup repository is configured has no managed backup
references. Unknown or configured backup bindings cannot be assumed migrated.
Independent exported copies remain under owner control and are not silently
inventoried or deleted.

`security.key_cache_lease_seconds` controls the existing cache lease, including
zero-duration operation-scoped use. Segment capabilities retain encrypted tenant
envelopes and derive plaintext only through the shared lease authority. Shutdown
completes required cryptographic publication before closing custody, zeroizing
cached provider material and releasing its resource grants. Retained capabilities
refuse derivation after closure.

An integrity fence closes ordinary admission while retained Control continues
protected inspection against current administrator facts. Final Drain performs
the remaining authenticated publication, closes custody and requires complete
resource reconciliation before reporting graceful shutdown.

## Durable encodings

These objects are plaintext inputs to the existing authenticated, encrypted
Catalog owner. They introduce no second crypto backend or independently trusted
epoch registry. Integer fields below are big-endian unless specified otherwise.

| Object | Canonical layout and bound |
| --- | --- |
| Local root lifecycle | `POSLROT1`, 16-byte instance, 16-byte owning transaction, original 56-byte root identity, active route, one-byte successor presence and optional route, one-byte predecessor presence and optional route. A route contains eight-byte epoch, 56-byte root identity, two-byte ciphertext length and 1–1024 bytes of canonical System KEK envelope. An absent tail means ordinary state; exactly one trailing byte `1` means retirement prepared. Other tails refuse. Total maximum: 3424 bytes. |
| Tenant epoch set | `POSTKS01`, one-byte entry count and one-byte active entry count, followed by entries with 16-byte provider reference, eight-byte route epoch, two-byte envelope length and 1–1024 bytes of protected tenant envelope. One to sixteen entries, consecutive immutable epochs, at most one pending successor, total maximum 16384 bytes. Released single-envelope input remains readable. |
| Additive segment envelope | `POSDENV1`, 16-byte instance, 16-byte tenant, one-byte signal, four-byte shard, 16-byte segment, 32-byte immutable header digest, two-byte provider family, 16-byte provider reference, eight-byte epoch, two-byte ciphertext length and 1–256 bytes of wrapped DEK. Fixed prefix: 121 bytes. Duplicate, malformed, substituted or corrupt applicable routes refuse without fallback. |
| Verification checkpoint | `PEVCKP01` binds instance, tenant, target epoch and the authenticated source digest. Its flags select an optional exact scope and bounded existing integrity continuation. Completion is derived by the owning traversal; generic caller checkpoint or completion bytes cannot establish proof. |

The closed root audit stages are `started`, `cutover`, `verified`,
`retirement-prepared`, `retirement-refused` and `completed`. Tenant rotation audit
stages are preparation, bounded roll progress, cutover, bounded migration,
verification, retirement refusal and completion. Verification and preparation
have distinct durable root publications before predecessor unlink. A retry
reuses verification only when its typed audit, exact transaction, authenticated
RootState and complete plaintext object identity set match, and durability
confirmation succeeds. A changed source requires new verification.

An authenticated premature retirement can append a denial audit while preserving
key, task and custody objects. Invalid context, corruption, unavailable resource
admission or missing independent recovery verification refuses before that audit.
