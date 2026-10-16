# Make tenant purge cryptographically complete within managed scope

A Tenant Purge first transitions the tenant to `PURGING`, blocks new ingest, query, and tail operations, cancels or drains existing work, rolls active segments, removes live manifests, and evicts cached keys. It then removes every Tenant KEK envelope from the live Envelope Catalog and every registered Backup Repository's Repository Key Registry, writing a signed Purge Tombstone that restore must apply before exposing tenants. Completion requires proof that no reachable managed envelope can recover the Tenant KEK, after which remaining key material is destroyed and residual ciphertext is cryptographically unrecoverable. If a registered repository is unavailable, immutable, or retains a reachable historical envelope version, the purge remains pending. Governance audit retains only the tenant identifier, authorization and scope, timestamps, transitions, and completion proof. Positron explicitly cannot revoke unregistered, exported, or offline copies outside its managed scope.

A signed repository Purge Tombstone identifies the repository, tenant identity
and slug, authorized purge operation, and acceptance time. Its presence is an
irreversible restoration exclusion, including while managed envelope deletion is
still pending. It is not proof that key destruction has completed. Restore
preserves `PURGED` when already proved, otherwise records `PURGING`, omits the
excluded tenant's keys and live signal/policy reachability, and reserves its
identity and slug against later recreation. Every original source object is
still authenticated before excluded objects are omitted from the target.

Missing repository keys or references are tolerated only for the exact tenant
identity authorized by a current authenticated tombstone. The complete identity
set from the authenticated source Catalog must still match the manifest's
original signed key-context digest. Neither an absent envelope nor a reduced
inventory is itself purge authority. Restore reports distinguish recovered key
counts from excluded tenants and make no new key-destruction claim.
