# Use verified incremental full-instance backups

Release 1 creates online application-consistent full-instance snapshots by rolling active segments, capturing one manifest and Catalog Generation, and copying immutable objects incrementally by checksum through a supported Repository Adapter under ADR-0068. Each repository stores reachable Key Envelopes, Backup Envelope Overlays, and Purge Tombstones in a Repository Key Registry separate from immutable snapshot ciphertext. Backup manifests and repository control records are signed by the Instance Integrity Key, and hash-linked Registry Generations publish through compare-and-swap. Backups include tenants, policies, API-key hashes, manifests, signal data, and governance audit history but exclude external secrets, TLS private keys, Root KEKs, provider credentials, and Recovery Bundles. Verification covers signatures, the complete registry chain and current head, manifest references, checksums, format versions, Catalog Objects, provider references, key fingerprints, and effective purge state. An automatically bootstrapped local key must have a separately stored, verified Recovery Bundle before backup creation is allowed; external providers must pass access and native disaster-recovery readiness checks. Restore targets an empty offline instance, applies Purge Tombstones before exposing tenants, and publishes only after full verification; merge restore, continuous point-in-time recovery, individual-record recovery, and selective-tenant restore are outside Release 1.

Independent verification uses the signed `POSBKM02` manifest capture binding
(original capture operation and request digest) to authenticate the portable
Kernel index without consulting the original capture directory. Native capture
builders emit this version. `POSBKM01` remains readable for existing publication
and inspection, but lacks the binding required for independent native Catalog
verification; that workflow reports an explicit unsupported precondition rather
than inventing or trusting an unauthenticated request. Verification streams
ciphertext, authenticates captured Catalog metadata and audit history, recovers
required envelope identities through Data Protection, and revalidates independent
key-recovery readiness before publishing its immutable signed Verification Report.
The report binds the exact repository, snapshot, manifest, Registry Generation,
Catalog Generation, key context, examined counts, and completion scope. It does
not substitute for fresh-target restore publication and query execution.
