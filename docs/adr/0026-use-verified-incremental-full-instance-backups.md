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

The signed `POSBSV02` verification checkpoint binds completed native-file
checksum checks to the exact authenticated inventory and its file order. A cold
resume restarts any partial file and revalidates the inventory before using the
completed-file count. `POSBSV01` checkpoints remain readable and restart that
native checksum pass. This operation checkpoint version does not change the
Backup Format Epoch or snapshot format. Native Catalog and audit verification
still authenticates every required file and reconstructs its semantic state.
When a bounded offline turn ends without changing the durable operation or its
verification checkpoint, it safely requeues the owner and reports retryable
capacity unavailability; it does not present volatile work as durable progress.
If a recovered lifecycle clock has not yet reached an authenticated operation
timestamp, the same offline owner waits for genuine trusted elapsed time within
the caller's original deadline. Expiry reports retryable capacity unavailability
without changing the operation; a cold retry does not substitute wall time or
advance the authenticated timestamp.

Fresh restore holds the target Primary Data Volume lock while proving that both
roots contain no instance artifacts. The lock file alone is permitted. A retry
must authenticate the existing restore origin and the exact physical roots,
effective configuration digest, source manifest, recovery input and idempotency
key before opening a writable Catalog. An initialized or unrelated nonempty
target is refused without adopting it. The target retains the recovered instance
identity and gets a new Catalog identity bound to the verified source and restore
intent; it does not impersonate a historical source transaction.

The encrypted restore-origin descriptor records the verified source Catalog and
audit frontier as an authenticated prefix boundary. Original audit records retain
their identities and timestamps. Normal successor transactions, audit retention,
root rewrap and read-only recovery continue from that boundary. The descriptor
contains bounded provenance rather than a second permanent audit store. Native
root adoption records a new target transaction with the actual recovered route;
it does not fabricate a source migration or predecessor retirement.

The accepted restore Durable Operation owns staged data before copying begins.
Transfer and integrity verification use bounded resumable steps. Cold restart
revalidates source ciphertext and native integrity before publication. Current
signed tombstones are checked again at publication; a changed exclusion plan
fails the accepted operation and leaves the target offline. Cancellation is
revision-bound and is allowed before publication. The irreversible boundary is
the target Catalog transaction that records the signed Restore Report and
`Succeeded`. Root custody and the bootstrap gate are then synchronized. If that
final synchronization is interrupted, normal startup remains blocked and an
exact retry reconciles publication forward from the authenticated receipt.
