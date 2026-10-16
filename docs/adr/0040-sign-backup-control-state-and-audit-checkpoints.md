# Sign backup control state and audit checkpoints

Initialization creates an Ed25519 Instance Integrity Key whose private key is wrapped under the system KEK and whose public key and fingerprint are bootstrap metadata. It signs Backup Snapshot manifests, Backup Envelope Overlays, Purge Tombstones, Repository Key Registry generations, and periodic Governance Audit Store checkpoints. Each Registry Generation names its predecessor hash and becomes current through compare-and-swap; restore verifies the complete chain and refuses to publish a non-head or internally inconsistent state. Local Recovery Bundles pin the instance and integrity-key fingerprints, while external-provider recovery binds them through authenticated provider context. Integrity-key rotation cross-signs the successor and preserves public verification history. This detects offline corruption and ordinary rollback against a trusted state but does not claim to prevent restoration of an independently exported old repository copy outside Positron's managed scope.

`POSBKG06` adds bounded signed Purge Tombstone references to the Registry while
retaining older generation readers and predecessor links. Tombstone publication
preserves existing snapshots, reservations, overlays and deletion state. A
fresh-target restore requires an independently supplied integrity public key and
fingerprint before reading recovery metadata; a repository cannot pin itself.
Provider recovery first authenticates a current overlay context, independently
unwraps SYSTEM custody through the configured native provider, then verifies the
complete signed Registry ancestry before accepting the restore operation.

The signed `POSBRR02` Restore Report binds the repository, source snapshot and
manifest, current Registry head, original key context, restore operation and
request, verified target Catalog basis, audit frontier, recovered key count,
excluded tenant identities and complete verification flags. Its bytes and pointer
are committed through the existing Catalog with terminal operation publication.
The report's Catalog basis precedes that native successor transaction; it does
not claim that final bootstrap file synchronization has already completed.
