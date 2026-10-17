# Publish independent compatibility claims in one release manifest

Every Release 1 artifact is covered by a machine-readable Compatibility Manifest that keeps product, API, query, configuration, receiver, CRD, operator, storage, backup, and migration compatibility as separate tested claims. Product versions follow semantic versioning; patches cannot require persistent migration or break documented behavior. Public API and query `v1` contracts evolve additively with stable error and completion semantics, and older `v1` clients remain supported. A runtime Capability Statement lets new SDKs reject unsupported features before sending semantically invalid requests. Configuration reads the current and immediately previous minor schema and migrates only to a separate reviewed file. Persistent and backup Format Epochs declare exact read, write, and migration support through a published Migration Graph; older binaries refuse newer writable formats, and restore rejects unknown epochs before target mutation. Receiver conformance and operator N/N−1 compatibility remain independently pinned. Log and Trace Store Block claims separately declare v1/v2 readability and v3-only writes for all new blocks, with v3 required for marker-bearing values; this is a format contract to be tested, not evidence that compatibility gates have passed. Integration tests exercise client skew, migrations, restore, upgrade, downgrade refusal, CRD conversion, operator skew, and receiver targets.

Root-provider Durable Operations extend the recognized `POSOPR04` record with
kind code 4 and a bounded `POSKPM01` parameter tail. Existing operation kinds
retain their exact v4 encoding; v1 through v4 legacy records remain readable.
Older readers recognize the outer operation record and reject the unknown kind
or extended length, so they cannot silently omit the new authority. The
migration audit payload uses its own versioned `catalog-root-migration-v1`
encoding; legacy root rotation payloads remain readable. These additive record
formats are independent of public API and provider conformance claims.

The native Upgrade consumer uses the canonical Release Trust verifier in
`positron-kernel::release_manifest`. Its independently installed Project Trust
Root is distinct from the instance Integrity Identity. The signed manifest
binds exact product versions, an explicit source-version allowlist, artifact
hashes and sizes, source commit, independent compatibility claims, configuration
schemas, and persistent and Backup format claims. Source commit text preserves
the actual lowercase Git object name: 40 hexadecimal characters for SHA-1 or
64 for SHA-256. It never pads or rehashes a Git object name.

A single operator-staged candidate and the current installed signed manifest
are configured through `[release.installation]`. Public Upgrade requests select
the candidate manifest digest. They cannot supply a trust root or a server file
path. Manifest authoring, full release inventory generation, and distribution
tooling remain owned by Release Trust issue #113.

The native Backup compatibility owner assigns Backup Format Epoch 1 to the
legacy `POSBKM01` publication/inspection frame, and Epoch 2 to the `POSBKM02`
capture-bound frame required by native independent verification under ADR-0026.
This is an explicit compatibility mapping. The captured Catalog Format Epoch
remains a separate persistent-data field in either frame. The current native
capture writer emits Backup Epoch 2, and Upgrade requires the signed source and
target to support that writer and its independent verification reader. Legacy
Epoch 1 inspection does not establish an Upgrade snapshot verification or native
fresh-target Restore path.
No Backup migration edge is declared by this mapping.
