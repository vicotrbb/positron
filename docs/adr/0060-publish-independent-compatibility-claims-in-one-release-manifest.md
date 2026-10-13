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
