# Test native Backup Repository adapters by provider behavior

Release 1 implements Rust Repository Adapters for local filesystem, AWS S3,
explicitly supported S3-compatible products, Google Cloud Storage, and Azure
Blob Storage. Each Repository target names the exact service or product and
tested context. Writable providers must support immutable put-if-absent
objects, authoritative metadata, bounded range reads, checksums, resumable
upload, conditional registry-head compare-and-swap, observable deletion, and
bounded retry classification; listing is never a correctness primitive.
Initialization writes an immutable Repository Identity only into an explicitly
empty prefix and attaching existing contents requires exact verification.
Credentials use native identity or protected references, all external
transport requires verified TLS, and Positron encrypts before upload. Provider
versioning, retention, legal hold, and WORM are surfaced because retained key
envelopes keep Tenant Purge pending, while uncoordinated lifecycle deletion is
unsupported. Integration and fuzz tests cover provider failure and recovery
behavior. Repository Adapters remain backup-only and never become Release 1
primary storage.

The local adapter stores immutable Identity as `POSREP01`, format epoch 1,
with exact repository UUID, authorized instance UUID, Integrity fingerprint,
and SHA-256 commitment to the canonical native prefix. This format identifies
the local-filesystem provider; a remote adapter must define its own exact
native target binding before qualification. Immutable objects are checksum
addressed. Opaque head slots use `POSRHD01` with a checked content version;
resumable uploads use `POSUPL01` with exact object, total length, committed
length, and payload checksum. Unknown magic, format, malformed length, or
checksum fails closed. Atomic native publication syncs bytes before rename
and the owning directory before acknowledgement. An uncertain acknowledgement
remains unknown until authoritative inspection reconciles it.

Repository inspection is an additive existing Administration Durable Operation
kind (code 5), dispatched by the persisted Maintenance coordinator as
Repository Verification. Its bounded native locator and exact identity are
private accepted-operation parameters, committed atomically with acceptance.
The existing `POSOPR04` record has a `POSREP02` tail only for this new kind;
legacy kind bytes and decoding are unchanged. Older readers reject the unknown
kind rather than discard its private parameters. The accepted actor, expected
Catalog generation, action, and exact identity bind the stable operation ID
and idempotency semantics. Execution revalidates the creator's current grant.
Status, cancellation, retry guidance, and terminal lookup remain owned by the
existing Durable Operation authority; Maintenance records are scheduling and
resource ownership, not another operation journal.

Local Repository Doctor qualifies provider behavior through this same
interface and an isolated owned probe head, without interpreting backup
registry contents. Signed registry, restore and purge workflows retain their
Backup authority and require their own qualification. Local observable
deletion cannot qualify hidden external retention or permanent media erasure.
