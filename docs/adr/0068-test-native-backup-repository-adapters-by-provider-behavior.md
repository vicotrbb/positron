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

## AWS S3 adapter and additive formats

The AWS S3 implementation uses the same provider-behavior Repository interface,
with native SDK `1.152.0` / service API `2006-03-01` and the standard native
credential chain. SDK types remain private to Backup. Exact region, regional
HTTPS endpoint, bucket, expected owner and owned prefix bind the native Identity.
The Kernel owns native transport, DNS and credential-process resources through
the existing Maintenance reservation; ownership is retained across retries and
terminal publication without a second reservation.

Local `POSREP01` Identity and `POSRHD01` head bytes remain unchanged. AWS Identity
uses `POSS3I01`, epoch 1 and the same bounded 108-byte frame. Native upload
recovery `POSS3U01` binds target commitment, object checksum/size, committed
prefix checksum, staging selector, closed creation state and an attempt nonce;
its bounded frame includes encrypted staging bytes and a whole-frame checksum.
Requested native creation without exact owned evidence remains uncertain, even
when the advisory upload listing is empty. It never authorizes a second Create.

Existing `POSOPR04` records retain their local request encoding. Native
Repository provider kind 2 carries a bounded canonical five-field locator and
no credentials. `POSRPL01` is an optional bounded checked terminal policy tail;
optional `POSROP01` records only the Doctor probe's object retention, legal hold
and event hold. No-probe local policy bytes and legacy records remain identical.
Older readers reject unknown provider kinds or trailing extensions instead of
silently discarding them. Parameters retain their original intent digest and
policy is a terminal observation, not another authoritative operation journal.

Observed, unavailable and unobservable controls remain distinct. GetObject's
protection headers describe the same content response used for full-checksum
inspection; absent headers cannot prove no retention. Doctor's owned probe
observation is explicitly scoped and does not qualify hidden external retention
or tenant cryptographic purge. Canonical HTTP/protobuf projection and CLI expose
the checked terminal observations through existing authenticated Administration.

The native dependency graph pins only the required SDK/config/Smithy features,
uses Rustls/Ring certificate verification and retains the existing acyclic
Kernel -> Domain and Backup -> Kernel/Domain ownership. SSO and native credential
process support preserve the accepted standard-chain policy. Response bodies,
native parts, pages, cursors and resource admission remain bounded. Real AWS
qualification requires explicit designated target authorization; see
[the operational scope](../operations/aws-s3-repository.md). Local and pure SDK
boundary evidence does not qualify AWS behavior.
