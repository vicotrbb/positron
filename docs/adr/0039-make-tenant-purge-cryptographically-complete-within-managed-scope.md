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

Live Catalog reclamation retains authenticated commit and audit ancestry while
removing the exact encrypted objects that carried the tenant's historical KEK
envelopes, including transaction staging copies. Governance publishes the
permanent identity reservation and key-free current records jointly with an
authenticated descriptor of those object identities and the purge operation's
request digest. Only that descriptor authorizes a historical object's absence;
missing unrelated objects remain integrity failures. Historical reads substitute
an inert exclusion for the exact reclaimed identities, and root rewrapping does
not resurrect their envelopes. Private backup captures and active physical
references fence reclamation. A cold retry reuses the committed descriptor and
idempotently removes and synchronizes remaining files. The resulting live-file
proof is necessary but does not replace verified deletion from every registered
Repository or authorize terminal completion by itself.

Managed live purge uses a global maintenance conflict and tenant-attributed
protected Purge recovery claim because historical Catalog key objects and staging copies share
global capture, scrub, and root-rewrap owners. It waits for those dispatched
owners before reclaiming files and releases the shared scope after completion.
Resource attribution remains distinct from the global physical conflict.
Ordinary backup pressure cannot consume the protected
Purge control-read and deletion capacity.

The live deletion inventory uses complete numbered descriptor parts within the
existing one-object and total Catalog byte limits. Missing parts authorize no
reclamation. Its identity count is bounded by the total Catalog object-byte
budget divided by the 53-byte exact-location record width; existing proposal limits
also account for descriptor headers and other retained objects. A larger valid
inventory is refused with an explicit capacity failure before deletion and
remains pending. It never truncates the inventory or claims key destruction.

Live inventory retains native directory iterators in the installed maintenance
execution, under a transferred tenant Purge admission grant. Each turn examines
at most 64 directory entries and authenticates at most one Catalog object of the
existing maximum object size. Current key removal and permanent exclusion precede
this scan, so later unrelated Catalog publications cannot create new target key
objects. An unpublished inventory is discarded and rescanned in bounded turns
after cold recovery; it grants no deletion authority. Complete descriptor parts
are published atomically before reclamation. Each record identifies the exact
published, root-rewrap, or transaction-staging file, its format epoch, and object
identity. Each reclamation turn removes at most one such file and synchronizes
its directory. A domain-separated authenticated cursor binds the instance,
tenant, purge proof, complete descriptor digest, and next ordinal. The kernel
issues progress only after synchronization; interrupted removal is idempotently
repeated from the prior cursor. A forged ordinal, altered descriptor, or unrelated
missing file cannot authorize completion.


Managed Repository cleanup persists signed ancestry/deletion progress through the
existing Maintenance checkpoint. Each turn processes at most one signed ancestry
record and one tenant key object. Full-version deletion uses the existing native
version inventory and absence proof; a turn shares one 15-second provider deadline
across opening, verification, and deletion, rather than multiplying the deadline
by every historical version. A timeout retains the prior cursor and remains
nonterminal; retry reconciles ambiguous publication and partial deletion before
advancing. Existing Backup captures drain before purge dispatch; permanent
provider fences also exclude delayed remote conditional key uploads.

A newly registered Repository must first prove a clean prefix and install the
permanent exclusions retained in the canonical identity reservation. Admission
accepts an empty prefix or the exact deterministic initial exclusion barrier,
including its own interrupted staging/publication retry. It refuses older or
foreign contents until separately remediated. Native prefix checks use a fixed
page and refuse continuation; admission shares the same 15-second provider
attempt deadline. The Catalog mutation gate covers barrier verification and
registration publication. Repository inventory changes invalidate the ongoing
managed-scope pass, and terminal publication rechecks the exact Catalog generation.

A full-version deletion alone does not fence a previously accepted remote PUT.
Tenant key destruction therefore uses a distinct Repository capability requiring
both historical absence and exclusion of previously admitted writers. Local
storage supports it after Runtime drains capture owners and the directory lock
serializes cleanup. Cloud cleanup first conditionally replaces each exact former
tenant-key object name with a permanent, signed nonsecret purge fence bound to
that object, Repository and permanent tombstone. It then removes historical
secret versions without removing the current fence. Existing conditional-create
requests cannot recreate the key against this occupied name. Verified fence
reads report absence; ordinary deletion refuses the fence. The marker retains
the former object name and carries its own signed authority; it does not claim
to match the original secret object content checksum. A request timeout
is not proof that a remote mutation stopped, and unsupported transports remain
nonterminal.

The provider preconditions are documented in [S3 conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html),
[Cloud Storage request preconditions](https://docs.cloud.google.com/storage/docs/request-preconditions),
and [Azure Blob concurrency](https://learn.microsoft.com/en-us/azure/storage/blobs/concurrency-manage).

The native fence protocol is covered by local HTTP provider simulations,
including delayed conditional uploads. These tests do not establish live AWS,
Google Cloud, or Azure qualification; real-provider acceptance remains separate
and requires explicitly authorized disposable resources.
