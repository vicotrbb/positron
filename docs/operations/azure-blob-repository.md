# Azure Blob Repository

The native adapter targets Azure public-cloud Blob Storage REST `2023-11-03`
at `https://ACCOUNT.blob.core.windows.net/CONTAINER/` on flat-namespace
StorageV2 accounts. Native account information rejects other account kinds and
hierarchical namespaces. Account names, container
names, and the owned prefix are exact selectors. Arbitrary endpoints, SAS
query strings, account keys, and sovereign-cloud endpoints are rejected.
The adapter uses the existing Kernel-owned Azure Identity SDK `1.0.0` managed
identity implementation with the `https://storage.azure.com/.default` audience.

The verified TLS endpoint binds the native account and container names.
`POSAZI01` binds the repository UUID, authorized instance UUID, integrity-key
fingerprint, and SHA-256 commitment to the canonical target. This does not
claim an immutable Azure Resource Manager account ID. Attaching a repository
verifies the complete immutable Identity. Initialization refuses an owned
prefix containing current, historical, deleted, or uncommitted native objects.

## Configure the native selector

Run repository operations through the existing authenticated Administration
service. The server resolves its managed identity after Maintenance grants
native resources. The CLI reads the administration credential from standard
input.

```console
positron repository doctor --endpoint localhost:4318 --server-name database.example \
  --credential-stdin --azure-account positronbackup --azure-container backups \
  --azure-prefix instance/backups/ --repository-id REPOSITORY_UUID \
  --expected-generation CATALOG_GENERATION --idempotency-key REQUEST_UUID
```

Use `init` for an explicitly empty owned prefix. Use `verify` to attach an
existing repository. `status`, `lookup`, `wait`, and `cancel` use the same
Durable Operation receipts as the other Repository Adapters. Native target
selectors and credentials do not enter operation responses or diagnostics.

The managed identity needs blob read, write, list, and delete permissions on
the designated container. The built-in Storage Blob Data Contributor role
contains those data actions. Native account validation also requires the custom
`Microsoft.Storage/storageAccounts/blobServices/getInfo/action` permission.
An account Owner role is not required. Reading service properties can require an
additional account-scoped permission. Denial is reported as an unavailable
policy observation and never as evidence that soft deletion is disabled.

## Native behavior and bounds

Immutable publication uses `If-None-Match: *`. Reads and registry-head updates
bind the exact native ETag with `If-Match`. Reconciliation uses direct object
inspection after uncertain publication. MD5 checks cover native transfers;
SHA-256 identifies immutable encrypted objects. Range requests are bounded to
4 MiB and verify the returned extent, ETag, and native range MD5.

Uploads retain bounded encrypted input and an owned staging selector in
`POSAZU01`. The existing Kernel control authenticator binds that recovery
frame to the instance and target. Azure block IDs are deterministic content
commitments. Recovery compares native block IDs and lengths before reusing
blocks, verifies the committed staging object, and conditionally publishes the
final immutable object. A staging selector is not a bearer capability, so it
needs no additional credential store or encryption scheme.

Objects are bounded to 64 MiB. Upload blocks are bounded to 4 MiB. Native XML
responses are bounded to 128 KiB, 4,096 elements, and 16 nested elements.
Listing cursors remain opaque provider-owned state. List pages never establish
a current object, upload, or registry-head absence.

Cleanup validates owned live and historical bytes before deleting versions
or snapshots. Native retention, legal hold, remaining deleted history,
interruption, and uncertain deletion keep cleanup pending. An obsolete ETag
cannot delete a concurrent registry successor. Uncommitted block cleanup uses
native Delete Blob under the authenticated owned staging selector.

Container immutability flags, object legal holds, object retention deadlines,
and service soft-delete retention are reported where observable. Account
versioning and external lifecycle rules remain unobservable through these
selected data-plane APIs. Successful cleanup does not prove the absence of
hidden copies or permanent media erasure. Full snapshot, restore, and managed
Tenant Purge semantics remain with their existing workflow owners.

## Run implementation acceptance

The normal integration test uses an independent bounded loopback Blob REST
simulator. It exercises the native adapter through persisted Maintenance
admission, including shared Repository Doctor behavior, ETag races, historical
cleanup, native block recovery, checksum failures, throttling, and uncertain
responses.

```console
cargo test --locked -p positron-backup --features test-support --test azure_blob_target
cargo test --locked -p positron-backup --features test-support --test azure_blob_admission
cargo test --locked -p positron-backup --features test-support --test azure_blob_conformance
cargo +nightly-2026-07-20 fuzz run azure_blob_repository -- -max_total_time=30
```

Loopback construction is available only under `test-support`, uses no
credentials, and rejects non-loopback addresses. Production construction
retains native managed identity and certificate verification. No Azurite
version or deployed Azure target is qualified by the protocol simulator.
Simulation acceptance follows ADR-0068 and does not prove Azure IAM, identity
renewal, service TLS, or deployed retention behavior.

## Qualify a designated Azure target

The ignored `azure_real_service_conformance` integration test uses native
managed identity and verified TLS. Set these non-secret inputs for an explicitly
authorized disposable prefix.

- `POSITRON_AZURE_QUALIFICATION_AUTHORIZATION=explicitly-authorized-disposable-prefix`
- `POSITRON_AZURE_QUALIFICATION_ACCOUNT`
- `POSITRON_AZURE_QUALIFICATION_CONTAINER`
- `POSITRON_AZURE_QUALIFICATION_PREFIX`

```console
cargo test --locked -p positron-backup --features test-support \
  --test azure_blob_conformance azure_real_service_conformance -- --ignored
```

This fixture uses test instance custody and leaves the immutable test Identity
in its designated prefix. It never adopts an existing foreign repository.
Record exact account settings, identity grants, and native service outcomes
before claiming qualification for that deployment. A failed run requires
inspection of that same owned prefix before another test identity is used.

The adapter follows Microsoft's [conditional Blob operations](https://learn.microsoft.com/en-us/rest/api/storageservices/specifying-conditional-headers-for-blob-service-operations),
[Put Block](https://learn.microsoft.com/en-us/rest/api/storageservices/put-block),
[Get Block List](https://learn.microsoft.com/en-us/rest/api/storageservices/get-block-list),
[Put Block List](https://learn.microsoft.com/en-us/rest/api/storageservices/put-block-list),
[List Blobs](https://learn.microsoft.com/en-us/rest/api/storageservices/list-blobs),
and [Delete Blob](https://learn.microsoft.com/en-us/rest/api/storageservices/delete-blob)
contracts. Native account checks and permissions follow
[Get Account Information](https://learn.microsoft.com/en-us/rest/api/storageservices/get-account-information).
