# Canonical Positron v1 API source

`positron.proto` is the hand-edited versioned public contract required by
ADR-0028. The committed Rust v1 types, HTTP/JSON route map, OpenAPI document,
Schema Digest, reference documentation, and validation fixtures are part of
the same product surface and must change together.

`positron-api/build.rs` generates Protobuf messages, fixed enums, and the Rust
`ApiKeyServiceClient`, `TenantQuotaServiceClient`, `TenantServiceClient`, `TenantAliasServiceClient`, `TenantLifecycleServiceClient`, `TenantRetentionServiceClient`,
`PolicyPreviewServiceClient`, `PolicyTestServiceClient`, `PolicyDiffServiceClient`,
`PolicyExplainServiceClient`, `PolicyActivateServiceClient`, `ProviderMigrationServiceClient`, and `RepositoryServiceClient` directly from this schema using locked `prost-build 0.14.3` and
`protoc-bin-vendored 3.2.0`. Ordinary Cargo builds regenerate the output in
`OUT_DIR`; no globally installed compiler is required. API-key HTTP clients
and the runtime service use those generated messages and client through the
bounded JSON adapter named by the canonical HTTP mapping. The API listener
serves HTTP/JSON; generated Protobuf bindings are available as wire types,
while a gRPC administration listener is not exposed.
The build also derives the embedded Schema Digest from the exact Protobuf
source bytes; contract tests compare it with the committed map, OpenAPI,
fixtures, and digest artifact so stale public artifacts fail the tests.

The foundation exposes capability negotiation: it reports the
canonical v1 package and Schema Digest or refuses an incompatible major with a
stable code, retry class, completion state, and non-secret source. It does not
introduce SDK publication or a deferred product capability.

`ApiKeyService.Manage` is served by the authenticated `api` listener at
`POST /v1/api-keys:manage`. The body is limited to 1024 bytes; responses are
limited to 64 KiB. JSON uses snake_case action and scope names. Unknown fields,
duplicate fields, malformed identifiers, and action-inapplicable fields are
rejected. Authorization is `Bearer` metadata. `target_tenant` is an optional
control-plane target for an API-key lifecycle action selected by a System
Administration principal;
it never chooses or impersonates data-plane authority. Only System
Administration may manage keys.

Create requires `scope`, `expected_generation`, and `idempotency_key`, with an
optional `expires_at_unix_seconds` measured against the persisted Lifecycle
Clock. It may name `target_tenant` to provision a tenant-bound principal for
that immutable Tenant ID; otherwise it retains the authenticated legacy
administrative create behavior. Rotate and revoke require `principal`, `expected_generation`, and
`idempotency_key`; list and scope_inspect may also name `target_tenant`, while
scope_inspect requires `principal`.
Identifiers use canonical lowercase UUID text. List returns only redacted
descriptors. A create or rotate retry returns the original principal without a
secret; a lost first secret requires a new rotation. HTTP failures use stable
codes `authentication_rejected` (401), `invalid_request` (400),
`stale_generation` or `idempotency_conflict` (409), `key_unavailable` (404), and
`administration_unavailable` (503).

`TenantRetentionService` is served by the authenticated `api` listener at
`POST /v1/tenant-retention:preview` and
`POST /v1/tenant-retention:update`. A tenant-administration credential may
operate only on its own active or read-only tenant. Preview returns pages of at
most 64 redacted scope impacts, with an opaque continuation that binds the
Catalog snapshot, trusted evaluation instant, and complete confirmation digest.
The confirmation digest still covers the full canonical impact. A reduction
update carries that digest, expected retention generation, and idempotency key.
Authentication completes before body decoding. The
schema-derived `TenantRetentionServiceClient` and `positron tenant retention
preview|update` CLI use the protected-stdin credential and TLS-default
transport contract shared by the administration clients.

`TenantService` is served by the authenticated `api` listener for explicit
System Administration requests: `POST /v1/tenants:create`,
`POST /v1/tenants:inspect`, `POST /v1/tenants:list`, and
`POST /v1/tenants:update-display-name`. All requests authenticate before the
bounded body is decoded. Create receives an immutable tenant ID, canonical slug,
display name, retention period, positive resource limits, and idempotency key;
inspect returns one redacted tenant descriptor. List returns fixed pages of up to
48 descriptors and an opaque Catalog-snapshot continuation; a stale continuation
must restart enumeration rather than mixing descriptor snapshots. The display-name update
uses a nonzero display generation and idempotency key. The schema-derived
`TenantServiceClient` and `positron tenant create|inspect|list|update-display-name`
CLI use protected-stdin credentials and TLS by default; plaintext requires the
explicit `--allow-plaintext` opt-out.

`TenantAliasService.Bind` is served at `POST /v1/tenant-aliases:bind` for a
System Administration bearer. It records an immutable compatibility assertion
for an explicit tenant and returns only a redacted receipt. The schema-derived
`TenantAliasServiceClient` and `positron tenant alias bind` CLI use
protected-stdin credentials and TLS by default; plaintext requires the explicit
`--allow-plaintext` opt-out.

The native CLI invokes this API using `positron key create|list|rotate|revoke|scope-inspect`.
TLS is the default: pass `--endpoint ADDRESS:PORT --server-name DNS_OR_IP --trust-file CA_PEM
--credential-stdin`; the server name is verified against the presented certificate and the CA
reference is read only for that connection. `--allow-plaintext` is an explicit opt-out and cannot
be combined with a trust reference. Supply the bearer through a pipe from a secret manager. Terminal input is refused to prevent echo. Secrets
are never accepted in arguments or environment variables. Mutations require
`--expected-generation N --idempotency-key UUID`; create also requires
`--scope ingest|query|tenant-administration` and accepts optional
`--target-tenant UUID`; the same target is accepted for list, rotate, revoke,
and scope-inspect, while rotate/revoke/scope-inspect require `--principal UUID`.
`--expires-at N` is optional for create. A new
secret is emitted once to stdout; protect that output as credential material.
Public plaintext requires the server's configuration-file-only
`listener.api_transport = "plaintext"` opt-out and the client's explicit
`--allow-plaintext`; it is never an automatic TLS fallback. This sends bearer
credentials and API data without transport encryption. Positron emits the
non-secret configuration warning, remains ready with a persistent health
warning, and records the selected profile once in the governance audit chain.

The client preserves only published failures: `invalid_request`, `authentication_rejected`,
`stale_generation`, `idempotency_conflict`, `key_unavailable`, and
`administration_unavailable`. Malformed,
oversized, or status-mismatched error responses are a bounded transport failure and do not echo
their body.

`PolicyService.Validate` is served by the authenticated `api` listener at
`POST /v1/policies:validate`. A Tenant Administration bearer authenticates before
the bounded 64 KiB candidate is decoded; a System Administration credential cannot
impersonate a tenant through this endpoint. Validation compiles a prospective
candidate in memory and returns only its generation, digest, and rule count. It
never activates a policy, writes a catalog generation, or reveals rules, literals,
or telemetry values. The native CLI is `positron policy validate --policy-file PATH`
with the same protected stdin credential and TLS defaults as the other
administration clients. Its closed failures are `invalid_request` (400),
`authentication_rejected` (401), and `administration_unavailable` (503).

The native Policy CLI uses the checked public clients. Every command requires
`--endpoint IP:PORT` and `--credential-stdin`; TLS requires `--server-name`
and `--trust-file`, while `--allow-plaintext` is the sole plaintext opt-out.
It reads caller-selected files only to the published request bounds:

- `positron policy validate --policy-file PATH`
- `positron policy test --policy-file PATH --candidate-file PATH`
- `positron policy diff --before-policy-file PATH --after-policy-file PATH`
- `positron policy explain --policy-file PATH --candidate-file PATH`
- `positron policy activate --policy-file PATH --expected-generation N --idempotency-key UUID`

Its output contains only published generations, digests, counts, semantic
categories, accepted or rejected outcome, bounded redacted explanations, and
audit position. It never prints credentials, file contents, rule identifiers,
predicate literals, fixture values, or remote error bodies.

`PolicyService.Activate` is served by the same authenticated `api` listener at
`POST /v1/policies:activate`. A Tenant Administration bearer authenticates
before the bounded candidate is decoded. The request carries the expected policy
generation and a canonical Administrative Idempotency Key. A successful request
durably publishes the candidate's required successor generation with governance
evidence; an exact retry returns the original receipt after later changes or
reopen. A stale generation reports only the current generation and a semantic
category, and changed content under an existing key is an idempotency conflict.
The operation is prospective: it does not rewrite existing telemetry.

`PolicyService.Test` is served by the same authenticated `api` listener at
`POST /v1/policies:test`. A Tenant Administration bearer authenticates before
the bounded prospective policy and fixture are decoded. It evaluates the
fixture only in memory and returns the policy generation, digest, accepted
outcome, and applied-rule count; it never activates the candidate or returns
fixture values, rule identifiers, predicate literals, or telemetry values. The
served route's closed
failures are `invalid_request` (400), `authentication_rejected` (401), and
`administration_unavailable` (503).

`PolicyService.Explain` is served by the same authenticated `api` listener at
`POST /v1/policies:explain`. A Tenant Administration bearer authenticates before
the bounded prospective policy and fixture are decoded. It evaluates only in
memory and returns the policy generation, digest, accepted or rejected outcome,
and a bounded explanation containing only semantic action evidence. It never
activates a policy or returns rule identifiers, predicate literals, or fixture
values. Its closed failures are `invalid_request` (400),
`authentication_rejected` (401), and `administration_unavailable` (503).

`TenantQuotaService.Update` is served by the authenticated `api` listener at
`POST /v1/tenant-quotas:update`. A Tenant Administration bearer may mutate only its
attributed control-plane tenant; `tenant` never provides data-plane attribution. The request
contains an expected resource generation, idempotency key, positive weight, and eleven positive
named resource limits: `memory_bytes`, `queue_slots`, `task_slots`, `buffer_cache_bytes`,
`batch_items`, `lease_slots`, `retry_slots`, `io_permits`, `cpu_work_units`,
`file_descriptors`, and `disk_headroom_bytes`. A successful update returns the published
successor `resource_generation`. Replaying the same valid idempotency binding returns that
successor without restoring obsolete live quota state.

The quota CLI is `positron tenant quota update` and uses the same protected stdin credential and
TLS defaults as `positron key`. It requires all eleven named limits, `--tenant`,
`--expected-generation`, and `--idempotency-key`; plaintext needs explicit `--allow-plaintext`.
Quota failures are `invalid_request` (400), `authentication_rejected` (401),
`stale_generation` or `idempotency_conflict` (409), and `administration_unavailable` (503).

`TenantLifecycleService.Transition` is served by the authenticated `api`
listener at `POST /v1/tenant-lifecycle:transition`. A System Administration
bearer authenticates before the 1024-byte request body is decoded. The request
names its immutable target tenant, lifecycle target, expected lifecycle
generation, and idempotency key. An exact retry returns the original committed
transition and audit metadata; stale requests expose only the current lifecycle
generation and one bounded redacted semantic difference. Direct `Purged`
completion is unavailable until its separately authorized cryptographic purge
completion has succeeded. The native CLI is `positron tenant lifecycle
transition --tenant UUID --target active|read-only|suspended|purging|purged
--expected-generation N --idempotency-key UUID`, with the same protected stdin
credential and TLS-default transport contract as the other administration
commands. Its closed failures are `invalid_request` (400),
`authentication_rejected` (401), `tenant_unavailable` (404),
`stale_generation`, `idempotency_conflict`, `invalid_transition`, or
`purge_completion_unavailable` (409), and `administration_unavailable` (503).
A stale-generation body also carries the current nonzero `resource_generation` and a bounded,
redacted `semantic_diff`, so a caller can recover without receiving quota values or credentials.

`TenantAliasService.Bind` is served by the authenticated `api` listener at
`POST /v1/tenant-aliases:bind`. A System Administration bearer authenticates
before the 1024-byte body is decoded. The request names an explicit immutable
tenant, one bounded protocol-specific `external_alias`, its expected alias
generation, and an idempotency key. The alias is a compatibility assertion for
data-plane requests only after the credential has already attributed one
tenant; it never selects routing or authority. A successful first bind returns
only the target tenant, successor alias generation, and redacted audit
position/time. The alias text, credential, and request digest stay out of the
receipt. Exact retries return the original receipt, while an alias cannot be
rebound, unbound, or reused by another tenant, including after purge. Closed
failures are `invalid_request` (400), `authentication_rejected` (401),
`tenant_unavailable` (404), `stale_generation`, `idempotency_conflict`,
`alias_already_bound`, or `alias_conflict` (409), and
`administration_unavailable` (503).

`MaintenanceService.AbandonSegment` is served by the authenticated `api`
listener at `POST /v1/maintenance:abandon-segment`. System Administration
credentials are revalidated for preview, confirmation, status, and retries.
The 768-byte request names immutable tenant, signal, shard, and segment.
Preview returns exact authenticated Event Time and Ingest Time loss ranges,
Catalog generation, and a confirmation digest without publishing state.
Confirmation requires that digest, expected Catalog generation, idempotency
key, and explicit `accept_data_loss: true`. The live segment reference,
permanent incomplete-data evidence, succeeded operation, and exact loss audit
are published atomically. Segment bytes remain quarantined evidence; this
command neither repairs bytes nor claims complete query results over lost data.
Exact retries return the original receipt. Status supplies the same scope and
segment with `operation_id`, without confirmation fields.

The CLI is `positron maintenance abandon-segment --tenant UUID --signal logs|traces
--shard N --segment HEX`, using the existing credential-stdin and TLS transport
contract. Add `--expected-catalog-generation N --confirmation HEX --idempotency-key UUID
--accept-data-loss` to confirm, or `--operation-id HEX` to inspect the receipt.

`ProviderMigrationService.Manage` is exposed through the authenticated
administrative HTTP/JSON projection at `/v1/key-provider-migrations:manage`.
Its generated client shares the canonical 4096-byte request/response bounds.
The operation status projection contains public outcome and retry metadata;
protected configuration references and their digests remain private operation
parameters. This service does not advertise a gRPC administration transport.

`RepositoryService.Manage` is the authenticated administrative HTTP/JSON
projection at `POST /v1/repositories:manage`, with descriptor-derived 4096-byte
request and response limits. It serves `init`, `verify`, `doctor`, `status`,
`lookup`, and `cancel`. Mutations require expected Catalog generation and a
principal-bound idempotency key; their operation ID, progress, cancellation,
retry guidance, and lookup retention follow the existing Durable Operation
contract. A server-local native locator is private accepted-operation data;
responses and errors never return it or credentials.

The CLI is `positron repository init|verify|doctor|status|lookup|wait|cancel`,
using protected `--credential-stdin` and TLS by default. Local mutations take
`--locator SERVER_PATH --repository-id UUID --expected-generation N
--idempotency-key UUID`. `wait --operation-id HEX --wait-seconds N` observes the
accepted operation for a bounded 1..60 seconds; expiry leaves its outcome
unknown and instructs the caller to inspect that same operation.

These commands inspect native Repository provider behavior and immutable
identity. Doctor uses an isolated owned probe head and objects, checks CAS,
checksum/range, multipart recovery, and observable deletion, and removes only
its exact probes. External retention is reported as `not_observable` by the
local adapter. These provider checks do not establish signed backup-registry,
restore, permanent-erasure, or remote-provider conformance. This service does
not advertise a gRPC administration listener.

Repository management accepts either the local `path` or the complete `aws_s3`
selector (bucket, region, regional HTTPS endpoint, expected owner and prefix).
Native credentials are server-side standard-chain inputs and are never wire
fields. Terminal `policy` distinguishes observed, unavailable and unobservable
bucket controls. Optional `doctor_probe` additionally reports only the owned
probe's retention expiry/mode, legal hold and event-hold period; it is absent for
initialization and verify. Unknown controls never imply absence or purge proof.

Google Cloud Storage selects `google_cloud_storage` with bucket, numeric project
number, exact location and prefix. CLI flags are `--gcs-bucket`,
`--gcs-project-number`, `--gcs-location` and `--gcs-prefix`. A request selects
exactly one local/AWS/GCS target. The server resolves native workload credentials;
selectors, credentials and resumable session URIs never enter responses.

Policy receipts may add a `soft_delete` observation whose observed `value` is
retention seconds. Retention periods preserve `seconds`, and active GCS event
holds use `until_release` without a fabricated period. `provider_enforced`
reports an effective object deadline when bypass mode is not exposed. Legacy
receipts retain their existing fields and absence semantics. Real GCS provider
qualification remains independent of API schema and local test results.

Azure Blob Storage selects `azure_blob` with the exact public-cloud account,
container, and owned prefix. Protobuf field 9 is additive. The selector is
exclusive with local, AWS, and GCS selectors. Server-owned managed identity uses
the Azure Storage audience; credentials and arbitrary endpoints are rejected.
See [the Azure Repository scope](../../../docs/operations/azure-blob-repository.md).

`BackupService.Manage` is the authenticated HTTP/JSON projection at
`POST /v1/backups:manage`, with 4096-byte request and response limits. Creation
requires an exact existing Repository selector and UUID, expected Catalog
generation, principal-bound idempotency key, and `retention_seconds` in
60..315360000. Selectors use the same local, AWS, GCS, and Azure fields as
Repository administration. The server resolves credentials.

The CLI is `positron backup create|status|lookup|wait|cancel`. For example:

```console
positron backup create --endpoint 127.0.0.1:4318 --server-name localhost --trust-file ca.pem --credential-stdin --locator /srv/backups --repository-id UUID --expected-generation N --idempotency-key UUID --retention-seconds 86400
positron backup status --endpoint 127.0.0.1:4318 --server-name localhost --trust-file ca.pem --credential-stdin --operation-id HEX
```

`lookup` supplies the original idempotency key. `cancel` supplies the operation
ID, its current `expected_operation_revision`, and a new idempotency key. `wait` polls the same
operation for 1..60 seconds (`--wait-seconds`, default 30); expiry preserves an
unknown caller outcome. Status and lookup reject Repository selectors and
retention. Responses expose the operation, optional exact Repository Identity,
and a verified terminal receipt containing manifest checksum, captured Catalog
generation and identity, uploaded/reused bytes, and retention deadline. They
never expose native selectors or credentials. `backup_publication` disables
cancellation; `backup_registry_published` records the irreversible boundary.

Successful backup receipts also require `registry_generation_checksum`, the
nonzero SHA-256 checksum of their signed publication generation.

`BackupService.List` is a separate authenticated read at
`POST /v1/backups:list`. `positron backup list --repository-id UUID` uses the
same endpoint, credential-stdin, and TLS options. `--limit N` accepts 1..128
(default 128), and `--cursor HEX` resumes a page. Requests contain only the
registered repository UUID, limit, and optional opaque cursor; listing creates
no Durable Operation. The 176-character lowercase hexadecimal cursor binds the
exact Repository Identity, signed Registry Generation, and final snapshot of
the preceding page. A changed registry head requires starting the listing over.

The response contains exact Repository Identity, optional signed registry
checksum, ordered unique snapshot entries, and an optional next cursor.
Each entry reports its 32-character snapshot ID, manifest checksum, creation
time, and retention deadline. A missing registry checksum means no registry
head exists; a signed head containing only reservations still returns its
checksum with an empty published-entry list. Listing returns at most 128
entries in a 65536-byte response; its request remains limited to 4096 bytes.

Backup management also accepts `expire` for an elapsed snapshot retention
period. It requires the registered `repository_id`, exact 32-character
`snapshot_id`, nonzero 64-character `expected_manifest_checksum`, expected
Catalog generation, and idempotency key. It rejects native selectors,
retention duration, and operation ID. The CLI uses `positron backup expire`
with `--repository-id`, `--snapshot-id`, `--expected-manifest-checksum`,
`--expected-generation`, and `--idempotency-key`, alongside normal protected
credentials and transport options.

Management responses require `kind` (`snapshot` or `retention`) and
`cleanup_pending`. Successful retention operations carry `retention_receipt`
with snapshot ID, manifest checksum, signed registry generation checksum, and
counts of deleted, already absent, and retained shared objects. Snapshot and
retention receipts are mutually exclusive. Registry expiry publication crosses
`backup_registry_expired`; cleanup then completes before retention succeeds.

An accepted cancellation remains Running in `backup_cancellation` with
`cancel_requested_cleanup_pending` until owned cleanup completes. A Cancelled
operation reports `cleanup_pending: false`. Snapshot success can still report
pending local capture cleanup, and failures can report unresolved cleanup;
these fields describe the authoritative state rather than claiming rollback.

Backup management responses require a nonzero `operation_revision`, beginning
at 1 when accepted. Status, lookup, and wait expose that exact operation's
revision. Cancellation requires `expected_operation_revision` alongside the
operation ID and idempotency key and rejects `expected_catalog_generation`.
Use `positron backup cancel --operation-id HEX --expected-operation-revision N
--idempotency-key UUID` with the normal transport and credential options.
A changed operation revision requires inspection before retrying. Foreground
Catalog changes do not invalidate an unchanged operation's cancellation
precondition. Create and expiry retain their Catalog-generation preconditions;
all actions except cancellation reject an operation revision precondition.

Failed backup operations require `terminal_error_code`; other states omit it.
The closed codes are `handler_rejected`, `legacy_unknown` for legacy records,
and `backup_retention_not_due`. A known trusted clock before the snapshot's
retention deadline produces a durable Failed expiry operation with the latter
code and an uncrossed irreversible boundary. Replaying its idempotency key
returns that same failure; a new request can succeed after the deadline.
An uncertain clock keeps expiry pending with retry guidance. CLI status, lookup,
wait, and expiry output display the persisted terminal reason.

Backup management and listing report explicit admission refusal as HTTP 503
with `code: capacity_unavailable`. The generated client preserves this as
`BackupServiceClientFailure::CapacityUnavailable`; callers can retry the same
idempotent request. Unknown or malformed responses remain transport failures.
