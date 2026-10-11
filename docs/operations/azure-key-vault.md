# Azure Key Vault custody

`AzureKeyVaultKeyProvider` implements the asynchronous Key Provider port for
Azure Key Vault REST API 7.6. Operators pre-provision an RSA or RSA-HSM key with
2048, 3072, or 4096 bits, exponent 65537, and `wrapKey`/`unwrapKey` operations.
RSA-HSM in a Premium Key Vault is supported; Azure Managed HSM is a separate
provider and conformance target. This adapter never provisions or changes a
root key, retargets an alias, or administers Azure access policy.

Supply a complete canonical, lowercase HTTPS Provider Key URI of the form
`https://VAULT.vault.azure.net/keys/NAME/32_HEX_VERSION`, with that exact version
as the separate `ProviderKeyUri` version. Azure China `.vault.azure.cn` and
Azure Government `.vault.usgovcloudapi.net` use their matching native cloud
identity authority and vault audience. Ports, user information, normalized or
escaped paths, unversioned key names, arbitrary hosts, and Managed HSM endpoints
are refused before identity I/O. The response `kid` must exactly equal the
selected immutable URI. Configure the canonical identity, even though Azure's
identifiers are generally case insensitive; Positron never silently normalizes
or retargets stored provider identity.

The workload needs `get`, `wrapKey`, and `unwrapKey` for that key. Reserve
`required_resources()` from the existing Resource Governor and use an existing
Tokio runtime before constructing native identity. `from_managed_identity`
uses the pinned official stable Azure identity SDK 1.0.0, with system-assigned
identity or its client, object, or resource ID selector. Its supported sources
are IMDS and App Service; the SDK's explicit rejection of Azure Arc, Azure ML,
Cloud Shell, Service Fabric, and App Service resource-ID selection is preserved.
There is no developer credential fallback. `from_workload_identity` uses
projected Kubernetes workload identity. Optional non-secret tenant/client/file
selectors override native `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and
`AZURE_FEDERATED_TOKEN_FILE`; projected-token symlinks are supported. The SDK
owns token selection, exchange, renewal, and its ten-minute projected-token
refresh cache. The beta-only AKS identity binding proxy is not part of this
pinned stable SDK. Credentials are external and never persisted in Positron.

Each operation verifies exact metadata, enabled state, not-before and expiry,
RSA key size, and both required key operations. Native `wrapkey` and `unwrapkey`
use `RSA-OAEP-256` exclusively, with no local RSA implementation or alternate
algorithm. Its SHA-256 OAEP bound is checked before submission: modulus bytes
minus 66, including the entire deterministic Wrapped Key Payload. Ciphertext
must be exactly the modulus length. Key Vault RSA does not offer an authenticated
context or OAEP label parameter. The recovered canonical payload independently
verifies instance, scope, key ID, epoch, format, purpose and provider identity
before any KEK transfer. A forged routing context, substituted key, truncated
receipt or malformed plaintext fails closed.

One operation runs at a time; competing operations return `LimitExceeded`.
Metadata and wrapping/unwrapping share one fifteen-second deadline including
native identity acquisition. Only explicit HTTP 429 throttling is retried for
Wrap, at most once. Metadata and Unwrap may retry HTTP server failures once.
`x-ms-retry-after-ms` or numeric `Retry-After` are honored within a two-second
budget; malformed or longer retry delays return unavailable without another
submission. The fallback delay is 100 ms. Permission errors are permanent;
missing/deleted versions are wrong-key failures. Wrap's server or transport
failure after submission is ambiguous and is never automatically retried.
Identity failure before submission is unavailable or its original typed native
failure. Error classes retain no service message, response body, or token.

The existing Data Protection session and memory cache remain the lifecycle
authorities. Valid leases permit existing keys during outage until expiry;
uncached/expired keys fail unavailable with no fallback. Startup and recovery
perform live verification. Credential reload, rotation, revocation, and cache
purge use the existing invalidation contract. Root rotation and cross-provider
migration unwrap, rebuild canonical context, wrap under a pre-provisioned
destination and verify the new envelope. They do not rewrite encrypted frames
or authorize retirement before the existing live/backup reachability proof.
External recovery still requires native provider custody and live access; the
adapter does not export an Azure root key or claim independent Azure disaster
recovery acceptance.

The transferred 64 MiB resource reservation covers identity construction,
SDK token/cache/request copies, serialization expansion, simultaneous native
owners and transport scratch. It retains the existing sixteen task/I/O/file
slots and native DNS/HTTP/file admission limits. Identity files and HTTP bodies
are capped at 128 KiB, selectors at 8 KiB, Azure responses at 32 KiB, and RSA
requests below 2 KiB. The same admitted HTTP/DNS owner as the Google adapter
supplies verified TLS, disabled redirects/proxies/idle pooling, bounded native
DNS, limited connection dispatch, and cancellation ownership until cleanup.
For App Service the SDK captures its selected endpoint once into an Azure-only
capability. Requests must match that exact HTTP scheme, host, port and path,
selected identity and cloud audience, with only the SDK's expected query fields.
Every resolved peer must be loopback or link-local before credentials are sent;
connections pin that complete admitted address set. Empty, mixed and remote peer
sets fail closed. This is Positron's conservative local-endpoint policy, not an
Azure guarantee of particular IP ranges or acceptance of every App Service
deployment. IMDS retains its existing fixed metadata peers; projected workload
identity retains verified HTTPS. Redirects and proxies remain disabled. Native refresh does not start an unowned thread.
The workload file is read through the admitted owner on construction and refresh.

SDK presence checks distinguish absent environment values from rejected values.
Oversized source values cannot silently switch managed-identity branches;
secret presence-check copies are zeroized. Unsupported native forms retain the
SDK's explicit errors. The reservation precedes SDK native environment capture. Environment values are
checked after the standard library captures them, with conservative launch
allowance for supported Linux/macOS deployments as in the existing native
identity owner. This bounds product work; it is not a universal allocator limit
for an embedding process that mutates arbitrary environment values. Owned
payloads, token fields, raw HTTP bodies, assertion/form buffers, and SDK header
copies use zeroizing storage. SDK diagnostics are suppressed and provider errors
are sanitized. TLS, HTTP, and serde parser scratch retain their reviewed library
memory behavior. No FIPS certification is claimed.

For real-target acceptance, explicitly construct this provider and supply the
exact Azure Key Vault target metadata and context to
`KeyProviderConformance::healthy`, `outage`, `recovery`, and
`rotation_and_migration`. The operator induces/restores the real outage and
supplies another pinned destination; the harness cannot modify cloud keys.
The generic harness checks context substitution, corruption, truncation and
actual recovery. A Managed HSM target cannot be reported as Key Vault acceptance.
Default tests use immutable published-wire shapes and isolated fictional native
identity, never ambient credentials or Azure service discovery. They establish
local contracts; no live Azure acceptance was performed by this change.

The primary wire contract is the official [Azure Key Vault 7.6 REST schema](https://github.com/Azure/azure-rest-api-specs/blob/65eb9311d304dcf9874d05fdec39ea65baae8db8/specification/keyvault/data-plane/Keys/stable/7.6/keys.json),
including Get, Wrap and Unwrap Key, and [Key types and algorithms](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details).
The [App Service native endpoint reference](https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity#rest-endpoint-reference)
describes its platform-supplied local identity endpoint and rotating secret.
The [stable SDK source](https://github.com/Azure/azure-sdk-for-rust/tree/c3c92ed4349125e25d176f13faa9ef016b790b3e/sdk/identity/azure_identity)
defines identity behavior; retained patch provenance records the exact archives
and narrow custody changes. Azure [throttling guidance](https://learn.microsoft.com/en-us/azure/key-vault/general/overview-throttling)
explains per-vault operation quotas and service rejection. Operators must inspect
actual vault limits; Positron adds no quota authority or key-management service.
