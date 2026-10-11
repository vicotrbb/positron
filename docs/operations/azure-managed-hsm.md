# Azure Managed HSM custody

`AzureManagedHsmKeyProvider` is the independent Managed HSM implementation of
Positron's asynchronous Key Provider port. It uses the published stable Key
Vault/Managed HSM keys REST API 7.6, with a pre-provisioned `RSA-HSM` key of
2048, 3072 or 4096 bits, exponent 65537, and `wrapKey`/`unwrapKey` operations.
Software `RSA`, `oct-HSM`, `EC-HSM` and alternate wrapping algorithms are outside this adapter's supported target.
The adapter never provisions, changes, exports, deletes or rotates an Azure
root key. Rotation in Positron means rewrapping under another pre-provisioned
immutable version; migration uses the existing verified envelope workflow.

Supply the exact canonical lowercase HTTPS URI
`https://HSM.managedhsm.azure.net/keys/NAME/32_HEX_VERSION` and matching separate
version. China `.managedhsm.azure.cn` and Government
`.managedhsm.usgovcloudapi.net` select their respective native cloud authority
and Managed HSM audience. The public token scope is
`https://managedhsm.azure.net/.default`; sovereign scopes use the corresponding
Managed HSM suffix. Vault endpoints, arbitrary hosts, ports, aliases, escaped
or normalized paths and unversioned keys fail before identity I/O. Every
metadata and cryptographic response `kid` must exactly equal the selected URI.
A Premium Key Vault `RSA-HSM` key is still a Key Vault target and cannot satisfy
Managed HSM acceptance.

Managed HSM data-plane authorization uses **Managed HSM local RBAC**, separate
from Azure management-plane RBAC and Key Vault access policies. Provision the
workload with permission to get, wrap and unwrap the selected key. The adapter
uses only `GET /keys/NAME/VERSION`, `POST /keys/NAME/VERSION/wrapkey` and
`POST /keys/NAME/VERSION/unwrapkey`, each with `api-version=7.6`. It does not
request security-domain, key-administration, backup or role-management rights.
Operators retain responsibility for HSM security-domain and disaster-recovery
custody; a Positron backup does not contain the HSM root key.

Reserve `required_resources()` through the Resource Governor before calling
`from_managed_identity` or `from_workload_identity` in the existing Tokio
runtime. The pinned official Azure identity SDK owns managed/workload token
selection, exchange, refresh and cache. Public adapters reject each other's
provider family before environment, file, DNS or network activity. Both service
types share one private Azure identity/transport/operation owner and the
existing Crypto Backend, envelope/session, cache and recovery authorities.
The [native Azure custody limits](azure-key-vault.md) also apply here, including
64 MiB admission, 128 KiB identity files/bodies, 8 KiB selectors, verified TLS,
disabled redirects/proxies, admitted DNS and cancellation cleanup. Isolated
App Service tests exercise the actual SDK's distinct HSM resource audience.
No embedding-process allocator guarantee, universal TLS/serde heap zeroization
or native-host deployment acceptance is asserted.

`RSA-OAEP-256` wraps the entire canonical Wrapped Key Payload, with modulus
bytes minus 66 as its plaintext limit. The ciphertext must be exactly the
modulus length. No native context or OAEP label is available on this operation;
instance, tenant/system scope, key ID, epoch, format, purpose and provider
identity are authenticated by validating the recovered canonical payload.
Metadata must have `RSA-HSM`, enabled state and both required operations.
Live verification and wrapping also require a current `nbf`/`exp` window.
Managed HSM expressly permits unwrap with date-expired or not-yet-valid keys,
so direct `KeyProvider::unwrap` permits that recovery case while disabled keys
remain rejected. Session startup/restore verification still performs a live
wrap/unwrap probe and therefore requires a currently valid key with both
capabilities; expired keys cannot establish new provider readiness.

The deadline is fifteen seconds across metadata, native identity and the
operation, with one admitted operation at a time. HTTP 401/403 are permanent
permission failures; 404/410 are wrong/missing-version failures. Explicit 429
throttling may retry once with bounded `x-ms-retry-after-ms` or numeric
`Retry-After` (at most two seconds); malformed/longer delays fail unavailable.
Wrap transport/server failures after dispatch are ambiguous and never retried.
Metadata/unwrap server failures may retry once. Service error bodies and tokens
are discarded; typed errors carry no service messages or secrets. These are
Positron classifications of the published HTTP failure boundary, independent
of HSM role administration and provider-specific quota settings.

The existing bounded zeroizing KEK cache owns leases, expiry, health and
invalidation. Valid leases survive an outage until expiry, with no fallback;
cold/expired keys fail unavailable. Rotation, revocation, credential reload
and administrative purge use the existing invalidation contract. Shared
backend tests cover published cryptographic vectors, every persistent frame
kind, nonce restart, memory limits and zeroization. Independent HSM immutable
wire transcripts cover native requests, metadata/receipt pinning, context
substitution, invalid plaintext, disabled/date-expired keys, HSM permissions,
throttling, deadline/cancellation, cold-cache outage, root-version rewrap and
local migration. They establish local adapter behavior, not native RSA or live
cloud acceptance. The existing envelope fuzz target additionally reaches HSM
URI, metadata and response parsing under all operation policies.

For explicit real-target acceptance, construct this exact provider and pass
`ProviderConformanceTarget::new(ProviderFamily::AzureManagedHsm,
"Azure Managed HSM", "7.6", ACTUAL_DEPLOYMENT)` to the existing
`KeyProviderConformance::healthy`, `outage`, `recovery` and
`rotation_and_migration` phases with exact context and another pinned
pre-provisioned destination. The operator induces/restores the outage outside
Positron; no cloud administration or executable callback is supplied by the
harness. A Key Vault target is rejected as a family mismatch. Default tests
use only immutable published-wire shapes and fictional isolated native identity
with loopback HTTP rejection. No live Azure call, ambient credential discovery,
cloud infrastructure change or FIPS certification claim is part of this work.

The common wire operations are explicitly published for both Key Vault and
Managed HSM in the [Azure REST API reference](https://learn.microsoft.com/en-us/rest/api/keyvault/).
The immutable [stable 7.6 keys schema](https://github.com/Azure/azure-rest-api-specs/blob/65eb9311d304dcf9874d05fdec39ea65baae8db8/specification/keyvault/data-plane/Keys/stable/7.6/keys.json)
was read independently for this target; its SHA-256 is
`16c2b5499019b2fd663bba2c014ea1ccde2bf58684188cecbfed0a776314a13e`.
[Managed HSM key details](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/about-keys-details)
provides the RSA-HSM algorithm and date-controlled recovery semantics;
[object identifiers](https://learn.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates)
provides the three cloud endpoint suffixes;
[Managed HSM access control](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/access-control)
provides tenant authentication and local RBAC separation. The official
[Azure guest-attestation constants](https://github.com/Azure/confidential-computing-cvm-guest-attestation/blob/main/cvm-securekey-release-app/Constants.h)
and [Azure CLI cloud endpoints](https://learn.microsoft.com/en-us/cli/azure/azure-cli-endpoints)
distinguish the Managed HSM token resource and cloud endpoints. Azure's
[Managed HSM service limits](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/service-limits)
are operational provider quotas; Positron adds no separate quota authority.
