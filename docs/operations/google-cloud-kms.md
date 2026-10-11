# Google Cloud KMS custody

`GoogleCloudKmsKeyProvider::from_application_default` constructs the caller-owned
asynchronous Key Provider for one pre-provisioned symmetric CryptoKeyVersion.
The `ProviderKeyUri` contains the complete
`projects/.../locations/.../keyRings/.../cryptoKeys/.../cryptoKeyVersions/N`
resource and the same positive canonical decimal version. A CryptoKey, alias,
signed version, or substituted endpoint is refused. The adapter never provisions
keys, changes IAM, rotates Google primary versions, or deletes cloud resources.
The workload needs `cloudkms.cryptoKeyVersions.get`,
`cloudkms.cryptoKeyVersions.useToEncrypt`, and
`cloudkms.cryptoKeyVersions.useToDecrypt` on the selected key/version. Prefer
native workload identity with the official Google Application Default
Credentials chain. The caller supplies an existing Tokio runtime and reserves
`required_resources()` through the existing Resource Governor before opening
native identity.

The admitted official ADC chain supports authorized-user and service-account
credentials, service-account impersonation, external-account federation from
files, URLs, executable output or AWS identity, and the standard metadata
fallback. The same immutable native owner follows accepted nested credentials.
The upstream ADC rejection of GDCH credentials is preserved. Executable sources
also require Google's explicit executable opt-in; configure only a trusted
credential executable. Positron bounds its direct child, output, deadline and
reaping, rather than claiming a limit on arbitrary child program memory or
descendants.

The metadata probe requires the exact selected version, `ENABLED` state and
`GOOGLE_SYMMETRIC_ENCRYPTION`. Encrypt addresses that immutable version and
requires its exact name in the response. Google Decrypt addresses the parent
CryptoKey and selects the version from the ciphertext; its response does not
provide a version-name receipt. Both operations supply the canonical Positron
context digest as additional authenticated data and verify the CRC32C receipts.
The recovered canonical plaintext payload independently binds the selected
provider identity, tenant/object scope, epoch, format and purpose before any
KEK transfer. CRC32C detects transport corruption; the KMS authentication and
canonical payload checks supply the cryptographic binding.

The shared Data Protection owner continues to govern plaintext KEK cache leases,
expiry and invalidation. This adapter adds no plaintext cache. Rotation and
migration use authenticated unwrap, canonical rebuild, destination wrap and
verification through the existing owner. An additive successor envelope does
not authorize predecessor retirement. Recovery and backup recovery use the same
identity/context checks; unresolved or opaque backup references retain their
existing retirement barrier.

One KMS operation runs at a time; competing operations fail with
`LimitExceeded`. The complete operation, including identity acquisition, has a
fifteen-second deadline. A request makes at most two attempts, separated by
100 ms only after an explicit quota or service-unavailable rejection.
`RESOURCE_EXHAUSTED` and `UNAVAILABLE` are retryable. Permission, key, disabled
version and context errors are permanent typed failures. `CANCELLED`,
`DEADLINE_EXCEEDED`, `INTERNAL`, `UNKNOWN`, malformed errors and unrecognized
server failures can leave Encrypt's outcome uncertain and are not automatically
retried. An identity timeout before submission is unavailable; an Encrypt
timeout or transport failure after submission is ambiguous. No provider message
or response body determines the failure class.

Google's current KMS quotas are regional and charged to the project owning the
key. Software, HSM and external KMS have separate usage metrics; metadata reads
consume read quota. Effective limits depend on the project, location and
protection level, so operators should inspect their actual limits before
selecting workload concurrency. The adapter preserves the native credential
quota-project header and responds to explicit quota rejection through the same
bounded retry policy. That header does not change KMS's documented key-project
quota charging. See [Cloud KMS quotas](https://docs.cloud.google.com/kms/quotas).

Native files and credential HTTP bodies are capped at 128 KiB, KMS requests at
16 KiB and KMS responses at 32 KiB. Native JSON admits at most 2,048 nodes,
depth 32 and 128 KiB of string content, and refuses duplicate object fields.
Remote identity and KMS use verified TLS. Plain HTTP identity endpoints require
every resolved address to be loopback, `169.254.169.254`, Google
`fd20:ce::254` or AWS `fd00:ec2::254`; the validated set is pinned to the
connection. The exact Google IPv6 address supports the standard
[metadata endpoint on IPv6-only VMs](https://docs.cloud.google.com/compute/docs/metadata/overview). Redirects, ambient proxies,
HTTP/2 and idle pooling are disabled. Native DNS uses the same bounded resolver
as the AWS adapter, including its system-file and wire limits. SDK refresh,
connection dispatch, resolver work and direct-child cleanup retain the original
grant until actual termination. Keep the Tokio runtime alive until these owners
reconcile. Dropping a request or provider does not release work still cleaning
up.

The single transferred reservation admits sixteen task slots, sixteen I/O
slots and sixteen descriptors. Native refresh tasks have an eight-task ceiling,
DNS workers a four-task ceiling, connection dispatchers a two-task ceiling and
the direct-child cleanup worker a one-task ceiling. These maxima total fifteen
background tasks. Independent operation ceilings are two HTTP requests, four
file reads, one direct child and one cryptographic operation. The descriptor
allowance covers four files, two HTTP connections, two child output pipes and
up to eight DNS UDP/TCP descriptors. These are simultaneous admission bounds;
cancellation retains the occupied slot until its owner finishes cleanup.

The 64 MiB memory claim includes simultaneous native owners and transient
copies. Its conservative allocation is 28 MiB for up to eight admitted SDK
workers at 3.5 MiB each, 5 MiB for ADC construction, 8 MiB for two HTTP/TLS
connections, 4 MiB for file/process/DNS/backend work, 8 MiB for inherited
environment capture and launch, and 11 MiB of headroom. The accepted ADC graph
actually retains at most two refresh caches. Each worker allowance includes a
128 KiB raw body, a JSON tree with at most 2,048 values and 128 KiB of strings,
container overhead, decoded DTO and token/watch copies, retry request copies,
and serialization expansion up to six times for JSON or three times for form
encoding. The SDK's detailed copy inventory is in its retained patch provenance.

Release 1 runs on Linux and macOS. The inherited launch allowance follows
their [Linux exec argument/environment limits](https://github.com/torvalds/linux/blob/master/fs/exec.c)
and [macOS argument limit](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/syslimits.h).
Positron does not mutate the process environment. Official ADC selection uses
safe standard-library environment captures after admission; their allocation
precedes a length check. This accounting is a bounded product-work claim,
rather than a universal physical allocator ceiling for an embedding process
that replaces environment values at runtime. Library scratch, allocator
overhead and transport internals retain their reviewed library behavior.

Application-owned key material, native JSON trees, token fields and credential
buffers use zeroizing ownership. Headers are sensitive and diagnostics are
redacted. Upstream TLS, HTTP and serde scratch allocations retain their library
memory behavior. The Crypto Backend performs native RSA-SHA256 and HMAC-SHA256;
this adapter does not install a global signing provider or claim FIPS validation.

For real-target acceptance, an operator explicitly constructs this provider
with the exact pre-provisioned identity and grant and supplies it to
`KeyProviderConformance::healthy`, outage, recovery and rotation-and-migration
methods. The operator controls the real outage and destination key. Repository
default tests neither discover an ambient target nor contact Google Cloud.
Published wire fixtures and isolated native credential boundaries establish
local contracts, not live Google service acceptance. NativeHost provider
selection remains the responsibility of its existing composition boundary.

Google's [Encrypt contract](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/encrypt),
[Decrypt contract](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/decrypt)
and [CryptoKeyVersion contract](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions)
define the resource, algorithm and integrity receipts.
The [canonical RPC status definitions](https://github.com/googleapis/googleapis/blob/master/google/rpc/code.proto)
explicitly allow a successful state-changing operation before deadline expiry;
[AIP-193](https://google.aip.dev/193) defines the structured error boundary.
