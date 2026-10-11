# OpenBao Transit

The native adapter independently targets **OpenBao 2.7.1**, Transit HTTP API v1,
[official release](https://github.com/openbao/openbao/releases/tag/v2.7.1), commit
`a5db72cef75c24b920ade02065b18dd8eb666bac`. OpenBao and Vault remain separate
conformance targets. The source checks below establish the shared wire operations;
Vault tests and protocol similarity do not establish OpenBao acceptance.

Operators pre-provision a `derived=true`, `convergent_encryption=false`,
`aes256-gcm96` key and select its exact positive version. Positron does not create,
rotate, export, disable, destroy or restore provider-owned root keys. The Provider
Key URI is `https://HOST[:PORT]/v1/MOUNT/keys/NAME` plus a canonical positive decimal
version no greater than 2147483647. Nested mount paths are supported. Escaped or
normalized paths, aliases, queries, fragments and noncanonical versions fail
closed. Health must report initialized, unsealed, active OpenBao 2.7.1; redacted or
other versions are refused. OpenBao 2.7 has native namespaces, but this adapter
supports the root namespace only and sends no namespace header. Keys and machine
authentication must be provisioned there; there is no namespace selector.

`OpenBaoTransitKeyProvider::from_native` consumes the existing Security Lifecycle
grant before reading credentials or CA roots. Its constructor refuses Vault
identities, and the Vault constructor refuses OpenBao identities. Independently
verified common Transit operations share the existing native transport and
credential custody code. There is no additional SDK, cryptographic implementation,
cache, lease authority or validation runner.

Verified TLS checks chains and hostnames without an insecure opt-out, redirects or
proxy routing. Optional public PEM CA roots supplement the public roots. The CA
file is bounded to 32 KiB and 16 certificates, opened without following symlinks,
and must be regular, single-link, owned by root or the effective UID, and not
writable by group or others. The retained grant covers the existing bounded native
DNS, connection, file, response and transport tasks through cancellation cleanup.

Kubernetes and JWT authentication explicitly read a protected projected JWT file
and POST `{role,jwt}` to `auth/MOUNT/login`. The selected JWT auth role must support
one-shot JWT login, rather than browser OIDC login. Protected token files use an
empty authentication mount and GET `auth/token/lookup-self`. All accepted tokens
must be renewable service tokens, have positive remaining TTL, and unlimited uses
(`num_uses=0`). Root tokens with unlimited lifetime and batch tokens are refused.
Login/renew replies carry `auth.token_type`; lookup carries `data.type`. These are
independently checked OpenBao fields. Token prefixes are opaque.

Renewal POSTs `{}` to `auth/token/renew-self` after half the returned TTL. Deadlines
are anchored before requests so network delay cannot extend validity. A failed
renewal drops the cached token and returns its typed failure; the next operation
reopens the credential file and authenticates again. Expiry also reauthenticates.
OpenBao Kubernetes renewal TokenReviews the original login JWT, so rotation of a
projected JWT may require a fresh login. OpenBao JWT renewal checks the current
role and TTL policy. Immediate credential reload replaces the adapter and evicts
KEKs with the existing `CacheInvalidation::CredentialReload` authority.

Credential targets must be regular, single-link, owned by the effective UID,
owner-only files of at most 8 KiB. Protected tokens reject symlinks; projected JWT
references allow AtomicWriter symlinks while checking the opened target on every
read. The supported hardened Kubernetes configuration uses one explicit shared
`runAsUser` so the projection is owned by that UID with mode 0600. Default 0644 and
fsGroup 0640 projections are refused. In reviewer-service-account mode, OpenBao's
reviewer needs TokenReview permissions; Positron's workload account does not need
that permission. Client-as-reviewer mode requires it on each workload account.

Each operation admits one caller with a 15-second deadline and one item per
request. The wire parser is bounded to 32 KiB; Wrapped Key Payload plaintext to
1 KiB. Encrypt pins `key_version` and supplies the verified Envelope Context
digest as both native derivation `context` and `associated_data`. No caller nonce
is supplied; OpenBao's native reviewed AES-GCM implementation generates it.
Metadata checks the exact name, selected version, derivation, convergence,
algorithm, allowed version range, capabilities, and `soft_deleted=false`. A newer
latest version does not change the selected version. Old envelopes can decrypt
after a higher minimum encryption version if the selected version still permits
decryption. Ciphertext must have the exact `vault:vVERSION:` prefix and canonical
bounded Base64 nonce/tag framing. The OpenBao source and published API explicitly
use that prefix. Unwrapped payloads independently verify instance, scope, child
key, epoch, format and purpose before acceptance.

Permissions are permanent failures; missing or wrong keys, receipt substitutions
and context errors fail closed. Explicit 429 throttling can retry once with numeric
Retry-After bounded to two seconds. Transport loss or server errors after encrypt,
login or renew are ambiguous and never replayed. Sealed/unavailable 503 is
retryable. Existing cache leases control outage use and expiry, with no provider
or plaintext fallback. Startup/recovery verify the live target; rotation and
migration use the existing verified session and multiple-envelope workflow.

Positron-owned JWT, token, request, response and decoded plaintext buffers have
bounded zeroizing ownership. They are never persisted or included in errors,
telemetry, diagnostics or bundles. This does not promise physical erasure inside
serde, TLS, allocators or operating-system buffers.

For a separately authorized real deployment, construct the admitted native
adapter with protected identity and pass
`ProviderConformanceTarget::new(ProviderFamily::OpenBaoTransit, "OpenBao",
"2.7.1 / Transit v1", ACTUAL_DEPLOYMENT)` to the existing
`KeyProviderConformance::healthy`, `outage`, `recovery` and
`rotation_and_migration` phases. The operator induces and restores outages and
pre-provisions rotation/migration keys outside Positron. The harness has no key
administration authority or executable callback. Tests use fixed independently
published-format replies, fictional credentials, and native TLS loopback. No live
OpenBao deployment, cryptographic acceptance or ambient credential discovery was
performed. Shared Crypto Backend frame known-answer vectors remain separate from
native provider acceptance.

The immutable primary sources independently checked are:

- [Encryption fields and receipts](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/builtin/logical/transit/path_encrypt.go), [decryption](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/builtin/logical/transit/path_decrypt.go), [key metadata](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/builtin/logical/transit/path_keys.go).
- [Ciphertext version template and native crypto](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/sdk/helper/keysutil/policy.go), [published API ciphertext examples](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/website/content/docs/api/secret/transit.mdx), [health fields](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/http/sys_health.go).
- [Auth response serialization](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/sdk/logical/translate_response.go), [native token lookup and renewal](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/vault/token_store.go), [token and namespace headers](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/api/client.go).
- [In-tree Kubernetes login and renewal](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/builtin/credential/kubernetes/path_login.go), [in-tree JWT login and renewal](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/builtin/credential/jwt/path_login.go), [authentication dependencies](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/go.mod).
