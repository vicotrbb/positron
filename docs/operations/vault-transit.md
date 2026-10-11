# Vault Transit

The native adapter targets **HashiCorp Vault Community 2.1.2**, Transit HTTP API
v1, official release commit
`76fdd6587523c4c6cb079635075e019714d23470`. Vault and OpenBao are independent
conformance targets. This adapter does not establish OpenBao compatibility.

Operators pre-provision a `derived=true`, `convergent_encryption=false`
`aes256-gcm96` key and select its exact positive version. Positron never creates,
rotates, exports, disables or destroys Vault keys. The canonical Provider Key URI
is `https://HOST[:PORT]/v1/MOUNT/keys/NAME` plus a separate canonical decimal
version. Nested mount paths are supported; aliases, escaped/normalized paths,
queries, fragments and noncanonical versions are rejected. Health receipts must
report initialized, unsealed, active Vault 2.1.2. Redacted or different versions
fail closed. Least privilege permits GET `sys/health`, read of this exact key,
update of its encrypt/decrypt paths, and the selected native authentication paths.
No namespace, proxy, redirect, insecure TLS or root-key lifecycle selector exists.

`VaultTransitKeyProvider::from_native` consumes the existing Security Lifecycle
resource reservation before opening any file or starting network work. It accepts
the existing `TransitAuthentication` model, the native authentication mount, and
an optional `CredentialFileReference` for additional public PEM CA roots. TLS
always checks certificate chains and hostnames. Public roots remain available;
the optional bundle is capped at 32 KiB and 16 certificates.
The bundle must be a no-follow regular, single-link file owned by root or the
process effective UID, with no group or other write permission; public read
permission is allowed because CA certificates are public. The provider retains
the grant until its bounded transport workers terminate. The shared native runtime
retains its existing DNS, HTTP, connection, file, response and task bounds.

Kubernetes and JWT authentication read the explicitly referenced projected JWT
and POST `{role,jwt}` to `auth/MOUNT/login`. Protected token files use an empty
authentication mount and GET `auth/token/lookup-self`. All accepted tokens must
be renewable service tokens with positive remaining TTL and unlimited uses
(`num_uses=0`). Root tokens with unlimited lifetime and batch tokens are refused.
Tokens are opaque; their prefixes are not interpreted. Renewal uses
`auth/token/renew-self` after half the returned TTL, with deadlines anchored before
the request so transport delay cannot extend validity. Expiry reopens the file
and performs native authentication again. Renewal rejection fails closed, drops
the cached token and returns a typed failure. To reload credentials immediately,
replace the adapter and invalidate the existing Key Provider Cache with
`CacheInvalidation::CredentialReload`; no second KEK lease authority is created.

Credential targets must be regular, single-link, owned by the process effective
UID, owner-only files of at most 8 KiB. Protected Vault token files reject
symlinks. Projected JWT references allow Kubernetes AtomicWriter symlinks while
checking the opened target and reopening after expiry. This supported hardened
Kubernetes setup requires all containers to share an explicit `runAsUser`, so
kubelet owns the service-account token by that UID with mode 0600. Default 0644
projections and fsGroup 0640 projections do not satisfy this custody policy.
References and selectors contain no credential values. Tokens, JWT buffers,
request bodies, response bodies and decoded plaintext use bounded zeroizing
ownership. This is a statement about Positron-owned buffers, not a guarantee of
physical heap erasure inside serde, TLS libraries, allocators or the operating
system. Errors, tracing and diagnostics expose no raw provider body or token.

Each operation admits one caller and has a 15-second deadline. The port submits
one item per request; it never submits native batches or accepts partial batch
success. Responses are bounded by the existing transport before the 32 KiB wire
parser. Plaintext payloads are at most 1 KiB. Encrypt requests pin `key_version`,
use the canonical Envelope Context digest as both native derivation context and
authenticated associated data, and omit `nonce`, leaving nonce generation to
Vault's reviewed native AES-GCM implementation. Successful ciphertext must have
the exact `vault:vVERSION:` prefix and canonical bounded Base64 nonce/tag framing.
The separate metadata receipt checks the exact name, version presence, key type,
derivation, convergence and allowed version range. A newer latest version does
not silently change the selected version. Unwrap remains possible after a higher
minimum encryption version, provided the selected version may still decrypt.
Every recovered canonical Wrapped Key Payload is independently verified for
instance, scope, key, epoch, format and purpose before the session accepts it.

Permission rejection is permanent; missing/wrong keys, receipt substitutions and
context errors fail closed. Explicit throttling can retry once, with bounded
numeric Retry-After (at most two seconds). Transport loss or server errors after
encrypt, login or renewal are ambiguous and never replayed. A sealed/unavailable
503 is retryable; no provider or plaintext fallback occurs. Existing Key Cache
Lease behavior controls KEK use during outages and expiry. Rotation, migration,
restart recovery, cache invalidation and encrypted frames retain their existing
Data Protection authorities.

For an explicitly authorized real target, create this native adapter with an
admitted grant and protected native identity, then pass
`ProviderConformanceTarget::new(ProviderFamily::VaultTransit, "HashiCorp Vault",
"2.1.2 / Transit v1", ACTUAL_DEPLOYMENT)` to the existing
`KeyProviderConformance::healthy`, `outage`, `recovery` and
`rotation_and_migration` phases. Use separately pre-provisioned pinned keys for
rotation and a supported destination for migration. The operator induces and
restores outages outside Positron; the harness has no executable callback or key
administration authority. Startup and recovery always verify the live provider.
Default tests use immutable published-format wire transcripts and fictional
loopback TLS identities. These are parser, routing, custody and lifecycle tests;
they do not constitute live Vault acceptance or native cryptographic validation.
No live infrastructure call or ambient credential discovery was performed.

Primary sources are the exact [release](https://github.com/hashicorp/vault/releases/tag/v2.1.2),
[Transit key metadata](https://github.com/hashicorp/vault/blob/76fdd6587523c4c6cb079635075e019714d23470/builtin/logical/transit/path_keys.go),
[native encryption](https://github.com/hashicorp/vault/blob/76fdd6587523c4c6cb079635075e019714d23470/builtin/logical/transit/path_encrypt.go),
[health receipts](https://github.com/hashicorp/vault/blob/76fdd6587523c4c6cb079635075e019714d23470/http/sys_health.go),
and [HTTP authentication serialization](https://github.com/hashicorp/vault/blob/76fdd6587523c4c6cb079635075e019714d23470/sdk/logical/translate_response.go).
The [Transit API](https://developer.hashicorp.com/vault/api-docs/secret/transit)
publishes the ciphertext wire example used by tests; the
[token API](https://developer.hashicorp.com/vault/api-docs/auth/token) and
[Kubernetes projected-volume security context](https://kubernetes.io/docs/concepts/storage/projected-volumes/#securitycontext-interactions)
describe the native renewal and supported token projection contract.
