# KMIP 2.1

`Kmip21KeyProvider` implements a bounded Positron client subset of the OASIS
KMIP 2.1 OS binary TTLV protocol. It uses a pre-provisioned symmetric AES-256
key for remote AES-GCM encryption and decryption of canonical Wrapped Key
Payloads. This contract describes the accepted protocol subset. It does not
claim general KMIP compatibility, full Basic Cryptographic Client profile
conformance, or acceptance of a particular server deployment.

The canonical Provider Key URI is `kmip://HOST[:PORT]/objects/OBJECT_ID` with
the separate version `sha256:HEX_DIGEST`. Port defaults to 5696. OBJECT_ID is
an exact opaque identifier of 1–256 ASCII letters, digits, hyphens, underscores
or dots, excluding `.` and `..`. The fingerprint contains exactly 64 lowercase
hexadecimal digits from the server's Raw-format SHA-256 Digest attribute.
Aliases, percent escapes, normalized paths, user information, queries,
fragments, extra path components and noncanonical versions are refused.
The endpoint and fingerprint are included in the existing canonical Envelope
Context. No separate key-version or context authority exists.

Operators must establish a trusted server policy that prevents replacement or
rebinding of the selected object for its entire use and recovery lifetime.
KMIP Import with Replace Existing can otherwise replace material under the same
identifier. The client must have only the four operations below for its selected
object, with no lifecycle or import permission. Administrative policy must also
prevent other identities from replacing that object. Rotation provisions a
different object and preserves the old object for recovery. The metadata digest
detects an earlier substitution, but Get Attributes and Encrypt/Decrypt are
separate requests: the protocol cannot atomically assert that the fingerprint
still matches at execution. A dishonest server or racing administrator that
violates this provisioning contract is outside the accepted trust model. No
invented introspection or post-operation check proves that administrative policy.

| Operation | Supported request and required response |
| --- | --- |
| Discover Versions (`0x1E`) | Request only version 2.1; require exactly that version. No downgrade or alternate version negotiation. |
| Get Attributes (`0x0B`) | Exact Unique Identifier and references to Object Type, Cryptographic Algorithm, Cryptographic Length, Cryptographic Usage Mask, State and Digest. Require matching identifier, Symmetric Key, AES, 256 bits, Encrypt and Decrypt usage, and one complete Raw/SHA-256/32-byte digest matching the pinned fingerprint. |
| Encrypt (`0x1F`) | AES/GCM, IV Length 96 bits, Tag Length 16 bytes, Random IV true, canonical payload as Data and the full canonical Envelope Context as Authenticated Encryption Additional Data. Require matching identifier, equal-length Data, 12-byte IV and 16-byte authenticated tag. |
| Decrypt (`0x20`) | Same parameters, stored IV and tag, opaque ciphertext Data and full canonical Envelope Context as additional data. Require matching identifier and a bounded canonical plaintext payload whose embedded context matches independently. |

Probe and wrapping require Active state. The native decrypt port also accepts
Deactivated state, as KMIP permits, but the shared session's capability probe
requires an Active object before unwrap, recovery or migration. An operator
therefore keeps old objects Active while they remain required for recovery.
The usage mask may include other server-side permissions, but Positron never
requests or implements them; operators apply least privilege independently.

Every other KMIP operation is refused by omission: Create, Create Key Pair,
Register, Rekey, Derive Key, Certify, Recertify, Locate, Check, Get, Get Attribute
List, Add/Modify/Delete Attribute, Obtain Lease, Get Usage Allocation, Activate,
Revoke, Destroy, Archive, Recover, Validate, Query, Cancel, Poll, Notify, Put,
Rekey Key Pair, Sign, Signature Verify, MAC, MAC Verify, RNG Retrieve, RNG Seed,
Hash, Create Split Key, Join Split Key, Import, Export, Log and any later or
vendor-defined operation. No external plaintext Root KEK is obtained, exported,
persisted or logged. Key lifecycle, aliases, delegation and server policy
administration have no Positron API in Release 1.

The client uses TLS 1.3 with `TLS_AES_256_GCM_SHA384`, verified certificate chain
and hostname, and a native client certificate/private key. TLS 1.2 and earlier,
anonymous authentication, username/password credentials, HTTP/JSON/XML
bindings, insecure TLS, early data, session resumption, proxy and redirect
selection are refused. This TLS 1.3 client choice satisfies the applicable
Basic Authentication client transport clauses (§3.1.1–3.1.2); it is not a claim
that a server satisfies its different mandatory cipher requirements or that
the client satisfies every Baseline or Basic Cryptographic profile requirement.
Other cryptographic algorithms, block modes, RSA wrapping, opaque server
references, streaming/correlated cryptographic sequences, alternate object
types, wrapped key exports, additional digest instances and extension fields
are outside this subset.

`Kmip21KeyProvider::from_native` consumes the existing Security Lifecycle
reservation before files, DNS or network work. Pass `required_resources()` to
the existing resource authority and the existing
`ProviderCredentialModel::KmipMutualTls` containing protected certificate,
private-key and trust-root file references. PEM files are limited to 32 KiB
each, certificate chains and private CA bundles to 16 certificates. All files
are opened without following symlinks and with nonblocking semantics, and must
be regular single-link files. Identity files must belong to the effective UID
with owner-only permissions. CA bundles may belong to root or that UID with no
group/other write permission; public read is permitted. Public trust roots are
retained alongside the explicit bundle. The selected files are reopened for
every operation; replacement credentials are verified before transport. To
invalidate cached KEKs immediately, use the existing
`CacheInvalidation::CredentialReload` and replace the adapter if selectors change.
Positron-owned PEM, request, response and plaintext buffers have bounded
zeroizing ownership. Native TLS owns the parsed private-key identity. This does
not assert physical heap erasure inside TLS, allocators or the operating system.

Each admitted operation has one caller, a 15-second deadline, one fresh TLS
connection, and a single synchronous item per request. TTLV records are bounded
to 8 KiB before allocation; at most 32 fields per known structure are parsed,
with checked lengths, scalar types, zero padding and UTF-8 text. Canonical
plaintext is at most 1 KiB. Multiple batches, asynchronous Pending/Undone,
batch correlation IDs, unsupported fields or extensions, duplicate attributes,
missing receipts and malformed or truncated frames fail closed. Successful
responses must not contain Result Reason or Result Message; failed responses
require Result Reason and must not contain a payload. Server messages are
validated only as bounded text and are never exposed in errors or telemetry.
The envelope's opaque ciphertext framing is version byte 1, 12-byte IV,
16-byte tag, then ciphertext. IV generation and uniqueness across restarts are
the trusted server's native GCM responsibility: Random IV is always requested;
Positron has no local nonce generator or counter for this external key.

No request is automatically retried. Before Encrypt submission, transport
failure is `Unavailable`; after submission, lost transport or deadline is
`Ambiguous` and must not be replayed. Decrypt/read-only transport loss is
`Unavailable`. Explicit server temporary-failure reasons are `Unavailable`,
capacity reasons `LimitExceeded`, missing/replaced key receipts `WrongKey`,
invalid context/parameter receipts `ContextMismatch`, and unsupported or
denied capabilities `PermissionDenied`. Malformed framing is `ContextMismatch`
or `LimitExceeded`; bad native selectors or files are `InvalidConfiguration`
or the applicable custody failure. A caller may attempt a new read-only request
after restoring the provider, but there is no provider/plaintext fallback.

The existing `KeyProviderSession`, `KeyProviderCache`, typed `KeyCacheLease`,
rotation, migration, frame encryption and recovery workflows are reused.
Cached KEKs remain usable only within their configured lease and only where
the existing workflow permits it; startup/recovery and creation of new wrapping
material verify the live provider. Expiry, explicit invalidation and drop
zeroize cached material. Rotation/migration create and verify a new envelope
using a separately pre-provisioned pinned key while retaining the source.
No credential is copied into backups, bundles, diagnostics or crash artifacts.

For an explicitly authorized real deployment, instantiate this native adapter
and pass `ProviderConformanceTarget::new(ProviderFamily::Kmip21, ACTUAL_SERVICE,
"KMIP 2.1 / Positron AES-GCM subset", ACTUAL_DEPLOYMENT)` to the existing
`KeyProviderConformance::healthy`, `outage`, `recovery` and
`rotation_and_migration` phases. Operators verify the immutable-object policy,
native Random-IV guarantee, pre-provisioning and least privilege separately;
the harness checks observable wrap/unwrap/context/failure behavior and cannot
prove administrative policy. Induce/restore outages outside Positron and select
a separate pinned destination. There is no executable callback or new runner.

Default tests use actual mutual-TLS loopback with fictional identities and
immutable specification-derived replies. They test public wire, identity,
custody, bounds and context outcomes, not a dynamically stateful KMIP emulator.
The published ciphertext and tag from the OASIS
[CS-BC-M-GCM-2-21 case](https://docs.oasis-open.org/kmip/kmip-profiles/v2.1/os/test-cases/kmip-v2.1/mandatory/CS-BC-M-GCM-2-21.xml)
for `$UNIQUE_IDENTIFIER_13` (AES-256, all-zero public key/IV, 16-byte zero data)
exercise rejection of ciphertext for the wrong payload length. They do not
claim that those bytes encrypt a Positron payload or that all mandatory KMIP
test cases ran. Existing reviewed CryptoBackend vectors validate local frame
cryptography; no custom cryptographic implementation is introduced. The
existing envelope fuzz target also exercises untrusted bounded TTLV and native
payload decoding. No live KMIP or other provider infrastructure was contacted.

The authoritative references are the
[KMIP 2.1 OS specification](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html)
(§4.16 cryptographic parameters, §4.21 Digest, §5 attributes, §6 operations,
§8 messages, §9 fields, §10 binary TTLV and §11 tags/enumerations) and the
[KMIP 2.1 OS profiles](https://docs.oasis-open.org/kmip/kmip-profiles/v2.1/os/kmip-profiles-v2.1-os.html).
