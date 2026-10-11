# Use pre-provisioned external keys and native workload identity

External Root KEKs are pre-provisioned by operators. Positron may resolve an alias during initialization but persists an immutable version-pinned Provider Key URI; it may verify, wrap, unwrap, rewrap, and migrate its own envelopes, but Release 1 never creates, enables, disables, schedules deletion of, or destroys an external root key. AWS uses its standard credential chain and workload roles, Google Cloud uses Application Default Credentials and Workload Identity, Azure uses managed or workload identity, Vault and OpenBao use renewable machine tokens obtained through Kubernetes or JWT authentication or a protected token file, and KMIP uses mutually authenticated TLS. Configuration stores only non-secret selectors and protected credential-file references; provider-native environment or file credentials may be consumed but are never persisted, returned, or logged. External provider connections always require verified TLS with no insecure opt-out. Initialization performs a temporary context-bound wrap and unwrap probe, verifies the exact key identity and least-privilege capabilities, and zeroizes probe material without persisting it.

For the Release 1 KMIP 2.1 subset, the Provider Key URI locator selects an exact
server and opaque object identifier; its version is `sha256:` followed by the
64 lowercase hexadecimal digits of that symmetric key's Raw-format SHA-256
Digest attribute. The adapter requires that exact digest before every remote
cryptographic operation. An object identifier alone is insufficient: KMIP
Import with Replace Existing can replace material while retaining the identifier.
The trusted server's provisioning and administrative policy must permanently
prevent replacement or rebinding of each selected object during its use and
recovery lifetime. The client has only Discover Versions, Get Attributes,
Encrypt and Decrypt permission. Rotation creates a separate pre-provisioned
object and a new Provider Key URI, never replacement under the old identifier.
Digest verification detects prior substitution; it is not an atomic
conditional-encryption mechanism and cannot protect against a server or
administrator violating that immutability policy between requests. The existing
Envelope Context remains the sole payload-binding authority. The
[KMIP operations contract](../operations/kmip-21.md) specifies the supported
subset and its refused profile elements without claiming general KMIP profile
conformance.
