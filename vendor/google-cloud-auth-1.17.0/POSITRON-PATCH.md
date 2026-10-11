# Positron patch to google-cloud-auth 1.17.0

This directory starts from the published `google-cloud-auth` 1.17.0 crate, not a
replacement ADC implementation. The original Apache-2.0 SPDX package metadata, copyright/license headers,
and upstream files remain included. The published archive does not contain a
standalone license text; `LICENSE` is added from the official upstream root at
the same pinned VCS commit.

- Published archive: `https://static.crates.io/crates/google-cloud-auth/google-cloud-auth-1.17.0.crate`
- Archive SHA-256: `ac9870b8ea484519aa8601e14886f2efc148ea490034e43d04bef1d246170cc9`
- Published VCS commit: `373bb9cc698f45e1f63e41beef090924af2ac2a4`, upstream path `src/auth`.
- Upstream repository: `https://github.com/googleapis/google-cloud-rust`.
- Added license source: `https://github.com/googleapis/google-cloud-rust/blob/373bb9cc698f45e1f63e41beef090924af2ac2a4/LICENSE`.
- Added license SHA-256: `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`.

The patch adds an explicit `Arc<dyn native::Runtime>` to the existing official
ADC builder and propagates it through accepted source credentials and token
providers. The embedding caller owns file reads, HTTP, executable output,
SHA-256, HMAC-SHA-256, RSA signing, and refresh-task admission. Positron supplies
this owner from its existing resource governor, caller runtime, transport, and
CryptoBackend. No global or task-local hook is installed.

The original ADC precedence and credential dispatch remain authoritative:
explicit ADC file, well-known ADC file, then metadata; authorized user, service
account, impersonated service account, and external account. File, URL,
executable, and AWS external subject sources retain their official selection
and opt-in rules. Accepted impersonation sources receive the same owner;
upstream rejection of an impersonated source in another impersonation config
remains. GDCH remains outside ADC. Its changed lines only adapt the shared
private STS token DTO. ID-token providers only adapt private Token ownership
handoffs and private test DTO constructors; they do not gain a native runtime. Native `build_signer` fails explicitly before credential
lookup; Positron's Cloud KMS adapter needs access-token credentials.

Without an injected owner, the existing upstream I/O, cryptography, refresh,
and builder selection paths remain available. Private token cleanup and Debug
redaction also apply to those paths. Public access-token and subject-token
construction/trait interfaces retain their string handoffs. SubjectToken's
private token field now clears on drop and its Debug output is redacted.

The native path keeps the existing refresh-cache behavior and admits its task
through the owner. The task retains that owner through its actual destruction;
closing the last credential receiver cancels refresh. One private timeout wraps
the complete token-provider future at 15 seconds, including a multi-step
federation/impersonation refresh. The owner's HTTP/process implementation must
retain admission until actual dispatcher/DNS/process cleanup finishes, even
when a caller or the SDK timeout drops its future.

## Bounded buffers and secret ownership

Native input and HTTP response bodies are capped at 128 KiB. Native JSON is
prevalidated before constructing a Value tree: at most 2048 values, depth 32,
and 128 KiB of aggregate string/key bytes. The no-tree pass rejects malformed
syntax, invalid numbers, and duplicate object keys; its owned temporary keys
clear on drop. Completed Value trees use the private SecretJson guard, which
clears strings and keys on success, error, or cancellation. Native impersonation
moves its source subtree under this guard instead of cloning a whole source
credential tree into an intermediate DTO.

Private completed client-secret, refresh-token, private-key, access-token,
subject-token, AWS secret/session-token, URL-header-value, executable-command,
and executable-argument fields use existing Zeroizing owners or explicit Drop
cleanup. Completed field values therefore clear on partial DTO failure as well
as ordinary destruction. Cached Token copies clear their token, token type,
and metadata. Form values, serialized request bodies, request URLs, formatted
Bearer/Basic text, decoded response text, and AWS signing intermediates retain
zeroizing ownership. Debug output and native errors omit their secret contents;
native typed status/admission/decode failures retain their safe error source.

These guarantees concern the owned fields/buffers above. They do not assert
that serde's internal untagged-enum/scratch copies, immutable HeaderValue
storage, reqwest/hyper/TLS copies, allocator history, stack/register scratch,
standard-library process argv/environment buffers, or upstream no-owner
transport buffers erase. The JSON/body/input caps bound
native application-owned data; the embedding transport and backend own their
separate limits. Native top-level quota override, ADC selector, HOME/APPDATA root, and metadata-host
values are checked against 4 KiB before provider/header or path/URL copies.
The metadata client captures its host once and reuses the bounded client in its
provider. Raw standard-library environment retrieval still allocates before
that safe length check; this is not an injected bounded environment-reader API.

## Logical copy inventory

This inventory is about source ownership, not an allocator measurement or a
claim that a reservation enforces allocation automatically.

- Each native file/response starts with one guarded raw body, at most 128 KiB.
  The prevalidation key set is destroyed before the Value tree is constructed.
  One accepted tree owns at most 2048 values and 128 KiB of string/key bytes.
  Container capacity must be added separately; string bytes alone are not a
  tree-memory estimate.
- User/service account construction has one tree and one decoded private DTO;
  its secret fields move into the provider/generator rather than creating an
  additional provider copy. A user refresh clones its two retained secret
  fields once into a guarded OAuth request. Their aggregate source bytes are
  bounded by the admitted config.
- Native impersonation has one source subtree, moved from its guarded parent,
  and one DTO containing the remaining metadata. Source construction does not
  clone that subtree. The accepted official ADC graph has at most two cache
  providers: the source and target. External-to-IAM exchange occurs in the
  external provider, not a third cache.
- External config construction retains one config and clones its selected
  credential source once for the provider. Common config fields are not cloned
  again. Secret client fields and header/command/argument copies retain their
  guards. Serde's untagged source-enum intermediate is an opaque parser copy.
- Each refresh HTTP stage has one request, plus one request clone where the
  existing retry loop uses try_clone. STS form values add one guarded parameter
  map. JSON serialization can expand a string by six times and form encoding
  by three times before the post-serialization body cap rejects it; account for
  that transient expansion rather than counting only the accepted wire body.
- Each decoded HTTP response has one guarded raw body, one guarded tree, and
  one private response DTO. Secret DTO bytes are bounded by that tree's
  aggregate strings. A successful token moves into the cache. The watch cache
  retains one token; refresh can hold the replacement token concurrently, and
  each requesting future obtains one token clone before its public handoff.
- AWS signing retains guarded canonical headers/request, the string to sign,
  derived keys, signature, and serialized subject token. Native AWS secret and
  session environment values are individually checked against 128 KiB; region
  is checked against 4 KiB. A percent-encoded subject can temporarily occupy
  three times the capped serialized JSON before its own limit rejects it.

Positron's memory reservation must include these containers, transient encoding
expansions, simultaneous SDK/request tasks, transport buffers, and parsed
backend key ownership. The native process also inherits the parent
environment through the standard process launcher; its internal argv and
environment copies belong to that launcher and the child, not these guards.
The figures above are inputs to that calculation, not a
complete 64 MiB physical-heap proof for opaque libraries.

## Exact archive delta

Of 67 original regular files, 43 are byte-identical and 24 are changed. No
original file is omitted. Added files are `src/native.rs`, this provenance note, and the official
upstream `LICENSE` text. The changed original files are:

- `Cargo.toml`
- `src/credentials.rs`
- `src/credentials/external_account.rs`
- `src/credentials/external_account_sources/aws_sourced.rs`
- `src/credentials/external_account_sources/executable_sourced.rs`
- `src/credentials/external_account_sources/file_sourced.rs`
- `src/credentials/external_account_sources/url_sourced.rs`
- `src/credentials/gdch.rs`
- `src/credentials/idtoken/impersonated.rs`
- `src/credentials/idtoken/mds.rs`
- `src/credentials/idtoken/service_account.rs`
- `src/credentials/idtoken/user_account.rs`
- `src/credentials/impersonated.rs`
- `src/credentials/internal/sts_exchange.rs`
- `src/credentials/mds.rs`
- `src/credentials/service_account.rs`
- `src/credentials/subject_token.rs`
- `src/credentials/user_account.rs`
- `src/errors.rs`
- `src/headers_util.rs`
- `src/lib.rs`
- `src/mds/client.rs`
- `src/token.rs`
- `src/token_cache.rs`

The package manifest adds zeroize with alloc/serde support and serde_urlencoded
for the private native adapter. Unchanged upstream files are not counted as
Positron implementation. Validate native public outcomes through the kernel's
Google tests, including isolated fictional ADC inputs and bounded fixture
transports. These are regression fixtures, not Google Cloud conformance
results; real-target conformance remains the operator harness's responsibility.
