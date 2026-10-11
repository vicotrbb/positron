# AWS KMS custody

`AwsKmsKeyProvider::from_standard_chain` opens the native AWS identity chain for
one immutable, pre-provisioned symmetric encryption key. Its `ProviderKeyUri`
contains the complete key ARN and the version `immutable`. Aliases and bare key
IDs are refused. The ARN selects the region and partition endpoint; callers
cannot substitute an endpoint. KMS requests use verified TLS and the official
AWS SigV4 signer through the internal Crypto Backend. The workload needs
`kms:DescribeKey`, `kms:Encrypt` and `kms:Decrypt` on that exact key, including
its encryption-context conditions. This adapter never provisions or deletes a
key, grants permissions, or changes AWS rotation settings.

Reserve `AwsKmsKeyProvider::required_resources()` through the existing governor
before constructing the provider. The transferred grant remains with the
provider, including its resident identity cache, HTTP client and credential
refresh. One operation runs at a time; competing operations fail with the
existing limit class rather than queue. Native DNS and child cleanup retain
that same grant after caller cancellation, until the worker terminates or the
direct child is reaped. The Tokio runtime must remain alive while these owners
reconcile. Dropping the provider releases its resident ownership; outstanding
native work releases its ownership only after completion. The separate shared KeyProvider cache continues to own admitted
plaintext leases and invalidation; this adapter introduces no plaintext cache
or alternate lease policy.

The official standard credential chain retains environment, profile, process,
SSO, web identity, ECS and EC2 workload sources. Prefer a workload role. Native
profile and token files are regular files bounded to 64 KiB. Native credential
process output is bounded to 64 KiB, stderr is discarded, and its direct child
has a five-second deadline and cancellation cleanup. The operator-selected
executable is trusted; the adapter does not claim to sandbox its descendants.
Credential HTTP bodies are bounded to 128 KiB. HTTP is allowed only when every
resolved address is loopback or an SDK workload metadata address; remote
identity and KMS use TLS. HTTP names are resolved once and the validated address
set is pinned for the actual connection, preserving the URL and Host. The SDK
still validates ECS endpoint selectors before the private transport accepts
them. All HTTPS clients also use the admitted resolver. One native resolver
lookup runs at a time, with at most sixteen returned addresses and a two-second
response deadline. Pinned Hickory 0.26.3 parses bounded DNS messages. It uses the
supported host's `/etc/resolv.conf` and `/etc/hosts`, each capped at 64 KiB,
with at most four name servers, six search domains and 512 host aliases; host
lines are capped at 1 KiB and names at 253 bytes. It does not load arbitrary NSS
plugins or Apple's dynamic split-DNS configuration. Its DNS cache is disabled,
attempt count is one, upstream request concurrency is one, CNAME depth is the
library's fixed eight, and at most four transport tasks may coexist. Each task
has a two-second deadline and carries the same original grant through actual
completion. A completed lookup drains its transport tasks before returning;
caller cancellation retains the occupied slot while those tasks reconcile.
Redirects, ambient HTTP proxies and idle connection pools are disabled. SDK
events are suppressed inside identity and request futures; returned errors are
closed Positron failure classes without provider messages or credentials.

KMS requests are bounded to 16 KiB and responses to 32 KiB. The native
encryption context binds the canonical Positron context digest and wrapping
purpose. Both responses and envelopes must identify the exact key ARN and
`SYMMETRIC_DEFAULT` before plaintext transfer. Application-owned plaintext and
native JSON buffers use zeroizing ownership. AWS SDK and TLS library internals
retain their upstream memory behavior; this is not a claim that those libraries
provide a certified zeroizing module or FIPS validation.

The fixed native admission budget is 32 MiB, including resident SDK/client
ownership and refresh peaks. The native environment reader retains the official
SDK implementation. Supported Linux and macOS process-launch limits bound its
initial strings; Positron does not mutate the process environment. The pinned
SDK's environment provider reads the access key, secret, token and account ID
sequentially; token/account trimming can briefly retain one original and one
copy. Linux bounds an individual exec string to 32 pages and the aggregate to
three quarters of `_STK_LIM` (six MiB on supported architectures), while macOS
caps the aggregate at at most one MiB. The budget covers the resulting native
copies before the adapter's stricter credential field limits, as well as bounded
files, HTTP buffers, DNS records and task ownership. Arbitrary external code
mutating that environment is outside the supported process composition.

Native identity refresh has a fifteen-second deadline and at most two SDK
attempts. KMS transport has a fifteen-second deadline and at most two attempts,
with a bounded 100 ms delay only after an explicit retryable rejection.
Throttle and known service outages are retryable. Wrong key, context and
permission failures are closed failures. Recognized `InternalFailure` and
`RequestTimeoutException` are retryable native outages. Missing, malformed or
unrecognized error codes with HTTP 500, 502, 503 or 504 are unavailable for
DescribeKey and Decrypt, and ambiguous for Encrypt. An uncertain Encrypt
transport result or server reply is not automatically retried. Recognized key,
context and denial codes remain authoritative regardless of status.

Envelope rotation and migration use the existing authenticated unwrap, rebuild,
wrap and verification owner. AWS `ReEncrypt` cannot rewrite the source-bound
context digest embedded in the canonical plaintext payload. Additive destination
envelopes and Catalog epochs retain their existing authority. Recovery verifies
the selected envelope and its context through the same owner; neither provider
availability nor a successor envelope authorizes predecessor retirement.
Opaque and unknown backup references continue to block retirement.

For a real AWS acceptance run, an operator explicitly constructs this provider
with a governor grant and invokes `KeyProviderConformance::healthy`, then the
existing outage, recovery, and rotation-and-migration methods against
pre-provisioned keys. The caller supplies the target identity and workload
credentials and controls the actual outage. Default repository tests never
discover a target from ambient environment or contact AWS. Published wire
fixtures and local identity-boundary tests are unit contracts, not an AWS
emulator or evidence of live service acceptance.

The wire fixtures follow AWS's [DescribeKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html),
[Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html),
and [Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html)
contracts and [KMS common errors](https://docs.aws.amazon.com/kms/latest/APIReference/CommonErrors.html).
Server-status fallback follows [AWS retry classifications](https://docs.aws.amazon.com/sdkref/latest/guide/feature-retry-behavior.html),
with the existing Encrypt ambiguity policy retained. Complete ARNs also pin the region of
[multi-Region keys](https://docs.aws.amazon.com/kms/latest/developerguide/mrk-how-it-works.html);
an interchangeable replica does not substitute for the selected ARN.
Partition suffixes and region grammar follow the [pinned official KMS endpoint table](https://github.com/awslabs/aws-sdk-rust/blob/7101aefb7632e44cce586886a1df595151409b5f/sdk/kms/src/endpoint_lib.rs),
including the AWS European Sovereign Cloud partition.

Native copy accounting follows the [pinned SDK environment provider](https://github.com/awslabs/aws-sdk-rust/blob/653085fbbc4a50138cf955445b65431bea3599d4/sdk/aws-config/src/environment/credentials.rs),
the [Linux exec bounds](https://github.com/torvalds/linux/blob/v6.18/fs/exec.c),
and [macOS argument limits](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/syslimits.h).

Application Design §4.11 keeps the asynchronous Key Provider port inside Data
Protection and places rotation and migration in its existing owner. Section 5
classifies AWS as a concrete external adapter; §6.1 requires Data Protection to
verify configured provider identity and context during recovery. This change
implements that port and the existing conformance target, without adding an
independent runtime scheduler or lifecycle authority. The caller-owned Tokio
runtime executes refresh and cleanup. The public integration test exercises an
actual isolated native credential-process failure before HTTP, then releases
the provider grant before tearing down that runtime. Native cancellation tests
also drive cleanup to confirmed resource reconciliation before runtime teardown.
