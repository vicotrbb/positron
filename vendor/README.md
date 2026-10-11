# Bounded native AWS identity seams

These packages are the published `aws-types` 1.6.0 and `aws-config` 1.12.0
sources, with their Apache-2.0 licenses retained. Upstream source revision is
`653085fbbc4a50138cf955445b65431bea3599d4`, paths `sdk/aws-types` and
`sdk/aws-config`. Published archive SHA-256 values are:

| Package | SHA-256 |
| --- | --- |
| aws-types 1.6.0 | `209f3a6d82a6e9e5f94abbed94c7a26e1c052341002bf57a5fb5481f625896fc` |
| aws-config 1.12.0 | `b8d7b388a9fc3a6db15a5ec778c38b354eff1364882c94d08e0252f7a47dcaa4` |

Cargo patches only these packages. Registry metadata, duplicate original
manifests and upstream lockfiles are omitted. Positron changes are confined to
the manifests, `aws-types/src/os_shim_internal.rs`, and the following
`aws-config` sources: `credential_process.rs`, `provider_config.rs`,
`ecs.rs`, and `profile/credentials/exec.rs`.

The SDK exposes no public reader override covering every standard-chain file.
The real reader therefore validates the opened descriptor as a regular file,
reads at most 65,537 bytes and refuses input above 64 KiB. Unix uses nonblocking
open to avoid waiting on a FIFO; other platforms retain regular-file validation.
Symlink projections remain supported because validation applies to the opened
file. Rejected collected bytes use `Zeroize`.

The process provider retains the upstream native command invocation and chain
position. It replaces unbounded `Command::output` with bounded zeroizing stdout,
null stderr, a five-second deadline, kill-on-drop, and explicit direct-child
kill/reap on failure. Failure messages do not contain commands, output or parser
details. A narrow admission hook carries the original Positron resource owner
from before spawning through confirmed reaping. Cancellation transfers it to
one cleanup task, and replacement processes are refused until cleanup finishes.
The owning Tokio runtime must remain alive through reconciliation; forced runtime
shutdown is not a process cleanup guarantee. Process internals and descendant sandboxing remain operator authority.
Focused native provider tests cover size refusal, stderr redaction, timeout,
and cancellation cleanup.

Provider configuration carries the same admitted DNS resolver into native ECS
selector validation, including profile-based ECS sources. The private transport
resolves HTTP aliases, checks every address, and pins the validated set for the
actual connection. HTTPS also uses this resolver. These hooks preserve the
standard chain's source selection and avoid an independent default DNS worker.

The generated KMS SDK serializers do not promise zeroization of plaintext Blob
and JSON copies. Positron instead uses a small native KMS JSON codec with
zeroizing application buffers, the unchanged official identity chain and
official SigV4 signer. This does not replace authentication or cryptographic
primitives. The bounded private HTTP connector is only the transport for that
chain and KMS operations. See [AWS custody](../docs/operations/aws-kms.md) for
limits and the explicit real-target conformance workflow.
