# Positron custody patch for azure_core 1.0.0

Upstream: Microsoft Azure SDK for Rust, MIT license. The added LICENSE.txt
reproduces the upstream repository license, which the published archive omits.

- Official archive: https://static.crates.io/crates/azure_core/azure_core-1.0.0.crate
- Archive SHA-256: `fe6a26a7d374b440015cbbcbf2d9d8be5a133aa940599f5e5dc569504baa262e`.
- Upstream Git commit: `c3c92ed4349125e25d176f13faa9ef016b790b3e`.
- Upstream path: `sdk/core/azure_core`.
- All 52 upstream archive files remain; modified files retain upstream headers.

This patch keeps the SDK's credential selection, identity protocol and refresh
semantics. Positron supplies bounded file and HTTP custody. Completed tokens and request bodies in the managed and projected-workload
paths selected by Positron use zeroizing owners. No external key lifecycle operation,
developer-tool fallback, alternative authentication authority, or cryptographic
algorithm is introduced by this patch.

The identity patch adds an optional projected-token file runtime; callers that
supply it read through their admitted owner without launching an SDK file thread.
The upstream ten-minute projected-token cache remains. The core patch makes
owned Secret and SecretBytes storage zeroize when released. The identity patch
redacts native Entra and managed-identity response errors, checks token expiry
without panicking, and zeroizes rejected oversized environment values. Malformed
response errors omit provider-controlled field values.

Verification is performed by the owning Positron adapter tests and workspace
checks. This provenance note does not establish native deployment acceptance or
Azure Key Vault or Managed HSM conformance.
