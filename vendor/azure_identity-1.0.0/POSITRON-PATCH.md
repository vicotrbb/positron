# Positron custody patch for azure_identity 1.0.0

Upstream: Microsoft Azure SDK for Rust, MIT license. The added LICENSE.txt
reproduces the upstream repository license, which the published archive omits.

- Official archive: https://static.crates.io/crates/azure_identity/azure_identity-1.0.0.crate
- Archive SHA-256: `32edf96b356ca7c51d7590c4925cc36efc3947a5da4468e8e0b25c56ecbb3de5`.
- Upstream Git commit: `c3c92ed4349125e25d176f13faa9ef016b790b3e`.
- Upstream path: `sdk/identity/azure_identity`.
- All 30 upstream archive files remain; modified files retain upstream headers.
- Eight originals are modified: Cargo.toml, src/app_service_managed_identity_credential.rs,
  src/client_assertion_credential.rs, src/env.rs, src/imds_managed_identity_credential.rs,
  src/lib.rs, src/managed_identity_credential.rs, and src/workload_identity_credential.rs.
  Added files are native.rs, LICENSE.txt and this provenance note.

This patch keeps the SDK's credential selection, identity protocol and refresh
semantics. Positron supplies bounded file and HTTP custody. Completed tokens and request bodies in the managed and projected-workload
paths selected by Positron use zeroizing owners. No external key lifecycle operation,
developer-tool fallback, alternative authentication authority, or cryptographic
algorithm is introduced by this patch.

The identity patch adds optional admitted native custody. It also passes the
App Service endpoint and identity selector from the SDK's actual source
selection to a caller-owned immutable endpoint capability, without duplicating
source selection. Presence checks zeroize temporary values and distinguish
absence from rejection, including oversized managed-identity environment values.
Unsupported source errors and selection order are preserved.

For the optional projected-token file runtime, callers that
supply it read through their admitted owner without launching an SDK file thread.
The upstream ten-minute projected-token cache remains. The core patch makes
owned Secret and SecretBytes storage zeroize when released. The identity patch
redacts native Entra and managed-identity response errors, checks token expiry
without panicking, and zeroizes rejected oversized environment values. Malformed
response errors omit provider-controlled field values.

Verification is performed by the owning Positron adapter tests and workspace
checks. This provenance note does not establish native deployment acceptance or
Azure Key Vault or Managed HSM conformance.
