# Distribution surfaces

[Native archives](native/README.md) package the unchanged Positron executable,
generated Configuration Contract, license, and native service examples for Linux
x86_64/aarch64 and macOS x86_64/aarch64. Construction uses `positron release
archive`; the canonical release inventory and trust verifier bind signing,
checksums, SBOMs, provenance, and independent rebuilds.

[Linux packages](linux/README.md) use native Debian and RPM package managers,
preserve the common GNU executable and generated contract, and add an explicit
systemd lifecycle with retained data and keys.

[Homebrew](../docs/operations/homebrew.md) derives its formula from the canonical
Release Inventory, installs the macOS archives unchanged, and runs an explicit
user LaunchAgent with retained configuration, data and keys.

Every surface uses the same Positron artifact and storage format. OCI, packages,
Compose, Nix, Helm, Kubernetes and other surface implementation tickets must not
introduce their own database behavior.
[Nix](nix/README.md) provides a locked source flake, packages and development
shells for all four native targets, configuration checks, and a NixOS module
with a VM lifecycle check. Its runbook covers trust, initialization, service,
upgrade and recovery.

[Standalone Helm](helm/README.md) generates a deterministic same-image chart
from the Release Inventory. It runs one restricted StatefulSet with separate
retained data/key/repository PVCs, native configuration, strict TLS probes and
explicit offline operation hooks; it does not require the Operator.
