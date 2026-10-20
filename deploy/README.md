# Distribution surfaces

[Native archives](native/README.md) package the unchanged Positron executable,
generated Configuration Contract, license, and native service examples for Linux
x86_64/aarch64 and macOS x86_64/aarch64. Construction uses `positron release
archive`; the canonical release inventory and trust verifier bind signing,
checksums, SBOMs, provenance, and independent rebuilds.

Every surface uses the same Positron artifact and storage format. OCI, packages,
Compose, Nix, Helm, Kubernetes and other surface implementation tickets must not
introduce their own database behavior.
