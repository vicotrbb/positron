# Use age v1 for local-key Recovery Bundles

A Recovery Bundle is an `age-encryption.org/v1` container whose inner payload is a deterministic, versioned Protobuf message containing the instance identity, local Root KEK, provider metadata, creation time, and integrity-key fingerprints. The Instance Integrity Key signs the payload before encryption. Release 1 supports one or more native age X25519 Recovery Recipients, any of which may recover the bundle, plus interactive age scrypt passphrase protection as a fallback. Passphrases are never accepted through arguments, environment variables, configuration, or logs. SSH recipients, external age plugins, and threshold secret sharing are excluded. Recipient rotation must create and verify a replacement bundle before retiring its predecessor, and inspection exposes only non-secret format, recipient, instance, and fingerprint metadata.

The inner payload retains canonical version 1 compatibility. Version 2 additionally
carries the original bootstrap root identity and a verified root-wrapped stable
system KEK envelope, allowing a successor local root to recover the existing
hierarchy without rewriting immutable encrypted content or changing the Instance
Integrity identity. Both versions use the existing signature purpose and native
age v1 container. The canonical fields, bounds and publication ordering are
specified in `docs/operations/local-key-recovery.md`.
