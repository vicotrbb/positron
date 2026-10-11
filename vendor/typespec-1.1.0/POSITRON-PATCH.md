# Positron custody patch for typespec 1.1.0

Upstream: Microsoft Azure SDK for Rust, MIT license.

- Official archive: https://static.crates.io/crates/typespec/typespec-1.1.0.crate
- Archive SHA-256: `753a2fe021e407d4fc9ee6f4f0a33403cc306d5c54c4e4ebe1b8cbde0ca052b9`.
- Upstream Git commit: `9a8a5f7bdb986e4c3ba230ad26b99996aae467d9`.
- Upstream path: `sdk/core/typespec`.
- All 14 published archive files are retained, including original source headers.
  Two originals are modified: Cargo.toml and src/http/headers.rs.

The only source change adds zeroization on release to owned HeaderValue strings.
Azure identity request headers and their SDK retry copies therefore retain
zeroizing ownership. Static borrowed header constants are unchanged. Cargo.toml
adds the pinned zeroize dependency. The added LICENSE.txt reproduces the
upstream repository MIT license omitted by the published archive.

This patch does not change identity selection, retry policy, HTTP semantics,
cryptography, or provider lifecycle. Adapter and workspace tests verify the
owning product; this note is not a live deployment acceptance claim. TLS, HTTP
and serde scratch retain their library memory behavior.
