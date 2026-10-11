# Positron retained RSA private-state ownership patch

Upstream: ring 0.17.14, crates.io published archive SHA-256
`a4689e6c2294d81e88dc6261c768b63bc4fcdb852be6d1352498b114f61383b7`.
The original Cargo.toml.orig and upstream licenses are retained.

The compiled manifest adds the already-pinned zeroize 1.9.0 dependency under
ring's existing `alloc` feature. Four source files change ownership cleanup:

- `src/arithmetic/bigint/boxed_limbs.rs` guards heap limb storage with
  `Zeroizing<Box<[Limb]>>`, including failed parses and cloned arithmetic owners.
- `src/arithmetic/bigint/private_exponent.rs` retains that same guarded ownership
  through the existing `into_limbs` transfer.
- `src/arithmetic/n0.rs` implements `Zeroize` for the inline Montgomery inverse.
- `src/arithmetic/bigint/modulus.rs` clears that retained inverse when an
  `OwnedModulus` drops; its heap modulus drops through the guarded limb owner.

RSA key pairs retain private primes, CRT exponents, CRT inverse and Montgomery
values through these owners. Arithmetic, algorithms, ABI and upstream unsafe
implementation are unchanged. Public arithmetic limbs also receive cleanup.
The existing Crypto Backend remains the sole Positron cryptographic authority.

The guarantees follow the reviewed zeroize ownership types and the complete
parsed-key ownership graph. Published positive RSA signatures and malformed-key
failure tests validate unchanged public behavior. They do not inspect freed
heap memory or certify erasure of every transient stack or library allocation.

The pinned Rust 1.96 compiler also requires nine explicit elided-lifetime
annotations in `polyfill/slice/as_chunks.rs`, `polyfill/slice/as_chunks_mut.rs`,
`arithmetic/bigint/modulus.rs`, `arithmetic/limbs512/storage.rs`, `pkcs8.rs` and
`rsa/public_modulus.rs`. These declaration-only compatibility changes retain
exactly the same lifetimes and avoid suppressing upstream warnings.
