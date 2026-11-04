# Publish six generated SDKs as one release set

Release 1 generates and publishes Rust, TypeScript, Python, Go, Java/JVM, and .NET SDKs from the canonical API definition to their standard registries. The server and every required SDK share one release version, API version, and schema digest; generation is pinned, generated wire code is never hand-edited, and each package must compile and pass the same live conformance suite. A signed release-set manifest records artifacts, checksums, generator versions, and publication state, and a release is not announced complete until failed registry publications resume successfully at the same version.

The Rust publication workspace is `sdk/rust`. Native Cargo generation copies the
canonical Public Interface adapters and tests, embeds the API Definition and
its Schema Digest, and retains pinned generator inputs. A separate library
package has no dependency on server-domain crates. Release Trust inspects the
actual Cargo archive, embedded definition/digest, package/API/registry identity,
pinned generator metadata, and clean source identity before accepting it in the
existing signed inventory. SPDX/CycloneDX, provenance, independent payload bytes,
crates.io native evidence, signatures, revocation, and complete-set requirements
remain in that same owning verification path. Private test identities establish
verification behavior, not publication or release evidence.

The TypeScript publication workspace is `sdk/typescript`. The Rust Public
Interface generator emits its HTTP wire types, exclusive Protobuf oneofs,
canonical descriptor and schema metadata, bounded transport, query delivery
helpers, and package identity. Compiler inputs are locked and the package has
no runtime dependencies. TypeScript's adapter executes generated bindings;
server policy and canonical error/retry metadata remain Rust-owned. Native npm
package inspection authenticates the embedded API definition, digest, source
commit, exports, version, generator and registry identity under the same Release
Trust path. The npm Sigstore provenance profile, SBOMs, independent rebuild,
signatures, revocation and Release Manifest remain the existing authorities.
Private fixture identities and local package tests do not establish publication.
