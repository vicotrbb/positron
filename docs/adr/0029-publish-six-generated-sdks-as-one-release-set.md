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

The Python publication workspace is `sdk/python`. The same Rust Public Interface
metadata owner emits typed Python requests/results, canonical wire validation,
bounded HTTPS and query delivery helpers. The package requires Python 3.11 or
later and has no runtime dependencies. Pinned setuptools tooling creates the
pure Python wheel; native PyPI inspection authenticates its package/version,
source commit, API/schema, generator, complete RECORD hashes and installation
paths under the existing Release Trust owner. Native PyPI attestations, SBOMs,
independent payload bytes, signature, provenance and revocation stay in that
same signed Release Manifest path. Clean generation, installed-wheel examples,
shared golden fixtures and a live candidate server exercise the package.
Private signing fixtures and local builds do not establish registry publication.

The Go publication workspace is `sdk/go`, with module identity
`github.com/vicotrbb/positron/sdk/go` and the standard Go module proxy registry.
The Rust Public Interface generator emits typed Go request/results, canonical
validation and error metadata, bounded native HTTPS, and query delivery helpers.
Go 1.24.0 is the pinned baseline; the module has no dependencies. Native module
ZIP inspection binds the module/version, source commit, API/schema, generator,
and complete generated package to the existing Release Trust path. Go checksum
database proofs authenticate the final ZIP and go.mod bytes. SBOMs, provenance,
signatures, revocation, independent rebuilds and complete-set publication remain
owned by the signed Release Manifest. Clean cache module installs, shared golden
fixtures and an installed-module live candidate test exercise the package.
Private fixture authorities and local proxy installs do not establish publication.

The Java/JVM publication workspace is `sdk/java`, with the existing native Maven
coordinates `dev.positron:sdk` and automatic module name `dev.positron.sdk`.
Java 21 and Maven 3.9.11 are pinned build inputs. Jackson 2.19.2 supplies native
record and tree serialization; all wire shapes, error policy and descriptor
metadata are emitted by the Rust Public Interface owner. Bounded native HTTP/TLS
and delivery helpers execute those bindings without a JNI or server-domain
runtime dependency. Native Maven inspection binds the actual POM, compiled and
source JARs, Javadoc, API/schema, source identity, generator and registry under
the existing Release Trust path. OpenPGP signatures, SBOMs, provenance,
independent rebuilds, revocation and complete-set publication remain in the
signed Release Manifest. Clean Maven consumer installs, shared golden fixtures
and installed-JAR candidate-server conformance exercise the package. Local
builds and private signing fixtures do not establish Maven Central publication.
