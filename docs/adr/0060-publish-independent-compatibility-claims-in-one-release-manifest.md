# Publish independent compatibility claims in one release manifest

Every Release 1 artifact is covered by a machine-readable Compatibility Manifest that keeps product, API, query, configuration, receiver, CRD, operator, storage, backup, and migration compatibility as separate tested claims. Product versions follow semantic versioning; patches cannot require persistent migration or break documented behavior. Public API and query `v1` contracts evolve additively with stable error and completion semantics, and older `v1` clients remain supported. A runtime Capability Statement lets new SDKs reject unsupported features before sending semantically invalid requests. Configuration reads the current and immediately previous minor schema and migrates only to a separate reviewed file. Persistent and backup Format Epochs declare exact read, write, and migration support through a published Migration Graph; older binaries refuse newer writable formats, and restore rejects unknown epochs before target mutation. Receiver conformance and operator N/N−1 compatibility remain independently pinned. Log and Trace Store Block claims separately declare v1/v2 readability and v3-only writes for all new blocks, with v3 required for marker-bearing values; this is a format contract to be tested, not evidence that compatibility gates have passed. Integration tests exercise client skew, migrations, restore, upgrade, downgrade refusal, CRD conversion, operator skew, and receiver targets.

Root-provider Durable Operations extend the recognized `POSOPR04` record with
kind code 4 and a bounded `POSKPM01` parameter tail. Existing operation kinds
retain their exact v4 encoding; v1 through v4 legacy records remain readable.
Older readers recognize the outer operation record and reject the unknown kind
or extended length, so they cannot silently omit the new authority. The
migration audit payload uses its own versioned `catalog-root-migration-v1`
encoding; legacy root rotation payloads remain readable. These additive record
formats are independent of public API and provider conformance claims.

The native Upgrade consumer uses the canonical Release Trust verifier in
`positron-kernel::release_manifest`. Its independently installed Project Trust
Root is distinct from the instance Integrity Identity. The signed manifest
binds exact product versions, an explicit source-version allowlist, artifact
hashes and sizes, source commit, independent compatibility claims, configuration
schemas, and persistent and Backup format claims. Source commit text preserves
the actual lowercase Git object name: 40 hexadecimal characters for SHA-1 or
64 for SHA-256. It never pads or rehashes a Git object name.

A single operator-staged candidate and the current installed signed manifest
are configured through `[release.installation]`. Public Upgrade requests select
the candidate manifest digest. They cannot supply a trust root or a server file
path. Manifest authoring, full release inventory generation, and distribution
tooling remain owned by Release Trust issue #113.

The native Backup compatibility owner assigns Backup Format Epoch 1 to the
legacy `POSBKM01` publication/inspection frame, and Epoch 2 to the `POSBKM02`
capture-bound frame required by native independent verification under ADR-0026.
This is an explicit compatibility mapping. The captured Catalog Format Epoch
remains a separate persistent-data field in either frame. The current native
capture writer emits Backup Epoch 2, and Upgrade requires the signed source and
target to support that writer and its independent verification reader. Legacy
Epoch 1 inspection does not establish an Upgrade snapshot verification or native
fresh-target Restore path.
No Backup migration edge is declared by this mapping.

Release Trust tooling (#113) now constructs and verifies the full release set
in `positron-release`. This supersedes the earlier native consumer's raw
Project Trust Root key-file configuration. The independently installed typed
trust document supplies the root, an independently advanced minimum snapshot
sequence, an explicitly selected delegated release signer, and a root-signed
snapshot of signing roles, expiry, revocations, native publisher policies, and
the current minor version. Kernel owns canonical Release Manifest encoding and
signature verification. The tooling uses a distinct release signing key type;
it never presents a delegated signer as an installed Project Trust Root.

The signed Kernel manifest references one canonical full inventory by checksum
and size. The inventory owns construction details and the required distribution
matrix; it is not another release authority. Runtime authenticates this
reference and its declared identities under the same installed trust before
Upgrade. Detached publication proofs bind the final manifest digest and exact
artifact digest. They are excluded from inventory file hashes because a proof
of publication follows manifest signing; including a final-manifest receipt in
its own inventory would create a circular hash dependency. Publisher keys and
transparency roots are authorized by the installed root rather than by a
receipt's self-asserted keys. Publisher provenance never substitutes for an
applicable native registry signature or trusted-publishing proof.

Support eligibility and installed-source authentication are separate decisions.
A current snapshot defines the current and immediately preceding supported
minor versions. Full release acceptance and Upgrade targets must satisfy that
window. An older installed source remains subject to authentication,
revocation, compatibility, and explicit source-version authorization, while
support age alone cannot prevent startup or its signed supported upgrade path.
Fresh trust is evaluated under the instance Clock authority during native
acceptance; initial bootstrap metadata verification is repeated under the
recovered authority before authorization and listeners.


The full inventory matrix is a minimum, with the native publication closure
required by each registry. Maven therefore includes POM, main, source and
Javadoc artifacts and their signatures. Native SDK contexts are closed by
surface: crates.io, npm, PyPI, Go module/checksum database, Maven Central and
NuGet. A generic GitHub workflow or a renamed registry URL cannot replace their
applicable native evidence. Homebrew uses an explicitly selected third-party
tap identity and a separate signed tap revision. The standard public-key OCI
signature profile remains distinct from keyless package provenance.

The crates.io OIDC upload protocol currently exposes no independently verifiable
offline registry receipt. Its explicit absence profile binds captured native
index/publishing metadata and actual Cargo package/source identities under
project publication provenance, without claiming a crates.io signature. Go
checksum evidence establishes logged module content, not publisher identity.
These distinctions preserve the product's strongest-native-evidence-available
requirement rather than inventing an unavailable registry proof.

The maintained offline Sigstore verifier supplies certificate, CT and Rekor
verification with no trust fetching. Maven uses maintained OpenPGP primitives;
NuGet uses maintained CMS/X.509/RFC 3161 primitives with a narrow, attributed
RSA timestamp compatibility patch and strict profile validation. Installed
native roots and certificate revocations remain root-signed release trust, not
keys learned from an artifact.

A native Upgrade target must carry the complete signed inventory with every
required publication marked published. A signed native-only predecessor
manifest remains valid source authentication, but cannot become a target by
omitting the inventory role or its bytes. The complete-target type is created
by the owning Release Trust validator; typed/native entry points cannot replace
it with a merely signed manifest. This supersedes the earlier #112 consumer's
five-role target acceptance while preserving old-source recovery and upgrade.


Product §3.24 requires successor-key rotation and an authenticated upgrade path
for historical installations. The installed document's selected `release_signer`
is therefore target authority, rather than the key for every historical source.
An additive root-signed `InstalledSource` identity role permits bounded current
verification of old source signatures after their `Release` assignment retires.
The owning validator tries at most 64 unique currently authorized source/release
keys and requires one signature match using the same Kernel signature primitive.
Revocation applies to both roles; source-only authority cannot construct a
verified target or verify a full release. Snapshot expiry, rollback floor and the
owning Clock still apply. No second trust root or manifest wire format is added.

Nix outputs use the same inventory and manifest. The `Nix` surface identifies
the output NAR and signed store path. Its native cache profile verifies Nix's
standard Ed25519 store-path fingerprint, including NAR hash, size and references,
under a root-authorized Publisher key. Generic workflow provenance cannot
replace that signature. Functional NAR bytes must match an independent build.

Nix-linked executables differ from GNU archive executables even at the same
product version. The existing `NativeExecutable` role also carries
`nix-linux-x86_64`, `nix-linux-aarch64`, `nix-macos-x86_64` and
`nix-macos-aarch64` platforms. Canonical
`[release.installation].executable_distribution` selects `native` (the existing
default) or `nix` for current/candidate executable attestation, durable upgrade
selection and recovery. This extends the platform namespace without another
manifest or executable authority, and never guesses from a filesystem path.
