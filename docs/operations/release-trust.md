# Construct and verify a release

`positron release` runs without opening an instance or loading its database
configuration. It never publishes packages, installs a trust root, downloads
proofs, or signs with a private key. An independently installed trust document
and locally supplied artifacts are required for authenticated verification.

A construction is not a release. `construct` measures the complete declared
Release 1 set and emits unsigned canonical inputs. `attach` authenticates one
manifest signature. Only `verify` reports a complete published set after checking
all required artifacts and bundled publication proofs.

## Installed authority

The installed JSON document contains `format: 1`, `root` (`public_key` and
`minimum_sequence`), `release_signer`, and `signed_snapshot`. Key bytes are JSON
byte arrays. `signed_snapshot` contains a 64-byte Ed25519 signature followed by
canonical snapshot JSON. Its signing message is
`positron.release-trust.v1\0` followed by that JSON. `trust-message` creates this
message; an external signer produces the detached signature; `trust-attach`
authenticates it against the explicitly supplied installed root.

The root and rollback floor are installed independently of the release bundle.
The root authorizes release signers, publisher keys, transparency log keys, and
native publisher profiles. They are separate roles. The instance Integrity
Identity does not authorize releases. A raw 32-byte legacy root file is refused;
an invalid typed document never falls back to a different format.

Snapshots have a nonzero increasing sequence, an issuance time, an expiry no
more than 30 days later, the current product version, bounded role assignments,
and revocations of keys, manifests, and artifact digests. Operators install a
new snapshot and independently advance the minimum accepted sequence when
rotating or revoking authority. Retaining an old floor does not establish that
a newer revocation snapshot has been installed. Verification never fetches an
update or treats absence of a revocation list as current trust.

CLI verification uses the host clock and prints the verification time and trust
sequence. Native Upgrade uses the instance's owning trusted Clock authority and
refuses Clock Uncertain. Startup authenticates installed source identity and
revocation state; support-age eligibility applies to accepting a target release.
An authenticated source outside the current and preceding minor versions can
still start and take its signed supported upgrade path. Expired trust must be
refreshed explicitly before authenticated release or Upgrade acceptance.

## Construction inputs

The canonical inventory binds the version, exact lowercase Git object name,
build identity, public API version, independent compatibility claims, pinned
input files, each artifact identity, SBOMs, license notices, provenance, test
results, registry identity, and publication state. Filenames are single portable
members of an explicitly supplied directory. Member symlinks and nonregular
files are refused. Installed CLI trust must be controlled by the current user
or root and must not be writable by group or other users.

The minimum Release 1 matrix contains four native executables, four native archives,
four Nix packages, two Debian packages, two RPM packages, two OCI images, one
OCI index, Homebrew, Compose, Helm, Grafana, six generated SDKs, source, API, and
documentation. A native registry can require several members per surface, such
as Maven POM, main, sources and Javadoc artifacts. This inventory describes
required future distributions; it does
not assert that they have been built or published.

Linux functional executable bytes, unsigned OCI filesystem payloads, generated
API bytes, and generated SDK source bytes must match separately supplied rebuild
inputs. A path alias or hard link to the original input is refused. Raw payloads
must be the actual artifact bytes; a supported signed NuGet package instead
binds the reconstructed unsigned ZIP through its owning native hash algorithm.
An OCI manifest must bind its layer, config,
platform, and unsigned filesystem digest; its index must bind both image
platforms. Supplying separate matching files proves byte equality, not that two
independent builders actually executed. Build provenance and builder evidence
remain separately authenticated release claims.

The tooling checks a bounded identity profile of SPDX 2.3 and CycloneDX 1.5/1.6
metadata, in-toto/SLSA provenance, and required result fields. It does not replace
upstream SBOM schema validation or execute the conformance, dependency, security,
or independent build jobs described by their results.

File measurement streams checksums and screens explicit caller canaries and
recognized credential forms. Gzip, tar, and ZIP members are scanned after
decoding without extracting paths, with limits on depth, bytes, and member count.
Tar iteration stays raw: GNU/PAX metadata is counted, bounded and screened as
serialized bytes before any expansion; GNU sparse entries are refused. Metadata
is not applied to subsequent paths or interpreted as a nested archive.
Unknown package formats still require the separately bound security and secret
scan results from their native packaging pipeline. Pattern screening is defense
in depth and does not establish absence of every possible secret.

## Offline command sequence

```console
positron release construct --inventory release-input.json --bundle artifacts --rebuild independent --out unsigned
positron release attach --manifest unsigned/manifest.json --signature manifest.sig --trust installed-trust.json --out release.manifest
positron release verify --manifest release.manifest --inventory unsigned/inventory.json --trust installed-trust.json --bundle artifacts --rebuild independent --target linux-x86_64
```

`construct` creates a new owner-only output directory containing `inventory.json`,
`compatibility.json`, `manifest.json`, and `signing-message.bin`. An external
signer signs the exact signing message. Existing output files are refused.
Optional `--canaries FILE` supplies a bounded JSON array of byte arrays; the
canaries are never rendered. `--upgrade-from FILE` supplies the canonical
source-version allowlist for construction.

The Kernel Release Manifest remains the single release authority. Its signed
inventory digest binds the full set; detached publication proofs bind the final
manifest digest after construction, avoiding a circular inventory hash. A
publisher assertion is publication provenance and cannot substitute for an
applicable native signature or trusted publishing attestation. Offline trust
roots and proof bytes must be supplied explicitly; no missing, unsupported,
expired, revoked, mismatched, or partial proof silently succeeds.

## Native publication profiles

The root-signed policy chooses an eligible native context for each surface.
Changing a registry URL or installing a generic workflow policy cannot turn an
SDK registry package into a direct GitHub artifact. These are offline profiles;
unsupported native formats fail explicitly.

| Surface/context | Required native evidence and binding |
| --- | --- |
| Direct downloadable assets | A standard GitHub Actions SLSA attestation, with the installed Fulcio/CT/Rekor roots, exact workflow SAN and issuer, repository, ref, source commit, and artifact subject. |
| npm SDK | Native npm provenance with its GitHub Actions build type, SHA-512 package subject, canonical npm package URL and shared release version. |
| PyPI SDK | A native publish attestation, including the PEP 740 envelope profile, exact distribution filename and digest, and authenticated publishing workflow. |
| crates.io SDK | The explicit OIDC-upload/no-offline-receipt profile: captured index name, version, checksum and non-yanked status, captured GitHub publishing metadata, actual normalized Cargo package identity and source VCS identity. The project publisher signature authenticates these captured claims. They are **not a crates.io signature or offline proof of registry acceptance**. |
| Go SDK | A native checksum-database record for both module ZIP and `go.mod`, signed current and independently installed prior checkpoints, inclusion and consistency proofs, canonical content hashes, and exact module/version. This establishes logged content, without asserting OIDC identity or proxy availability. |
| Maven SDK | Detached OpenPGP signatures under the installed primary certificate for the POM, main JAR, sources JAR and Javadoc JAR. Their actual names, GAV, shared version and complete member set must agree. |
| NuGet SDK | A native repository-primary package signature binding the V3 service index, actual Nuspec identity and reconstructed unsigned ZIP; an authenticated RSA/SHA-256 RFC 3161 timestamp and installed certificate chains bind signing time. |
| Homebrew third-party tap | A GitHub attestation under the actual installed tap workflow/repository/ref, with a separately recorded tap revision in the canonical inventory. The upstream product source commit remains a separate identity. Official `homebrew-core` catalog evidence is not approximated by this profile. |
| OCI images/index | Immutable OCI descriptors and actual filesystem/config/platform bindings, native cosign signatures, and authenticated transparency inclusion. |

Keyless verification uses the maintained Sigstore verifier with certificate
chain, SCT, transparency inclusion/checkpoint and integrated-time checks enabled.
It never substitutes a public-key project assertion for Fulcio/OIDC identity.
Private GitHub attestations without the required transparency proof are refused.
The separate project publication assertion binds the final canonical manifest
and each artifact after publication; it does not impersonate a registry.

The bounded Maven profile accepts installed v4/v6 primary certificates, SHA-2
binary detached signatures, current authenticated signing flags, expiry and
revocation state. It refuses subkey certificates and unsupported packet forms.
The NuGet profile supports repository-primary RSA/SHA-256 packages with the
signature as the last local/directory entry and no ZIP comment. Author plus
repository countersignatures and other algorithms are explicitly unsupported.
Timestamp policy includes ESS certificate binding, signed attributes, algorithm
agreement, certificate EKUs and the full declared accuracy interval. Native
certificate digests can be revoked through the same current root-signed artifact
revocations; verification makes no claim to have fetched current CA CRLs.

Go's bounded profile supports stable `vX.Y.Z`, matching module path major,
ASCII regular-file ZIP members, and an embedded root `go.mod`. Pseudo versions,
prereleases, `+incompatible`, `gopkg.in`, explicit directory members and Unicode
paths are refused. The crates profile supports bounded canonical regular-file
tar/gzip packages with required normalized `Cargo.toml` and source-matching
`.cargo_vcs_info.json`; links, sparse/GNU/PAX extensions and trailing archives
are refused. These limits qualify supported inputs and do not claim universal
compatibility with every ecosystem package.

These profiles follow the owning specifications:
[GitHub provenance](https://github.com/actions/toolkit/blob/main/packages/attest/src/provenance.ts),
[npm provenance](https://github.com/npm/cli/blob/latest/workspaces/libnpmpublish/lib/provenance.js),
[PyPI integrity](https://docs.pypi.org/api/integrity/),
[crates.io trusted publishing RFC](https://rust-lang.github.io/rfcs/3691-trusted-publishing-cratesio.html),
[Go checksum database](https://go.dev/ref/mod#checksum-database),
[Maven Central requirements](https://central.sonatype.org/publish/requirements/),
[NuGet signed packages](https://learn.microsoft.com/en-us/nuget/reference/signed-packages-reference),
and [Homebrew tap attestations](https://github.com/Homebrew/brew/blob/main/Library/Homebrew/attestation.rb).

## Key custody and incident operation

Keep the Project Trust Root offline under separately controlled custody. Online
release signers and publishers receive distinct role assignments with bounded
validity. Native registry identities, CA/log roots and package signing
certificates are authorized by the same root-signed snapshot. A build worker's
instance identity or an artifact's embedded certificate cannot install authority.

For routine rotation, provision the successor public identity, authenticate it
under the predecessor or Project Trust Root, publish a root-signed snapshot
containing the bounded overlap, and independently install its sequence floor.
Verify a candidate under the successor before retiring the old release-signing
assignment. Keep a bounded `InstalledSource` assignment for the old public key
when historical installations still need to authenticate their source and take
a signed upgrade path. This assignment never authorizes a target or full release;
source authentication tries the current snapshot's at most 64 unique authorized
release/source identities and requires exactly one signature match. Selecting the
successor `release_signer` therefore does not rewrite historical signatures.
Revocation overrides both roles, and expired source authorization must be renewed
explicitly under the Project Trust Root. These additive snapshot role semantics
implement the product §3.24 rotation rule without changing Kernel manifest bytes.
The
CLI emits signing inputs and attaches externally produced signatures; it never
handles signing private keys.

For compromise, identify affected key, certificate, manifest and artifact digests;
issue a newer independently distributed root-signed revocation snapshot; install
it and advance the rollback floor through the operator-controlled trust path.
Re-run native preflight and full offline verification. A revoked signer or
artifact remains refused even when its former release signature and registry
proof are cryptographically valid. Replacing trust does not authorize a new
binary, alter format compatibility, or publish a repaired release automatically.


Native Upgrade uses a complete-target type that authenticates the entire signed
published inventory and current support eligibility without staging every SDK
package locally. Native preflight still measures the selected executable and
all configured core files. A retained request rechecks expiry under the instance
Clock; actual admission reloads the candidate through current independently
installed trust, including target revocations and the current support window.
No installed release authority means no native Upgrade admission. Historical
source authentication does not imply target eligibility.
