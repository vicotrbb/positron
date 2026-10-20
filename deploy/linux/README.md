# Linux native packages

Debian and RPM packages relocate the unchanged native executable and generated
Configuration Contract. The package manager owns `/usr/bin/positron`,
`/usr/share/positron`, `/usr/share/doc/positron`, the service unit under
`/usr/lib/systemd/system`, and `/etc/positron/positron.toml`. Debian treats the
configuration as a conffile; RPM uses `%config(noreplace)`. Hooks refuse an existing
root, shared-group or interactive service identity rather than repurposing it.

Build from a verified Linux native archive with the same GNU executable for
archives, Debian and RPM on each architecture. The package baseline is GNU libc
2.34; the builder rejects higher imported GLIBC symbol versions. The intended
qualification targets are Debian 12, Ubuntu 24.04, Fedora 43, and Rocky Linux 9,
on x86_64 and aarch64. These names describe the required test matrix, not
qualification evidence. Build the common executable on the oldest supported
GNU baseline; an executable built against Ubuntu 24.04 does not establish
RHEL 9 compatibility. There is no bundled libc, interpreter or database daemon.

```console
deploy/linux/build.sh deb verified-linux.tar.gz 1.0.0 aarch64 new-debian-output
deploy/linux/build.sh rpm verified-linux.tar.gz 1.0.0 aarch64 new-rpm-output
```

Use native dpkg-deb and RPM 4.x tools with binutils, coreutils, gzip and tar.
Record their exact versions, builder image digest, source commit, Rust/linker
inputs and flags in the existing Release Inventory build inputs and SLSA
provenance. Run each packaging command twice in independent directories with the
same declared tools and compare the unsigned package bytes with `cmp`.
`SOURCE_DATE_EPOCH=0`, normalized file modes/timestamps, fixed RPM build host and
gzip payloads remove wrapping variability; the executable is never stripped or
modified. Package construction performs no signing or publication. The pinned baseline image
explicitly installs Rust 1.96.0; a floating `1.96` image tag alone may contain a
later patch compiler.

Native runtime dependencies are GNU libc >=2.34, libgcc, CA roots, coreutils and systemd;
account creation uses passwd/shadow-utils and lifecycle administration uses
util-linux. Debian declares libc6, libc-bin, libgcc-s1, coreutils, ca-certificates, passwd,
systemd and util-linux. RPM declares glibc, glibc-common, libgcc, coreutils,
ca-certificates, systemd, util-linux and
its preinstall shadow-utils dependency. Capture the resolved exact dependency
versions for every qualified target in its authenticated release evidence.

## Sign and verify

Use independently administered release signing custody. Sign final RPMs with
`rpmsign --addsign`. The existing root-signed Release Trust snapshot authorizes
its `Rpm { trusted_root_sha256 }` publisher policy; the referenced public primary
OpenPGP certificate authenticates the embedded RPM signature and its bound
payload. Package subjects are `pkg:rpm/positron@VERSION-1?arch=x86_64` or
`pkg:rpm/positron@VERSION-1?arch=aarch64`. Also verify with
`rpmkeys --checksig` using an independently
installed authorized public key in a dedicated keyring. Direct-download Debian
packages require the native GitHub Actions SLSA attestation authenticated through
the installed Fulcio, certificate-transparency, and Rekor roots, together with
the separate project publication assertion binding the final signed Release
Manifest and exact package bytes. Verify both through Release Trust before
privileged installation. This profile claims neither embedded Debian signatures
nor APT repository authentication. An APT repository would additionally require
signed `InRelease`/`Release` metadata under its independently installed key; this
recipe creates and publishes no repository.

Add final signed packages as the existing `Debian` and `Rpm` surfaces for their
exact Linux target, with independently rebuilt functional bytes as the reproducible payload. For
Debian this is the unsigned `.deb`. For RPM the functional bytes are the
immutable main header (including scripts, dependencies and paths) followed by
the compressed cpio payload, excluding the native lead/signature wrapping.
Materialize that exact range through the existing Release Trust CLI:

```console
positron release rpm-payload --package signed-positron.rpm --out rpm-functional-payload.bin
```

Run the same command on the independent unsigned RPM and compare those functional
bytes. The constructor's full unsigned RPM comparison remains an additional
check. Do not author offsets or treat only unpacked database files as the
functional package. Bind checksums, both SPDX/CycloneDX SBOMs, license notices, dependency
policy, build provenance and qualification in the existing inventory. Bind the
final manifest digest and package digest through the existing authorized
publication proof. Do not invent another manifest or trust root. Follow
[Release Trust](../../docs/operations/release-trust.md) for complete offline
verification and signed revocations before installation. Test altered packages,
wrong targets, missing SBOM/provenance, expired/revoked signing identities and
independent rebuild drift through that same verifier.

Screen the verified archive and decoded native package payload/control scripts
for secrets before signing; use native `dpkg-deb --raw-extract` or
`rpm2cpio`/`cpio` only in an isolated build directory. Scan each decoded regular
file through `positron release inspect`, including an explicit secret canary
failure fixture. Do not extract unverified downloads on an operator's host.

## Install and initialize

Verify the complete release offline using an independently trusted Positron and
Project Trust Root, then install with `apt install ./positron_VERSION_ARCH.deb`
or `dnf install ./positron-VERSION-1.ARCH.rpm`. Package hooks create a dedicated
non-login `positron:positron` account and separate `/var/lib/positron` and
`/var/lib/positron-secrets` directories, mode 0700. Configuration is
`root:positron` 0750 with a 0640 file. systemd creates owner-only disposable
`/run/positron`. Hooks do not initialize, enable or start the database.

Review the installed canonical configuration/reference. Provision listener TLS
certificates and set `security.local_key_file` to its protected file reference;
the public example omits secret-bearing fields. Use only the existing
Configuration Contract. For local-only operation, explicitly select plaintext
for loopback listeners as described in the native archive instructions.

Run as the service account:

```console
runuser -u positron -- positron config validate --config /etc/positron/positron.toml
install -d -o positron -g positron -m 0700 /run/positron
runuser -u positron -- positron serve --init-if-empty --config /etc/positron/positron.toml
```

Stop the foreground process with SIGTERM and wait for successful Drain. Claim
initial credentials once with `runuser -u positron -- positron bootstrap claim
--config /etc/positron/positron.toml`; keep credentials out of logs, history and
process arguments. Then use `systemctl enable --now positron.service`. The unit
runs the same foreground server without automatic initialization. Keep
`runtime.shutdown_grace_seconds` <=60 for its 65-second stop budget.

The same public ingest/query, readiness, doctor, verify, repository, backup and
fresh-target restore commands apply. Installed operations instructions are under
`/usr/share/doc/positron/operations`. Native archive operational guidance is in
[the native installation instructions](../native/README.md). Protect the binary
and configuration from service-account writes, keep durable data and keys
separate, and qualify the filesystem volume with the native capability probe.

## Upgrade, removal and recovery

A package-manager replacement is not a persistent-format upgrade. First follow
the explicit native Upgrade workflow with the authenticated target, supported
compatibility claims and verified Quiescent Upgrade Snapshot. Stop the service
and confirm exit before replacing package-owned files. Hooks reject replacement
of an active systemd service and never restart it automatically. Install the
approved package, verify installed bytes against the Release Manifest and start
the candidate with the same roots. Confirm readiness and query retained records.
After migration publication, use the native reported recovery plan; forcing an
old package over newer storage is unsafe.

`systemctl stop positron` sends SIGTERM and waits for the shared bounded Drain.
A second signal or stop deadline uses crash recovery. Invalid configuration,
missing/mismatched keys, unsupported formats and integrity ambiguity fail closed;
use native doctor/verify/recovery commands rather than deleting state.

`apt remove positron` or `dnf remove positron` stops/disables the service and
removes immutable package files. Debian purge additionally removes configuration;
RPM retains modified configuration as `.rpmsave`. Data, local keys, backups,
separately installed trust and the numeric service identity remain. Reinstall
and review retained configuration before starting; native startup recovers the
same retained data. Deleting data or keys is a separate explicit destructive
administrative action. Package removal never performs it.
