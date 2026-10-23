# Nix installation

When configuring signed release installation and Upgrade, set
`executable_distribution = "nix"` in `[release.installation]`. The canonical
configuration reference documents this selector. The complete signed manifest
contains separate `nix-` executable platform identities and NAR store-output
identities. Native cache signatures authenticate the exact store path, NAR hash,
size and references under the installed Project Trust Root's publisher policy.

The flake builds the same Rust workspace and complete CLI for `x86_64-linux`,
`aarch64-linux`, `x86_64-darwin`, and `aarch64-darwin`. Its locked nixpkgs input
supplies the linker, platform libraries and build tools. The locked Rust overlay
selects the exact compiler and components from `rust-toolchain.toml`, using
checksummed upstream distributions. Cargo uses the committed lockfile.
Nix is a distribution and development tool, never a
database runtime prerequisite.

## Build and check

From the authenticated source checkout:

```console
nix build --no-update-lock-file .#positron
nix flake check --no-update-lock-file
nix develop --no-update-lock-file
```

The package runs the configuration and release contract tests in its sandbox.
It uses `positron release archive` to obtain the Rust-generated example TOML,
JSON Schema, configuration reference and lifecycle runbooks. They are installed
under `share/positron` and `share/doc/positron`. The package preserves the linked
executable bytes. Linux links against its declared Nix closure instead of the
native archive's GNU libc baseline; these are separate measured artifacts from
the same application source, configuration and storage contract.

The Linux flake checks additionally boot the NixOS module in a VM. The check
requires a functioning VM builder and tests non-root startup, initialization,
permissions, bootstrap claim destruction, reload, restart, graceful stop,
offline verification and retained data after removal. Build each target on its
matching builder. Linux emulation does not qualify a macOS executable.

## Linux acceptance-platform baseline

The service VM uses the locked systemd 260.5 source and nixpkgs patches, with
`systemd-260.5-udev-rule-path.patch` (SHA-256
`0c56d1c7684a5ea455b5d4f6bdc1e154771e2d04a44903e650a3a52304abbe77`).
The patch corrects one udev rules stat-cache key and adds native owner regression
tests. Loading rules must use the same resolved path keys as the subsequent
reload check. Unpatched 260.5 stores directory aliases when loading but resolved
paths when checking, so a symlinked rules directory can repeatedly appear
changed without a file mutation. NixOS exposes its generated rules through such
a directory symlink. This baseline qualifies the corrected dependency; it does
not establish reliable boot with the unpatched dependency.

Only the acceptance VM's stage2 `systemd-udevd` executable and its matching
private library use that corrected build. PID1, initrd, journald, the exported
Positron module and consumer host packages retain their original dependencies.
The VM uses its original resources, deadlines and lifecycle assertions, without
udev diagnostic instrumentation, event observers or extra boot ordering.
Normal package output-reference checks remain enabled. The separate native
proof build enables upstream `tests` and `install-tests`; its installed test
scripts require Bash, so only that proof artifact's `out` and dependent `dev`
outputs permit those two existing Bash requisites.

The native regression runs the actual rules loader and reload checker for a
direct directory and a directory symlink. Each case checks unchanged rules,
a genuine size-changing rule mutation, reload and convergence. With the native
test artifact built, run the existing harness in a disposable root container
with a read-only Nix store, no source mount or network, and only the additional
`SYS_ADMIN` capability needed for its private mount namespace and proc mount:

```console
TESTFUNCS=test_udev_rules_reload_direct_directory:test_udev_rules_reload_symlink_directory timeout --signal=KILL 90s "$systemd_test_output/lib/systemd/tests/unit-tests/test-udev-rules"
```

Each child also has a 30-second bound. Missing namespace/mount privilege is a
proof failure, not a skipped test. The unpatched control passed while the alias
case failed at the initial unchanged-rules assertion; the one-line correction
passed both cases, including mutation detection. These native tests establish
the dependency correction; the complete uninstrumented service VM remains the
installation and lifecycle qualification.

## Verify release identity

Before installation, authenticate the source archive, `flake.nix`, `flake.lock`,
Cargo lockfile, pinned toolchain and exact build inputs using the independently
installed Project Trust Root and the full Release Manifest. A Nix store hash or
binary-cache signature alone does not authenticate the Positron release.

Export each built package's functional bytes with `nix-store --dump PATH` to a
NAR file. Build again in an independent builder with identical source, lockfile,
system, build flags and store paths, and dump again. Record the exact closure
with `nix path-info --recursive --json PATH`. Include the NAR as the existing
Release Inventory's `Nix` artifact for the corresponding `linux-x86_64`,
`linux-aarch64`, `macos-x86_64`, or `macos-aarch64` target. Its payload must be
present and independently reproduced. Retain the source and both lockfiles as
declared hashed inputs. Bind each output's SHA-256, size, SPDX and CycloneDX
SBOMs, license notices, source/toolchain identity, build provenance and detached
signature through the existing inventory and manifest. Do not substitute the
recipe for the output NAR or treat package construction as publication.

The native CI comparison also uploads `nix-current-build-staged-metadata`.
For each exact target it contains the measured executable and NAR, actual Git
source archive and commit, lockfiles, compiler identity, Cargo package metadata,
Nix closure, generated SPDX/CycloneDX documents, provenance, and a test-signed
canonical Kernel manifest referencing the staged inventory. Dependency licenses
come from captured Cargo metadata; unknown closure licenses remain unknown.
Compatibility fingerprints identify the captured API, query and receiver source
definitions and the accepted CRD/operator contracts. They do not assert that a
not-yet-published compatibility matrix has passed. The format declarations retain
Catalog Epochs 1/2 readability, current Catalog Epoch 2 writes, and the ADR-0060
native Backup Epoch 2 mapping.

This is offline current-build identity qualification, with an explicitly public
test key. It does not install trust, publish artifacts, create an Upgrade target,
or assert the full release validation evidence closure. The complete synthetic
release fixture separately tests native cache verification and release-wide
integration; its synthetic source/version are not current-build provenance.
Full release construction and verification continue to require every distribution
surface, all validation evidence, and authorized publication proofs.
The captured source archive remains an exact hashed build input, not an accepted
`Source` release artifact. It contains committed TLS/provider test keys, adversarial
PEM fuzz seeds and credential-shaped upstream examples. The unchanged full scanner
reports `SecretDetected`; `source-input-scan.json` retains that result. Staged
qualification measures those input bytes and scans every shipped executable, NAR,
API and metadata file. It does not turn the source refusal into a successful full
release secret scan.

Run the independently trusted CLI's complete offline release verification
before trusting any downloaded output:

```console
positron release verify --manifest release.manifest --inventory inventory.json --trust /etc/positron/project-trust.json --bundle release --rebuild independent-rebuild --target linux-aarch64
```

Keep current signed revocations and the independently advanced trust sequence
floor. The existing verifier handles signatures, manifest identity, checksums,
rebuild differences, secret scanning, SBOMs and provenance. Follow
`docs/operations/release-trust.md` for signing custody, rotation and recovery.
No command here signs, publishes or silently installs trust.

## NixOS service

Import `inputs.positron.nixosModules.default` and enable:

```nix
services.positron.enable = true;
services.positron.configFile = "/etc/positron/positron.toml";
```

Install the canonical TOML file owned by `root:positron`, mode 0640, under the
0750 configuration directory. Use the generated example and `positron config
validate --config /etc/positron/positron.toml`. The module creates the static
non-login `positron` account and separate 0700 data and secrets directories at
`/var/lib/positron` and `/var/lib/positron-secrets`. Runtime state is 0700 under
`/run/positron`. Keep the canonical default data, secrets and runtime paths for
this module's filesystem sandbox. Live data must use a supported local
filesystem. Configure backup repositories outside live data using the canonical
repository configuration and runbooks. Grant its existing owner-controlled
directory to the sandbox with `services.positron.extraReadWritePaths`, while
keeping repository configuration in canonical TOML and native lifecycle commands.

For a new installation explicitly set `services.positron.initialize = true`
to use `serve --init-if-empty`. Initialization is transactional and fails closed
on inconsistent data or missing keys. Existing instances need no initialization
setting. Retrieve the one-time claim privately as the service account:

```console
sudo -u positron positron bootstrap claim --config /etc/positron/positron.toml
```

Never put credentials, local keys, recovery material or claim output into Nix
expressions, derivations or the world-readable Nix store. Preserve the secrets
directory separately from live data and establish verified recovery material
before relying on backups.

Use `systemctl start|stop|restart positron` and `systemctl reload positron`.
The service validates canonical configuration before startup. It runs in the
foreground as `positron`, cannot change the system or home directories, and
writes only to its explicit directories and private temporary directory.
SIGTERM invokes the native Drain. The 3605-second stop budget covers the
configuration contract's maximum 3600-second shutdown deadline. Health and
structured journal logs come from the same native runtime.

## Upgrade, backup, restore and removal

Before changing the selected flake revision, follow the authenticated native
Upgrade protocol in `docs/operations/upgrades.md`, create and verify its
Quiescent Upgrade Snapshot, stop the service, and switch only to the authorized
candidate. Bind Nix output and executable identities in that candidate's
complete signed inventory. A Nix generation rollback alone cannot reverse a
persistent format migration. Keep the prior generation and recovery inputs
until acceptance succeeds.

Use the same `positron repository` and `positron backup` commands described in
`docs/operations/repository.md` and `docs/operations/restore.md`. Run as
`positron`; keep provider credentials and recovery files owner-only. Restore
into an empty, separately configured target with authenticated snapshot and
identity pins, and verify before starting service. Do not copy a live directory
or combine data with another instance's keys.

On invalid configuration, inspect `positron config validate` and the journal.
On integrity, identity or key failure, retain the complete data and secrets,
stop restart attempts, and follow the recovery runbooks. Never delete directories
to make initialization succeed. The module contains no destructive hooks.
Disabling the service or removing its package retains configuration, data,
secrets, trust and backups. Explicitly authorize and perform any later deletion
only after validating recovery. Nix garbage collection removes package store
paths, not these durable directories.

The Linux service check boots NixOS and uses the real service sandbox. It
acknowledges telemetry, verifies independent key recovery, creates a backup,
and drives signed database Upgrade through Drain, authenticated snapshot and
offline publication. A private next-patch fixture uses the same workspace,
lockfile dependencies and pinned toolchain with only package versions changed.
The existing Release Trust fixture signer binds its measured Nix executable
identity. Switching the module's package generation then checks target startup
attestation and the original record, followed by restore into empty roots and
removal/reinstallation. This fixture signing does not publish a release.
