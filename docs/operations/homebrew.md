# Homebrew on macOS

Homebrew installs the same Rust executable and generated Configuration Contract
as the native archives. The exact targets are macOS 15 on Apple Silicon
`macos-aarch64` and Intel `macos-x86_64`, matching the native CI matrix. A
third-party tap is required; no official homebrew-core publication is claimed.
The service is a user LaunchAgent. Run Homebrew and Positron as your ordinary
non-root user. Homebrew owns the immutable version directory; database state
lives outside the Cellar and survives package removal.

## Construct and authenticate

After building both native archives, record their final filenames, checksums,
source commit, toolchain and target identities in the existing Release Inventory.
Generate the formula from that same inventory:

```console
positron release homebrew --inventory inventory.json --out positron.rb
```

This command creates a new file and refuses replacement. It performs no network,
signing, publication or trust installation. Its output fixes the product version,
upstream Git commit, exact archive filenames and SHA-256 values. Regenerate after
any native archive changes, then measure the formula and its independent rebuild
as `Surface::Homebrew`, target `any`, in the inventory. There is no circular
manifest hash in the formula. Release construction and verification require the
formula bytes to match these canonical archive identities exactly.

Build the formula twice from the same declared inputs and compare its bytes.
Independently rebuild and compare native unsigned executables and archives as
described in the native README. Record macOS SDK, linker, Rust, Homebrew, packaging
template and lockfile identities in the existing pinned build inputs and SLSA
provenance. Preserve platform code signatures and notarization as distinct
wrapping evidence; their nondeterminism does not excuse unsigned payload drift.

Use the existing Release Trust workflow to bind the formula and both native
archives to SPDX and CycloneDX SBOMs, license notices, build provenance,
reproducibility and conformance evidence. The actual separately administered tap
repository, workflow/ref and tap Git commit belong in its authorized
`HomebrewTap` keyless publisher policy and `publication.native_revision`.
The tap revision is distinct from the upstream product commit in this formula.
Capture the native GitHub attestation for the exact formula bytes from that tap,
plus the project publication proof binding the final Release Manifest digest.
Authenticate both under independently installed Fulcio, CT and Rekor roots and
the signed current Project Trust Root snapshot. A formula checksum or tap Git
commit alone does not establish publisher identity. Do not substitute an upstream
workflow attestation for the tap workflow. See `release-trust.md` for offline
verification, revocation and key custody.

Before running Homebrew on downloaded Ruby, verify the complete release offline
with an independently trusted Positron, installed trust, bundled proofs and
independent rebuilt payloads:

```console
positron release verify --manifest release.manifest --inventory inventory.json --trust /protected/project-trust.json --bundle release --rebuild independent-rebuild --target macos-aarch64
```

Use `macos-x86_64` on Intel. Missing SBOMs, provenance, proofs, revoked identities,
changed archives and rebuild drift fail closed. Decoded archive files and formula
bytes pass the existing secret scanner, including explicit secret canary tests.
Do not unpack or execute unverified downloads. Formula SHA-256 protects downloaded
bytes; Release Trust authenticates their release identity. Publication and
production signing are separate release actions.

Install the verified formula from its independently pinned tap revision using
`brew install OWNER/TAP/positron`. Replace `OWNER/TAP` with the actual tap named
in the authenticated inventory. This source repository does not create a tap or
claim that an unpublished version is available. Do not use `brew upgrade` or
`brew services restart` as an automatic database format migration.

## Configure and initialize

The formula installs no active configuration and starts no process. The example,
JSON Schema and reference are under `$(brew --prefix positron)/share/positron`.
Create private configuration, data, secrets and disposable runtime directories:

```console
brew_prefix=$(brew --prefix)
positron_prefix=$(brew --prefix positron)
install -d -m 0700 "$brew_prefix/etc/positron" "$brew_prefix/var/lib/positron" "$brew_prefix/var/lib/positron-secrets" "$brew_prefix/var/run/positron"
install -m 0600 "$positron_prefix/share/positron/config/positron.toml.example" "$brew_prefix/etc/positron/positron.toml"
```

Do not overwrite an existing configuration. Keep all directories owned by the
same non-root user and secret files mode 0600. Other local users must not have
write access to the Homebrew prefix, configuration or runtime parents. Protect
stdout/stderr logs in the runtime directory; rotate them using your host logging
policy. They never contain bootstrap credentials. The binary and configuration
may be read only at runtime; data, secrets, runtime and the system temporary
directory must be writable. Keep data on one supported local filesystem volume,
with secrets and runtime outside the data root. Do not use a shared writer or
network filesystem. Verify the configured Unix socket path fits macOS limits.

Edit the existing fields in the generated TOML, using absolute paths with the
actual Homebrew prefix, typically `/opt/homebrew` on Apple Silicon or `/usr/local`
on Intel:

- `storage.data_directory`: `PREFIX/var/lib/positron`
- `storage.secrets_directory`: `PREFIX/var/lib/positron-secrets`
- `security.local_key_file`: `PREFIX/var/lib/positron-secrets/local-root-key.v1`
- `listener.control_path`: `PREFIX/var/run/positron/control.sock`
- `runtime.shutdown_grace_seconds`: at most 60, within the service's 65-second stop budget

The public example omits secret-bearing file references. Provision listener TLS
certificates and keys at protected paths. For an explicit loopback quickstart,
set the existing five transport fields to `"plaintext"` as described in the native
README. Keep every listener on loopback; the native runtime records warnings.
No formula hook changes transport security or initializes storage.

```console
positron config validate --config "$brew_prefix/etc/positron/positron.toml"
positron serve --init-if-empty --config "$brew_prefix/etc/positron/positron.toml"
```

Send SIGTERM to this foreground process and wait for successful Drain. Claim the
initial credential exactly once through `positron bootstrap claim --config
"$brew_prefix/etc/positron/positron.toml"` while the instance is stopped. Protect
the returned credential from logs and shell history. Initialization accepts only
truly empty roots or a provably incomplete initialization. Missing/mismatched
keys, inconsistent state or invalid configuration fail explicitly.

## Service and recovery

Start with `brew services start OWNER/TAP/positron` after explicit initialization.
The LaunchAgent executes `positron serve --config ...` in the foreground using
the stable opt path. It does not reinitialize or run a wrapper. It starts at login
and deliberately does not repeatedly restart a failed configuration or fenced
instance. Inspect `brew services info OWNER/TAP/positron`, the protected logs,
Operations Listener readiness and `positron doctor` to diagnose failures.

`brew services stop OWNER/TAP/positron` sends the native stop signal and allows
65 seconds before force. SIGTERM enters the shared Drain state machine. A second
signal or expired deadline uses crash recovery and cannot claim a Graceful
Shutdown Record. SIGHUP requests transactional configuration reload. Verify the
reported process has exited before replacing files or running offline commands.
Use `brew services restart` only for an already approved same-format restart.

Use the same authenticated ingest, query, doctor, verify, repository, backup and
restore commands as the native archive. `repository.md`, `restore.md`,
`local-key-recovery.md` and `upgrades.md` are installed beside this document.
Create and independently verify a Backup Snapshot and retain separate recovery
key custody before replacement. A copied live directory is not a snapshot.
Fresh-target Restore requires empty distinct roots and the supported provider
and Format Epoch before mutation. Query restored records before retiring the
source instance.

For upgrade, stage the candidate and complete signed release, run native Upgrade
preflight and create its Quiescent Upgrade Snapshot. Let the current process
Drain. Stop/unregister the LaunchAgent and confirm exit, then run `brew upgrade`
for the approved formula and reverify installed bytes against the manifest.
Start with the same configuration, data and key roots, check readiness and query
retained records. Keep the old keg until acceptance; `brew pin` can prevent
unplanned package replacement. After migration publication follow the reported
recovery plan. Do not force an older keg over newer storage.

Stop the service and confirm exit before `brew uninstall OWNER/TAP/positron`.
Removal deletes the keg and its symlinks, retaining external configuration,
data, keys, runtime logs, independently installed trust, backups and user identity.
Reinstall a compatible verified version to recover those roots. Deleting data
or keys is a separate explicit destructive operation. Correct failed dependencies
or use the named recovery operation; never delete roots to bypass fencing.

## Native qualification

The existing hosted native matrix runs on macOS 15 ARM64 and Intel. It builds
native payloads independently, then installs a locally generated formula through
Homebrew from an isolated test tap and cached local archive bytes. Test-only
fixture identities are never publication evidence. The installed executable
runs the existing authenticated ingest/query, restart, verify, backup,
fresh-target restore, Upgrade/Drain and retained-record acceptance tests. Native
tap attestation, manifest binding, missing metadata, revocation, independent
rebuild drift and decoded secret canaries use the existing offline Release Trust
fixtures. Qualification requires successful jobs on both architectures; editing
a workflow alone does not establish that outcome.

The formula follows the Homebrew [service DSL](https://docs.brew.sh/Formula-Cookbook#service-files).
