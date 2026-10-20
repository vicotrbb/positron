# Native archives

The archive contains the same `positron` executable used by other distributions,
the generated Configuration Contract, license, and a service example for its
exact platform. Linux archives and native packages share one GNU executable per
architecture built against the GNU libc 2.34 baseline in
`deploy/linux/Dockerfile`; the Linux package matrix and qualification procedure
are in `deploy/linux/README.md` in the signed source distribution. Native macOS builds target macOS 15
for x86_64/aarch64. Older libc or macOS versions require separately qualified
compatibility; the archive does not bundle a libc or platform SDK. Do not run an
archive built for another target.

## Build and verify

Build macOS directly with the pinned Rust toolchain and locked resolution.
Build Linux inside the frozen GNU baseline image from `deploy/linux/Dockerfile`,
using the same locked Cargo command and build flags; use that executable for
both the Linux archive and native packages. The CI recipe in
`.github/workflows/checks.yml` supplies identical source/target path remaps and
compares independent baseline builds. A host build against a newer libc is not
the common Linux package artifact.

For example, on macOS:

```console
# Remap native C and assembly debug compilation directories.
export CFLAGS="-fdebug-prefix-map=$PWD=/positron-source"
# On macOS, use the pinned platform linker's deterministic-input mode.
if [ "$(uname -s)" = Darwin ]; then export RUSTFLAGS="-C link-arg=-Wl,-reproducible"; fi
cargo build --locked --release -p positron
./target/release/positron release archive --target macos-aarch64 --binary target/release/positron --out positron-macos-aarch64.tar.gz
```

Use the corresponding target name on the other three builders. The constructor
rejects a mismatched executable header. It preserves the executable bytes and
normalizes archive order, modes, owner/group, timestamps, and gzip header. Build
again in an independent checkout with the same declared compiler, linker,
platform SDK, dependencies, source and build paths; compare both executable and
archive bytes. Use byte-identical compiler flags for both builds: when remapping
independent checkout paths, include both source-root mappings to the same
canonical prefix in both invocations. Apply the same source-root and target-root
mappings to native C and assembly through `CFLAGS=-fdebug-prefix-map=old=new`.
Rust path remapping does not cover native debug compilation directories; those
can change the linker's content-derived UUID even when Cargo subsequently
removes the debug data. Preserve the native build UUID and code signature;
neither is rewritten after linking. An archive match from the same executable is packaging
reproducibility only, not an independent compiler rebuild.

The pinned release profile compiles `age` as one codegen unit. This keeps that
crate out of Cargo's default local ThinLTO cross-unit promotion path while
retaining its optimization level, cryptographic features and dependencies.
Include this package profile in the declared build inputs. It does not replace
the independent executable and archive comparisons on every supported target.

Treat these as unsigned construction outputs. Add each executable and archive to
the existing Release Inventory as `NativeExecutable` and `NativeArchive` for its
exact target, with the independent unsigned payload, SHA-256 and size, both SPDX
and CycloneDX SBOMs, license policy, pinned toolchain inputs and build provenance.
Record the exact `RUSTFLAGS` and `CFLAGS`, including their remap prefixes, in the
existing pinned build inputs and authenticated in-toto/SLSA build provenance.
Use `positron release inspect` for checksums. See
`docs/operations/release-trust.md` in this archive for construction,
external signing, detached publication proof and complete offline verification.
Do not distribute a release without its authenticated manifest and full required
artifact set. macOS platform signing/notarization is a wrapping layer; retain and
bind independently rebuilt unsigned bytes separately. No command here publishes,
installs trust, signs with an instance key, or updates the database automatically.

Before extracting a downloaded archive, verify the complete release offline:

```console
positron release verify --manifest release.manifest --inventory inventory.json --trust /etc/positron/project-trust.json --bundle release --rebuild independent-rebuild --target macos-aarch64
```

The verifier must come from an independently trusted installation. Install the
Project Trust Root separately, with current signed revocations and the local
sequence floor. Do not trust keys bundled by a download merely because its own
checksums match. Verification refuses missing, changed, revoked, unsupported,
unreproduced or incomplete inputs and never fetches trust.

## Install and initialize

Extract into a new version directory. The archive creates only `positron/` with
regular files; it does not create accounts, write durable data, or run hooks.
Keep that directory root owned and not writable by the service account. For the
service examples, install it as `/usr/local/lib/positron`. Keep the prior version
until the explicit upgrade and recovery process completes.

Create a dedicated non-login `positron` account using the host's account tools.
Create `/etc/positron` owned by `root:positron` with mode 0750 and install its
configuration owned by `root:positron` with mode 0640. The service account can
read and traverse this configuration tree but cannot change it. Create
`/var/lib/positron`, `/var/lib/positron-secrets`, and `/run/positron` owned by
`positron:positron` with mode 0700. Keep secret files owned by the service
account with mode 0600. Keep data
and secrets separate; preserve both in recovery. Run database commands as the
service account, never as root. The immutable binary tree and configuration may
be read only; the configured data, secrets, runtime and temporary paths must be
writable. Do not place data on an unsupported network or shared filesystem.

From the extracted installation directory, install the configuration using
the host's administrative account:

```console
install -d -o root -g positron -m 0750 /etc/positron
install -o root -g positron -m 0640 etc/positron.toml.example /etc/positron/positron.toml
```

Review the
generated reference under `share/` and explicitly configure
`security.local_key_file = "/var/lib/positron-secrets/local-root-key.v1"` in the
`[security]` table. Secret-bearing fields are omitted from the public example.
The default durable paths match these examples. Set
`listener.control_path = "/run/positron/control.sock"` and keep
`runtime.shutdown_grace_seconds` at most 60 for the supplied service stop budget.
For macOS, create a separate owner-only `/var/lib/positron-runtime` directory
and set the control path to `/var/lib/positron-runtime/control.sock`. This
parent survives reboot while its socket remains disposable; it must be outside
the data and secrets roots. Linux systemd recreates `/run/positron` through
`RuntimeDirectory` when the service starts.

The generated example selects TLS. Before starting, provision the certificate
and private-key files for each listener at explicitly configured protected paths.
For a local-only quickstart, explicitly change `operations_transport`,
`api_transport`, `otlp_grpc_transport`, `otlp_http_transport`, and
`loki_push_transport` to `"plaintext"` in the existing `[listener]` table and keep
all bind addresses on loopback. This emits visible security warnings; it is an
operator choice, never an automatic fallback.

For a user-owned installation choose absolute paths under your home for data,
secrets, configuration and control socket instead; configure the local key path
to match. No system service or privileged account is needed to run foreground.
Keep the control socket path within the platform Unix socket length limit.

```console
/usr/local/lib/positron/bin/positron config validate --config /etc/positron/positron.toml
/usr/local/lib/positron/bin/positron serve --init-if-empty --config /etc/positron/positron.toml
```

First startup initializes only truly empty roots. It never resets existing or
corrupt data. Non-interactive initialization writes owner-only one-time bootstrap
claim material in the secrets directory and never logs an administrator key.
Stop the foreground process with SIGTERM and wait for successful exit. Run
`positron bootstrap claim --config /etc/positron/positron.toml` as the same owner
to claim once; the offline claim requires exclusive instance ownership. Then
restart without `--init-if-empty`.
Keep returned credentials out of shell history, logs and process arguments.
Subsequent starts use `serve --config ...` without `--init-if-empty`.

## Service lifecycle

On Linux, copy `share/positron.service` to `/etc/systemd/system/`, reload systemd,
and enable/start it only after foreground initialization. The unit runs under
the dedicated account, restricts writable paths, and sends SIGTERM on stop.
On macOS, review `share/com.guaracloud.positron.plist`, install it root owned as a
LaunchDaemon, and load it with the host's `launchctl bootstrap` command after
initialization. Configure standard output/error collection using your host's
logging policy. The example does not print credentials. Unload the daemon using
`launchctl bootout` before replacing files. macOS account creation and runtime
directory creation remain explicit host administration.

Readiness and liveness use the configured Operations Listener. Ready means the
shared runtime reached Serving; a live process alone is not ready. Send telemetry
only to the configured ingest listeners, and use the public Query API with a
separate query-scoped credential. TLS is required for non-loopback listeners
unless an operator explicitly accepts the recorded plaintext warning.

The installed `query` command uses the canonical bounded Log HTTP execute API.
Create a JSON request file containing a `pipeline` and explicit `budget`; use
nanosecond range endpoints appropriate for the records you ingested. For example,
the following request inspects records whose Query Time falls between 0 and 100:

```json
{"pipeline":"logs | range query_time 0 100 | limit 16","budget":{"scannedBytes":"1048576","decodedRecords":"16","outputRows":"16","outputBytes":"16384","memoryBytes":"1048576","cpuWorkUnits":"15","wallSeconds":"5","maximumTimeRangeNanoseconds":"100"}}
```

Pipe the Query credential to `positron query --endpoint IP:PORT --server-name
NAME --trust-file /protected/ca.pem --credential-stdin --request query.json`.
Use `--allow-plaintext` only with the explicitly configured plaintext listener.
The command emits the schema, pinned snapshot, ordering, effective budget,
lease, typed batches and one terminal. Inspect that terminal: Incomplete and
Continued never mean Complete. The bounded Log execute route is available;
public gRPC, SQL, resume, tail, export, Trace client methods and the six SDKs
remain tracked by issue #219, so aggregate Release 1 Query remains unavailable.

SIGTERM or SIGINT starts bounded Drain: readiness fails, new work closes,
admitted durability completes, and the runtime writes its Graceful Shutdown
Record before successful exit. A second signal or expired deadline is a crash
recovery path. SIGHUP transactionally reloads only supported mutable settings;
invalid configuration leaves the prior state active. Inspect `positron doctor`
and `positron verify` for explicit health and integrity results.

## Backup, restore, upgrade and recovery

Use the same authenticated `repository`, `backup`, `restore`, `verify` and
`upgrade` commands and public APIs as every distribution. `positron backup` and
`positron backup restore` expose operation start, inspect, wait and cancellation.
See the exact commands, preconditions and recovery steps in the bundled
`docs/operations/repository.md`, `restore.md`, `upgrades.md`, and
`local-key-recovery.md`.
Register a supported repository, create and independently verify a Backup
Snapshot, and retain its required recovery key material separately before any
upgrade. A copied live data directory is not a verified snapshot.

Stage the candidate binary, signed complete manifest and inventory using the
configured `release.installation` references and independently installed project
trust. Use the explicit Upgrade preflight and approved Quiescent Upgrade Snapshot
flow; allow the current process to Drain before activating the new binary.
Never overwrite a running executable, change initialized durable paths, or
reinterpret an incompatible Format Epoch. Start the candidate with the same
configuration and roots, inspect readiness and query retained data. A failed
preflight leaves the old process authoritative. After migration publication,
follow the reported recovery plan; do not force an old binary over newer data.

Restore only through the verified fresh-target Restore operation. Its target
roots must be empty and distinct, its key provider must match recovery custody,
and the snapshot's format must be supported before target mutation. Retain the
old instance until independently verified restored data can be queried. Missing
or mismatched local keys, fenced integrity state, unavailable repositories, and
invalid configuration fail explicitly. Correct the named dependency or use the
supported recovery command; deleting roots to bypass an error destroys evidence.

## Remove while retaining data

Stop and disable/unload the service, confirm process exit, remove the service
file and immutable installation directory, and reload the service manager.
Remove an optional PATH symlink only if it points to this installation. These
steps do not remove `/var/lib/positron`, `/var/lib/positron-secrets`, configuration,
trust or backups. Reinstalling the same compatible binary with those roots must
recover the same data. Keep the service account or preserve its numeric ownership
for that reinstall. Delete retained data and keys only as a separate explicit
destructive administrative action after the required verified backups exist.

## Native integration qualification

The four native CI jobs compare independently rebuilt release binaries and
archives, then exercise each installed executable. Ordinary local archive tests
build the same source as a locked native release in a separate Cargo target
directory when no installed executable is supplied. The retained-record flow
uses authenticated commands for snapshot creation and independent verification,
fresh-root restore, automatic Upgrade-to-Drain handoff, offline publication, and
query after candidate restart.

The upgrade candidate is a private test fixture: CI snapshots the tested source,
changes only that copy's unreleased package version from `0.0.0` to `0.0.1`,
commits the fixture source, and compiles its executable independently. Fixture
manifests bind the actual source commits and executable digests under private
test trust. This tests the native upgrade mechanism; it does not establish a
published version, project release signature, or reproducibility between two
released versions.
