# Portable OCI image

The image contains the unchanged GNU native `positron` executable, its generated
configuration example, JSON schema and reference, license, GNU runtime libraries,
and the pinned Mozilla CA bundle converted by curl on 2026-10-20 (MPL-2.0).
The GNU libraries come from the pinned Rocky runtime input. It contains no shell, package
manager, compiler, interpreter, or diagnostic tools. The same image and complete
CLI run under Docker, Compose, and Kubernetes. The database requires none of
those tools when run directly.

The image starts `/usr/bin/positron serve --init-if-empty` as UID/GID 65532 and
receives SIGTERM directly as PID 1. It sets the canonical control socket to
`/run/positron/control.sock` through the existing Configuration Contract and sets
`TMPDIR=/run/positron`. All other configuration uses the same native contract.
The generated files are under `/usr/share/positron`. There is no image-specific
initialization or storage implementation.

## Verify and install

Obtain the exact OCI index digest, both architecture image digests, signed Release
Manifest, full inventory, SPDX and CycloneDX SBOMs, licenses, provenance and
transparency proofs from one release. Install Project Trust independently. Before
loading or running the image, use the independently trusted native verifier:

```console
positron release verify --manifest release.manifest --inventory inventory.json --trust project-trust.json --bundle release --rebuild independent-rebuild --target linux-aarch64
```

Use `linux-x86_64` on AMD64. Verification is offline; missing proofs, changed
payloads, revoked identities and incomplete publication fail. A mutable registry
tag or successful build is insufficient. Use the authenticated index digest for
Docker/Compose `image` and Kubernetes `image`; each runtime selects its native
architecture. Never substitute a tag during upgrade.

Prepare the configuration before starting. Copy the generated example from the
verified native archive or image's `/usr/share/positron/positron.toml.example`.
Keep the configuration owner-readable with mode 0600. Set every listener's TLS
certificate/private-key paths to protected, read-only mounted files under
`/etc/positron/tls`, outside the database bootstrap roots. Provision those files
before serving. Configure externally reachable listener addresses explicitly;
Operations requires TLS for non-loopback addresses. The image does not generate
certificates or silently opt out of TLS. An unconfigured default invocation
refuses unavailable TLS material. A reviewed local-only configuration may
explicitly select plaintext on loopback; this emits security warnings.

Create distinct durable data and secrets volumes. Preserve their numeric owner
across every restart and replacement. For the default UID, a new Docker named
volume initially adopts the image directory's UID 65532 and owner-only mode.
For an arbitrary UID, provision the empty directories as that UID/GID with mode
0700 using host administration or a separate administrative provisioning
container. Mount explicitly provisioned empty named volumes with `volume-nocopy`
so Docker does not replace their ownership with the image directory metadata.
Never make secrets world-writable or use an fsGroup policy that grants other
users access to owner-only key material.

For example, after assigning `IMAGE` to the release's verified digest reference:

```console
docker volume create positron-data
docker volume create positron-secrets
docker run --name positron --detach --read-only --stop-timeout 60 \
  --mount type=volume,src=positron-data,dst=/var/lib/positron \
  --mount type=volume,src=positron-secrets,dst=/var/lib/positron-secrets \
  --mount type=bind,src="$PWD/config",dst=/etc/positron,readonly \
  --tmpfs /run/positron:rw,nosuid,nodev,noexec,uid=65532,gid=65532,mode=0700 \
  "$IMAGE" serve --init-if-empty --config /etc/positron/positron.toml
```

Publish only the listener ports selected in the reviewed configuration. The
configuration directory, files and TLS keys must be readable by the selected UID.
With an arbitrary UID, add `--user UID:GID`, use the matching tmpfs ownership,
and add `volume-nocopy` to the provisioned volume mounts. Use a qualified local
filesystem for data; a Docker Desktop host bind mount, an arbitrary network
filesystem or a Kubernetes PVC is not automatically storage-qualified.

Truly empty data and secrets initialize transactionally. Corrupt, mismatched or
partially initialized state follows the native fail-closed recovery rules; no
entrypoint script deletes or repairs it. Initial credentials never appear in
container logs. Stop the process gracefully before the native owner-only claim:

```console
docker stop --time 60 positron
docker run --rm --read-only \
  --mount type=volume,src=positron-data,dst=/var/lib/positron \
  --mount type=volume,src=positron-secrets,dst=/var/lib/positron-secrets \
  --mount type=bind,src="$PWD/config",dst=/etc/positron,readonly \
  "$IMAGE" bootstrap claim --config /etc/positron/positron.toml
docker start positron
```

Claim output contains credentials and is returned only once. Deliver it to
protected custody without shell history, logs or process arguments. An arbitrary
UID must also be selected on this one-shot command. Retaining data while losing
the matching local keys is data loss; keep verified recovery material separately.

## Health, Drain, backup and replacement

`/health/live` and `/health/ready` belong to the configured Operations Listener.
Use its TLS trust and server identity for network probes. A local plaintext
Operations Listener remains loopback-only; probe from the container's network
namespace with external administrative tooling. Such tooling is not included
in the image. Liveness alone does not authorize data traffic. Missing keys can
leave a recovery process alive for inspection while readiness stays unavailable;
this is fail-closed behavior, not a successful initialization.

SIGTERM and SIGINT perform the native bounded Drain and publish a Graceful
Shutdown Record before exit 0. Set the Docker/Compose/Kubernetes stop allowance
longer than `runtime.shutdown_grace_seconds`. A second signal, SIGKILL or expired
stop allowance requires crash recovery. SIGHUP uses the same transactional
configuration reload as the native executable. Read-only root operation requires
writable data/secrets mounts and disposable runtime state; backups and restore
staging require separately declared qualified paths with sufficient headroom.

Use the same `repository`, `backup`, `backup restore`, `verify`, `doctor`, `keys`
and `upgrade` commands documented in `docs/operations/`. Stop the service for
commands requiring exclusive offline ownership and run one-shot commands with
the same UID, configuration, data and secrets mounts. Run server-side operations
through the native authenticated APIs/CLI, with credentials on protected input.
A live-directory copy or container filesystem export is not a verified Backup
Snapshot.

Before replacement, create and independently verify a Backup Snapshot and retain
its key custody. Stage the complete signed candidate and configuration's
`release.installation` references; follow the native Upgrade preflight,
Quiescent Upgrade Snapshot, automatic Drain and offline publication procedure.
After successful publication, replace the container with the authenticated
candidate digest, reuse the exact roots/UID/configuration, and confirm readiness
and retained queries. Do not force an old image over a newer persistent format.
Use the reported recovery plan on failure. Restore only into fresh, distinct
qualified roots with the correct recovery keys. See `upgrades.md`, `restore.md`
and `local-key-recovery.md` for the authoritative steps and failure classes.

Stop and remove the container to uninstall. Removing an image or container does
not remove explicitly named data/secrets volumes. Retain both, configuration,
trust, backups and numeric ownership for reinstall. Deleting volumes is a
separate explicit destructive operation.

## Build-only construction and qualification

The Linux native archive jobs build the GNU executable twice from independent
source checkouts on native AMD64 and ARM64 runners. This image consumes those
exact archives. The runtime base and BuildKit are pinned by digest. The [Mozilla CA bundle](https://curl.se/docs/caextract.html) is pinned by its dated URL and SHA-256; the recipe updates that explicit input when the root store changes. Build with
`SOURCE_DATE_EPOCH=0`, disable BuildKit's separate optional attestation manifests,
and export one uncompressed OCI filesystem layer for the canonical verifier:

```console
docker buildx build --no-cache --provenance=false --sbom=false --build-arg SOURCE_DATE_EPOCH=0 \
  --output type=oci,dest=image.tar,compression=uncompressed \
  --file deploy/oci/Dockerfile DIRECTORY_CONTAINING_VERIFIED_NATIVE_ARCHIVE
```

That directory contains `native.tar.gz`. Export each independent build separately.
Extract the native layouts, then use `Dockerfile.index` with explicit
`native-amd64=oci-layout://ABSOLUTE_LAYOUT_DIRECTORY` and
`native-arm64=oci-layout://ABSOLUTE_LAYOUT_DIRECTORY` build contexts and
`--platform linux/amd64,linux/arm64`. This standard BuildKit step combines
immutable native descriptors offline and executes no foreign-architecture code.
It performs no registry publication.

The existing Release Inventory carries each `OciImage` manifest, its single
functional layer as `payload`, its configuration blob, and the `OciIndex` JSON.
Bind the exact source/toolchain/runtime inputs, checksums, dependency inventories,
SPDX and CycloneDX SBOMs, license policy, independent payloads and build provenance
through the existing release construction commands. Sign only with delegated
release/publication identities authorized by the independently installed root.
Use the standard public-key OCI/Cosign publication profile and bundled
transparency inclusion proofs described in `docs/operations/release-trust.md`.
The final index and both images need their own immutable digest and detached
manifest-bound publication proofs. Do not put final-manifest receipts inside the
inventory, which would create a hash cycle.

CI's private protocol signatures exercise the existing complete offline verifier
with actual OCI bytes and tampering; they are not project release signatures or
publication. CI also runs arbitrary-UID/read-only/one-time-claim/health/signal/key
loss recovery tests against the image, and the shared installed retained-record
flow covering ingestion, Complete query, verification, Backup, fresh Restore and
Upgrade. Its test harness and signal helper are separate read-only test mounts,
not shipped tools. Successful CI qualifies the tested construction; a completed
published release still requires the full authenticated release inventory and
real project trust/proofs. This implementation ticket publishes nothing.
