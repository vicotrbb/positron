# Standalone Docker Compose

Compose runs the same minimal OCI image and native configuration contract.
It adds no backend, key generator, database wrapper, operator or sidecar.
Use Docker Compose 2.24.4 or later (integration tests use native Linux AMD64 and
ARM64 Docker runners). A Docker Desktop smoke test does not qualify its host
filesystem as a Primary Data Volume.

## Verify and prepare

Obtain one release's signed manifest, inventory, complete bundle, independent
rebuild, Project Trust, SBOMs and provenance. Verify offline before running:

```console
positron release verify --manifest release.manifest --inventory inventory.json --trust project-trust.json --bundle release --rebuild independent-rebuild --target linux-aarch64
```

Use `linux-x86_64` on AMD64. Install Project Trust independently. Copy the
verified Compose artifact into a private deployment directory as `compose.yaml`.
Release construction generates it with:

```console
positron release compose --inventory inventory.json --out compose.yaml
```

Generation is unsigned construction, not authentication. It pins the exact OCI
index SHA-256 from the canonical inventory and source commit. Measure the
resulting bytes as the inventory's `Compose` artifact and independent payload;
use the existing release construction, signing and offline verification flow.
Release verification refuses any changed deployment, including an altered image
or security setting. Generate again whenever the OCI index changes. No registry
publication occurs in this workflow. The complete release inventory binds the
source, toolchain, targets, checksums, SBOMs, provenance, signatures and independent
compatibility claims through the existing Release Manifest.

Copy the verified native archive's generated `etc/positron.toml.example` to
`config/positron.toml` next to `compose.yaml`. The identical file is also in the
image at `/usr/share/positron/positron.toml.example`. Use its generated reference
and schema. Add these protected references under `[listener]` for each of
`operations`, `api`, `otlp_grpc`, `otlp_http` and `loki_push`:

```toml
operations_tls_certificate_file = "/etc/positron/tls/server.pem"
operations_tls_private_key_file = "/etc/positron/tls/server-key.pem"
```

Replace the `operations` prefix for the other four listeners. Provision a trusted
server certificate with `localhost` in its DNS SAN for the readiness probe,
its private key and the issuing CA at `config/tls/server.pem`,
`config/tls/server-key.pem` and `config/tls/ca.pem`. Include additional SANs for
your clients. Keep TLS enabled. Never put secret values in Compose environment
variables, CLI arguments or the YAML. The directory is mounted read-only and
must already exist. Give UID/GID 65532 access: directories 0700, configuration
and private key 0600, certificates 0644. Do not make key material world-readable.

The default generated data listeners bind loopback. Set `api_bind_address` to
`0.0.0.0:8080`, `otlp_grpc_bind_address` to `0.0.0.0:4317`,
`otlp_http_bind_address` to `0.0.0.0:4318` and `loki_push_bind_address` to
`0.0.0.0:3100` under `[listener]`. Compose publishes these only to host loopback;
review host exposure and certificates before changing that. Operations remains
container-local at `127.0.0.1:13133`. Its native TLS readiness probe needs no
administrator credential. Do not enable Operations mTLS without also replacing
the health probe with an approved client-identity-aware probe.

The generated stop allowance covers the canonical native configuration's maximum
Drain deadline plus a five-second safety margin: currently 3600 + 5 = 3605 seconds
(the default native deadline is 30 seconds). Normal Drain exits as soon as it
finishes; this allowance does not delay a successful stop. Generation reads the
bound from the Rust Configuration Contract and fails if that contract no longer
provides a bounded integer range. Native configuration rejects out-of-range
Drain deadlines, and release construction rejects a shortened generated artifact.
The service has a 2 GiB memory limit,
two CPU limit, 256 PID limit and 64 MiB disposable runtime tmpfs. Configure native
resource reservations and disk headroom for your workload within those ceilings;
change both deployment limits and native budgets when sizing a larger instance.
Named volumes `data` and `secrets` inherit the image's owner-only UID 65532 roots.
Use a qualified local filesystem. Keep the same project name, numeric owner,
configuration and both volumes across replacements. Backups have a separate
explicit `backups` mount at `/var/lib/positron-backups`; provision that mount
owner-only for UID 65532 before using it as a local Backup Repository.

## Initialize and operate

```console
docker compose config
docker compose up --detach --wait --wait-timeout 90
docker compose ps
docker compose stop
docker compose run --rm --no-deps positron bootstrap claim --config /etc/positron/positron.toml
docker compose up --detach --wait --wait-timeout 90
```

Claim output is a credential: capture it in protected custody. Stop before the
one-shot claim because it needs exclusive ownership. It succeeds once and
atomically destroys claim material. Container logs never contain the initial
API key. Truly empty data and secrets initialize through the native transaction;
corrupt, missing or mismatched key/data pairs fail closed. Do not delete state to
make a failed startup look empty.

Ingest and query through the native authenticated API or generated SDK, using
the mounted TLS identity. `docker compose restart` performs native Drain and
recovery. Health is derived from the Operations Listener's authoritative state;
`unhealthy` does not automatically restart a container. `unless-stopped` handles
process exits, while recoverable dependencies can remain alive and not ready.
Use authenticated Doctor and [operational-state.md](../../docs/operations/operational-state.md)
for detail. `docker compose stop` sends SIGTERM to the Rust PID 1, waits for Drain,
and retains volumes. Check successful process exit and the native Graceful
Shutdown Record; a forced kill requires crash recovery.

## Backup, restore and upgrade

Use the native [backup repository](../../docs/operations/repository.md),
[restore](../../docs/operations/restore.md),
[key recovery](../../docs/operations/local-key-recovery.md) and
[upgrade](../../docs/operations/upgrades.md) procedures. Run offline commands with
the service stopped, using `docker compose run --rm --no-deps positron COMMAND
--config /etc/positron/positron.toml`. Run online operations through the native
API/CLI, with protected credential input. Explicitly mount repository, trust,
recovery and candidate files at the paths selected in canonical configuration.
A container export or live volume copy is not a verified Backup Snapshot.

Create and independently verify a Backup Snapshot before upgrade. Stage the full
signed candidate and `[release.installation]` references, perform native Upgrade
preflight and the Quiescent Upgrade Snapshot, then follow its Drain and offline
publication. Before starting the native Upgrade operation, suspend automatic
restart for the planned replacement using
`docker update --restart=no "$(docker compose ps --quiet positron)"`. This lets the
source's automatic Upgrade Drain exit without Docker immediately starting the
old image again. Only after native publication succeeds, install the candidate's
verified generated Compose artifact and its accepted configuration and installed
manifest references. Then run `docker compose up --detach --force-recreate --wait`
to start the candidate image and restore the declared restart policy.
Keep the same volumes and configuration binding, and verify readiness and retained
queries. Never substitute a mutable image tag or force an older image over a
newer writable format. On failure, follow the native reported recovery plan.

Restore into a separate Compose project with fresh data and secrets roots and
its accepted target configuration and recovery keys. Never run two processes
against the same mutable data volume. A retained local-key volume alone is not
an independent recovery copy; preserve verified key recovery material separately.

## Remove and recover

`docker compose down` removes containers and the project network while retaining
named data, secrets and backup volumes. Reinstall with the same project name and
verified deployment to recover them. Keep configuration, trust, ownership and key
recovery material. `docker compose down --volumes` is a separate destructive
choice that removes those volumes; it is not the normal uninstall procedure.

For arbitrary UID operation, provision all writable mounts with the chosen
owner-only UID/GID, disable volume copy-up and match the runtime tmpfs owner and
service user. See the [OCI permission contract](../oci/README.md). Missing TLS,
invalid configuration, mount permissions, exhausted disk or lost keys must be
resolved explicitly; weakening permissions or opting out of encryption is not
recovery.
