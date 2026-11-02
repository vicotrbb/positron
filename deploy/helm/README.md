# Standalone Helm chart

This chart runs one database instance from the standard OCI image without the
Positron Operator. It installs no CRDs, API permissions, controller, shell,
sidecar or second database process. Operator reconciliation, Leases, finalizers,
backup CRDs and two controller replicas belong to issue #121. The copied Operator
requirements in issue #120 do not change the standalone StatefulSet outcome.

## Generate and authenticate

```console
positron release helm --inventory inventory.json --out positron.tgz
```

Generation constructs unsigned bytes. It pins the sole OCI index SHA-256 and
source identity in that canonical Release Inventory; no tag or registry lookup
is used. Measure `positron.tgz` as the `Helm` artifact and independent functional
payload in the existing Release Trust workflow. Construction and verification
reject changed chart bytes, missing independent payloads and differing rebuilds.
The current-build OCI qualification includes the chart in the same inventory,
SBOM, provenance and test-signed manifest. It does not publish a release.

Verify the complete release offline using independently installed Project Trust
before installation; see [Release Trust](../../docs/operations/release-trust.md).
Extract its verified chart. `values.yaml` includes the generated Rust native TOML
example, with only container paths, network binds and TLS file references adapted.
The native Configuration Contract validates the complete file before startup;
Helm's schema validates deployment inputs and does not replace native validation.
Keep secret values out of values files and ConfigMaps. Supply only protected file
references and the name of an existing TLS Secret.

## Storage and installation

Select an independently qualified filesystem-mode StorageClass. Passing Helm
rendering or the native Storage Capability Probe does not qualify an unknown
CSI driver. Every supported combination records the exact Kubernetes patch,
distribution, architecture, CSI driver/version and StorageClass parameters.
The three ReadWriteOnce PVCs hold the Primary Data Volume, native local keys,
and local Backup Repository separately. Retain the numeric UID/GID and PVCs
across replacements. Never share the live data PVC with another process.

Provision `server.pem`, `server-key.pem` and `ca.pem` in a namespace-local Secret.
The certificate must include `localhost` for native Operations probes plus DNS
names used by clients, such as `example-positron.NAMESPACE.svc`. The private key
is projected read-only with mode 0440 for the pod's exclusive fsGroup. Secret
files mount as a whole projected Secret. Probes read the regular CA leaf through
`/etc/positron/tls/..data/ca.pem`, preserving the native final-component no-follow
policy. The native configuration has its own projected directory at
`/etc/positron/config/positron.toml`.

For CA rotation, first publish a bounded overlap bundle containing both old and
new authorities. Wait for the projected generation to become visible and verify
native readiness before replacing the server identity. After replacing the Secret
or ConfigMap, request the existing process-owned reload without replacing the Pod:

```console
kubectl --namespace NAMESPACE exec -i example-positron-0 -- /usr/bin/positron config reload --control-path /run/positron/control/control.sock --credential-stdin < /protected/administrator-credential
```

The input file must contain the current instance system-administrator credential.
Keep it private; the credential is read from stdin and never supplied in arguments.

`status=reload_requested` acknowledges a coalesced request, not successful
application. Verify the active TLS identity and readiness before retiring the old
CA. Invalid certificate/key candidates retain the previous native listener
identity. A malformed or prematurely narrowed probe trust bundle is an operator
error and can fail probes even while the previous listener remains valid. The
Control request is available only in Serving; recovery does not consume it.
Never disable verification or put TLS private bytes in Helm values.

```console
helm show values ./positron.tgz > values.yaml
# Set storageClass and tlsSecret; review canonical configuration and budgets.
helm template example ./positron.tgz -f values.yaml
helm install example ./positron.tgz -f values.yaml --namespace NAMESPACE
kubectl --namespace NAMESPACE wait --for=condition=Ready pod/example-positron-0 --timeout=180s
```

A same-image non-root init container runs `positron bootstrap prepare-storage`
against the effective native configuration. It creates only missing terminal data
and secrets directories with owner-only mode 0700, including on setgid CSI mounts.
Parents must already exist. Safe existing roots stay unchanged; links, unsafe
ownership, modes or ACLs fail closed without repair. It creates no Catalog, key,
claim or database instance. The ordinary server then performs native initialization.

The pod uses Restricted-compatible settings, a non-root numeric identity,
read-only image, no added capabilities, RuntimeDefault seccomp, no API token,
explicit mounts, resource requests/limits and a bounded memory runtime volume.
Data APIs have a ClusterIP Service; Operations stays loopback-only and the
Control Listener remains owner-only. Provision NetworkPolicy/ingress and client
trust according to your environment. The chart does not create public trust.

Startup and liveness use native `doctor --live` over verified TLS. Readiness
uses `doctor --ready` independently. A recoverable dependency outage may stay
alive and not-ready beyond the startup threshold without triggering a readiness-
driven restart loop; only native liveness failure can fail startup or liveness.
Kubernetes sends SIGTERM directly to the binary. The termination allowance is
generated from the Configuration Contract maximum Drain deadline plus five
seconds (currently 3605 seconds); successful Drain exits immediately. No sleep
hook or shell wraps native lifecycle behavior.

## Bootstrap and native operations

Empty matching data and key roots initialize transactionally; inconsistent roots
fail closed. After the server reaches Serving, retrieve the initial credentials
once through its owner-only Control Listener using an exec stream:

```console
umask 077
kubectl --namespace NAMESPACE exec example-positron-0 -- /usr/bin/positron bootstrap claim --control-path /run/positron/control/control.sock > /protected/initial-credentials
```

The CLI validates the socket's ownership, exact mode 0600, non-symlink identity
and connected peer UID. The running instance uses its already-held storage
ownership, authenticates the claim and durably destroys it before returning.
The request has no administrator bearer; filesystem ownership authorizes this
bootstrap-only local operation. Network listeners cannot serve it. Starting,
Recovering, Draining and Fenced phases refuse it without consuming the claim.
No second database process mounts the live PVC. Exec stdout goes directly to
the caller and never enters the server's Pod logs. A second claim fails.
A lost response or failed output after consumption cannot redisplay or recreate
credentials; the CLI never retries destructive retrieval. Keep the captured
file in protected custody. Never run bootstrap claim as a Pod's main command
or a Job: Kubernetes would retain its stdout. The maintenance Job rejects it.

Native [repository](../../docs/operations/repository.md),
[recovery-key](../../docs/operations/local-key-recovery.md),
[restore](../../docs/operations/restore.md), and
[upgrade](../../docs/operations/upgrades.md) procedures remain authoritative.
Online backup uses the running database's authenticated public operation and
never mounts its live PVC in another process. Preserve idempotency keys, operation
IDs and native signed verification receipts across retries. Job completion and
PVC snapshots do not prove an application-verified Backup Snapshot.

Protected native release-installation files, query credentials and recovery
identities may be supplied in `operationInputsClaim`, an explicitly named
pre-provisioned PVC mounted read-only at `/etc/positron/operations`. Native file
ownership, mode, ACL and signature checks remain authoritative. Provision its
private subdirectories as the configured UID/GID with mode 0700 and secret files
0600; Secret projections are appropriate for TLS but do not acquire ownership of
private native recovery identities. The chart never copies, chmods or logs secret
values. Keep these inputs separate from data, keys and repositories. It rejects
references to its own data/key/backup claims as operation inputs.

For a local Backup Repository, provision an owner-only private repository
directory under the separate backup PVC according to the native repository
contract. This is independent of preparing the live data/key roots. Set
`backupClaim` to the source's existing backup PVC for a fresh-target restore;
the target still receives distinct newly allocated data and key PVCs. Never
reference a live data/key claim as a repository or operation input. Known aliases
to the target's own claims are rejected during rendering. Independent cloud
Repository Adapters use their existing native selectors and credentials.

For an offline operation, first update `replicas: 0` with maintenance disabled,
wait for the database pod to terminate, then enable maintenance with a unique
short `name` and explicit native `args`. The Job has no automatic retry; native
exclusive storage ownership independently rejects a concurrent owner. An expired
Job does not cancel or recreate its durable operation. Inspect the native receipt,
then resume using the original IDs. Remove the finished Job before starting the
StatefulSet. Never allow a maintenance pod to overlap a server pod.

Restore uses a separate Helm release and fresh PVCs, with `replicas: 0` until the
native verified restore completes. It rejects initialized or non-empty targets.
Recovery inputs are separately provisioned protected files; never inline them in
Job arguments or values. Local automatic root keys require a separately stored,
created and verified Recovery Bundle before backup is ready. External providers
use their native credentials and recovery contract.

Upgrades are intentional: `OnDelete` prevents Helm from silently rolling a running
instance. Run native signed-release preflight, Drain, quiescent backup verification
and publication under the existing Upgrade procedure before starting the exact
candidate digest. A same-format rollback is explicit and audited. Unsupported
format changes fail before Drain; restoring a verified snapshot uses fresh PVCs.
Changing an image field is not native Upgrade acceptance.

## Removal and qualification

Drain and stop before uninstall. All three PVCs have `helm.sh/resource-policy:
keep`; uninstall retains data, local keys and repository contents. PVC deletion,
repository purge and external key retirement require separate deliberate actions.
Reinstall with the same release name, identity and configuration to reattach;
check ownership and immutable instance bindings first.

Run the real Helm integration tests against a generated chart:

```console
POSITRON_TEST_HELM_CHART=/absolute/positron.tgz python3 deploy/helm/test_chart.py
```

Tests use Python unittest, Helm and PyYAML and parse native TOML independently.
Exact-cluster integration uses only an isolated local cluster with its dedicated
explicit KUBECONFIG. Local kind evidence qualifies only that exact combination;
it does not establish EKS, GKE, AKS, OpenShift, k3s, another architecture, or a
release-wide Kubernetes Conformance Matrix.

The isolated local tuple tested for issue #120 is Kubernetes `v1.37.0`, kind
`v0.33.0`, Linux `arm64`, Debian `13.6`, node image
`kindest/node@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5`.
Its `standard` StorageClass uses `rancher.io/local-path`,
`WaitForFirstConsumer`, and provisioner
`kindest/local-path-provisioner:v20260820-69b56db7`; there is no CSI driver.
Runtime and fixture source `ecdab8793234469d34ada5781fd466b1027336ac`, with
independent `0.0.1` candidate `652ea802932098189137a32ffbcb145c55e1046e`, passed
the native upgrade/TLS/drain, interruption/fencing/backup/restore, and OpenBao
`2.7.1` integration cases. The provider case used verified TLS, a protected limited
renewable token and public migration. It verified cache expiry and cold recovery
by pausing and resuming the same provider process; the cold database process
recovered on the same Pod UID with zero container restarts.

These outcomes cover this local-path tuple and same-process provider outage.
CSI detach/reattach and the managed-platform matrix remain unqualified; provider
restart durability was not exercised. Release acceptance still requires the
complete supported matrix and authenticated release artifacts.
