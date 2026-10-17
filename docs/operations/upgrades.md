# Upgrade an instance without losing acknowledged data

Use the configured signed candidate and the existing registered Backup
Repository. A native Upgrade interrupts service. The deployment owner replaces
the executable after offline publication; Positron does not download or replace
its own executable.

## Stage the release

Install the independently trusted Ed25519 Project Trust Root as a 32-byte file.
Keep that file separate from the instance Integrity Identity and client TLS
trust files. Obtain the current and candidate signed manifests through your
release process. Release manifest authoring and distribution tooling belongs
to issue #113.

Configure `[release.installation]` in the canonical configuration document:

```toml
[release.installation]
project_trust_root_file = "/etc/positron/release-root.pub"
current_manifest_file = "/etc/positron/current-release.manifest"
candidate_manifest_file = "/var/lib/positron-staging/candidate.manifest"
candidate_artifact_files = [
  "/var/lib/positron-staging/positron",
  "/var/lib/positron-staging/schema",
  "/var/lib/positron-staging/compatibility",
  "/var/lib/positron-staging/sbom",
  "/var/lib/positron-staging/provenance"
]
query_credential_file = "/run/positron/query-credential"
```

List candidate artifact files in the exact signed inventory order. Use absolute
paths without symlink components. Protect the Query credential file according
to the canonical protected-file policy. The credential stays in memory during
admission and startup verification and is absent from durable Upgrade status.
When any tenant is readable under the ordinary Query lifecycle policy, admission
requires a currently authorized Query credential. An instance with no queryable
tenants may omit it; startup still verifies integrity and readability. Keep the
credential valid through replacement, or rotate its protected file contents at
the same configured reference before resuming target verification.

Validate the configuration with `positron config validate`. Restart to install
changed release references. Keep a verified recovery bundle and a registered
Backup Repository available before requesting the Upgrade.

The signed source-version allowlist must include the executing source version.
The native artifact bytes and product version must match the current manifest.
The current-format path requires matching supported persistent and Backup
formats. A format change or an unpublished transition is refused before Drain.
The repository's current `0.0.0` build identity does not establish a published
release or a migration edge.

## Request the Upgrade

Send the System Administration credential through protected standard input.
Use the candidate manifest digest and the current Catalog generation returned
by inspection:

```console
positron upgrade start --endpoint HOST:PORT --server-name NAME --trust-file TLS_CA_FILE --credential-stdin --candidate-manifest DIGEST --repository-id UUID --retention-seconds 3600 --expected-generation GENERATION --idempotency-key UUID
```

Retain the operation ID. If transport fails, use `positron upgrade lookup` with
the same idempotency key before issuing another request. Exact replay returns
the original accepted intent. A changed request under that key is refused.

Use `positron upgrade status --operation-id ID` with the same transport and
credential options. Status includes exact release, artifact, configuration,
repository, snapshot, and progress bindings. The native Process owner performs
the existing Drain after intent commits. A phase label alone never proves a
completed Drain.

## Continue the offline operation

After the source process exits, continue under exclusive volume ownership:

```console
positron upgrade offline advance --config /etc/positron/positron.toml --operation-id ID --seconds 30
positron upgrade offline status --config /etc/positron/positron.toml --operation-id ID
```

Repeat `advance` until the stage is `Publishing`. Each call stops between
admitted provider turns at its deadline. An in-flight turn retains its existing
provider deadline. Nonterminal work remains resumable. If trusted recovery time
or capacity is unavailable, retain the operation ID and retry after recovery.
No caller may replace trusted time with wall time.

Offline continuation authenticates the committed final Drain marker and
unchanged native frontiers. It creates the post-Drain snapshot and independently
verifies its exact repository and manifest before publication.

Publish the requalified installed candidate:

```console
positron upgrade offline publish --config /etc/positron/positron.toml --operation-id ID
```

Stop the offline command before replacing files. Install the exact signed
candidate executable and its current manifest through the deployment owner.
Keep the configured paths stable. Start the target process with the canonical
configuration. The target verifies its actual executing artifact, startup
integrity, and a bounded Query through the existing tenant authority before it
reports `Succeeded` or opens data listeners. The probe uses the trusted recent
one-hour Query Time window and the normal admitted query CPU budget. An empty
window is a valid query result. The probe does not compare historical result
sets across versions. Startup integrity separately checks persisted readability.
If no query-readable tenant exists, startup records that outcome without
creating one.

## Cancel or recover a failed target

Before publication, request cancellation with the current operation revision
and a fresh hexadecimal 16-byte follow-up key:

```console
positron upgrade offline cancel --config /etc/positron/positron.toml --operation-id ID --idempotency-key HEX --expected-operation-revision REVISION
```

Offline status reads the authenticated operation without starting mutable
services, including after cancellation or success. An identical cancellation key
replays the original result without another publication. If conservative trusted
time precedes the last transition, a new cancellation remains resumable and must
wait for trusted elapsed time.

Active child Backup work must finish through its owner before cancellation. Completed snapshot and independent
verification records remain reachable while an active Upgrade still needs to
attach their receipt. Once the parent durably owns that evidence, ordinary
completed-operation lookup retention applies to the children.
Cancellation does not undo a published release.

For a same-format failed target with valid quiescent proof, select the measured
original source artifact explicitly. Run the source executable with its original
signed current manifest installed, then request the audited selection:

```console
positron upgrade offline rollback --config /etc/positron/positron.toml --operation-id ID --idempotency-key HEX --expected-operation-revision REVISION
```

The deployment owner installs the selected source artifact. If the quiescent
proof is no longer valid, obtain the retained exact snapshot reference with
`positron upgrade offline restore-reference`. This read authenticates the retained
Catalog receipt and exact snapshot binding without reopening mutable services
or requiring the current data frontier to remain valid. The receipt records the
completed independent verification; it does not prove that repository objects
and keys remain available now. The existing Restore workflow qualifies them
again on fresh target storage. Do not overwrite the existing volume with an
incompatible artifact.
