# Google Cloud Storage Repository

The adapter targets native Google Cloud Storage JSON API `v1`, with
`google-cloud-auth` `1.17.0` and the existing admitted Rust HTTP transport.
It supports flat-namespace buckets at `https://storage.googleapis.com`.
Custom endpoints and hierarchical namespaces are rejected. The immutable target
binds the bucket, numeric project owner, exact uppercase bucket location and
owned prefix. Bucket metadata must match every field before attachment.

Use `positron repository init|verify|doctor` with `--gcs-bucket`,
`--gcs-project-number`, `--gcs-location` and `--gcs-prefix`. Choose one target
per request. The serving owner resolves renewable Application Default
Credentials, including native workload identity, through the existing Kernel
Google runtime. Credentials and session URIs never appear in accepted-operation
parameters, status, logs or CLI output. API credentials use protected stdin;
provider transport requires verified TLS.

Objects use immutable content identities, native CRC32C verification and direct
generation-pinned reads. Range responses must match the exact requested extent.
Registry changes compare the current content version and publish with native
`ifGenerationMatch`. An uncertain write remains unknown until direct inspection
verifies the exact expected content. Advisory listing uses bounded native pages
and short-lived, owner-bound opaque cursors.

Resumable input is bounded to 64 MiB and interface parts to 4 MiB. Private
`POSGCU01` recovery frames bind the native target, object, total length, committed
payload checksum, staging selector and creation state. The Kernel authenticates
the frame through its existing Catalog key custody. It encrypts each resumable
session URI as one standard frame under a fresh system-object DEK and immutable
frame sequence, with the DEK wrapped in existing Catalog custody. URI plaintext
and unwrapped key material are never uploaded. These frames
are provider recovery artifacts, not snapshot manifests or a second workflow
journal.

The adapter persists a requested-creation checkpoint before native Create.
An interrupted Create without a durably captured session remains `OutcomeUnknown`
and never authorizes a duplicate session. Known sessions are queried for their
actual committed offset before bounded native chunks resume. Completed staging
bytes must pass full content verification before conditional final publication.
Cleanup authenticates historical recovery frames before cancelling sessions,
verifies owned staging contents and deletes only exact native generations.

Initialization refuses current, noncurrent and observable soft-deleted foreign
contents. Required missing or incomplete inspection fails closed. Bucket
retention, native object protection, event-based holds, versioning, lifecycle and
soft deletion remain distinct typed observations. A temporary hold is reported
through the existing legal-hold observation; event-based hold remains active
until authorized release. GCS retention periods are preserved in seconds.
Absence or unavailable inspection never proves a control disabled.

Soft-deleted generations remain recoverable. Cleanup that still observes them
returns `OutcomeUnknown`; the adapter cannot claim completed managed purge.
It does not change retention, lifecycle, holds, bucket policy or soft-delete
configuration. Signed registry, snapshot, restore and tenant-purge authorities
retain their existing owners and require separate complete-flow qualification.

## Implementation acceptance

Implementation acceptance permits local protocol simulation under ADR 0068.
The non-ignored `simulated_native_protocol_conformance` test runs a bounded
loopback JSON API fixture through the admitted Kernel HTTP transport and the
same Repository and Doctor interface. It uses anonymous credentials and no
cloud discovery. The existing four direct engineering checks and applicable
fuzzing remain required; simulated evidence does not qualify Google IAM,
credential renewal, TLS, or real service controls.

## Optional real-service qualification

The real GCS test is ignored and **UNRUN** without an explicitly authorized
disposable target. Unit format/metadata cases, native admission tests, public
API/CLI tests and fuzzing do not qualify Google Cloud Storage. Simulators provide implementation acceptance, not real-provider qualification.

Before execution, designate a real bucket and project number, exact location,
previously empty owned prefix, versioning/retention/lifecycle/soft-delete
expectations and scoped native workload identity. The prepared happy-path test
requires versioning enabled and current soft deletion/retention that permit
owned probe cleanup. Historical soft-deleted objects still require inspection
when the current policy is disabled. Its opt-in
is a prerequisite check, not authorization:

```console
cargo test --locked -p positron-backup --features test-support --test google_cloud_storage_conformance real_google_passes_shared_and_native_recovery_cases -- --ignored --exact
```

After authorization, set `POSITRON_RUN_REAL_GCS` to
`explicitly-authorized-disposable-prefix`, and provide the non-secret
`POSITRON_GCS_BUCKET`, `POSITRON_GCS_PROJECT_NUMBER`, `POSITRON_GCS_LOCATION` and
`POSITRON_GCS_PREFIX` selectors. Also supply `POSITRON_GCS_FOREIGN_SOFT_PREFIX`
for the separately prepared history fixture below. Do not discover credentials, create a bucket or
change bucket controls automatically. The scoped identity needs bucket metadata
inspection (`storage.buckets.get`), bounded object history/list inspection
(`storage.objects.list`), and owned-prefix object get/create/delete permissions.
Native ADC renewal may need its designated workload identity's token-service
permissions. Do not grant retention override or bucket-policy writes.

The harness uses the existing Kernel/Maintenance owner, shared Repository and
Doctor cases, a 6 MiB resumable object and managed interruptions after native
completion and before final publication. It retains immutable Identity. Failure
can retain owned recovery artifacts and an owner-only local `fixture-keys` file
in the reported temporary custody directory. Keep that custody until owned
session inspection and cleanup finish; inspect the same prefix before retrying.
No real service has been contacted as part of implementation.

Native cases are executable but remain **UNRUN** until their exact fixtures are
separately authorized. The shared/recovery test also checks wrong project and
location, two-owner native CAS, pagination across deletion, cursor ownership and
replay, and a deliberately wrong content-name checksum. The corruption probe is
conditionally created and its exact verified generation is removed; foreign
content never authorizes cleanup.

Complete signed backup, restore, verification and tenant purge acceptance is
blocked on the existing workflow owners: [#107](https://github.com/vicotrbb/positron/issues/107),
[#108](https://github.com/vicotrbb/positron/issues/108),
[#109](https://github.com/vicotrbb/positron/issues/109),
[#110](https://github.com/vicotrbb/positron/issues/110) and
[#111](https://github.com/vicotrbb/positron/issues/111). Repository/Doctor probes
do not implement or qualify those signed workflows.

Native contracts are documented in Google's [object metadata](https://docs.cloud.google.com/storage/docs/json_api/v1/objects),
[conditional object insert](https://docs.cloud.google.com/storage/docs/json_api/v1/objects/insert),
[resumable upload](https://docs.cloud.google.com/storage/docs/performing-resumable-uploads),
[version and soft-deletion listing](https://docs.cloud.google.com/storage/docs/json_api/v1/objects/list)
and [bucket controls](https://docs.cloud.google.com/storage/docs/json_api/v1/buckets).
These references define API behavior; they do not replace measured target evidence.

## Retained soft-history fixture

Prepare `POSITRON_GCS_FOREIGN_SOFT_PREFIX` independently, with separate explicit
authorization. Use a nonoverlapping prefix in the same bucket/project/location.
Create a small non-secret object while soft deletion retains objects, then delete
its exact generation. Disable current soft deletion only under separately
approved bucket-control scope; the retained generation must still have a future
`hardDeleteTime`. The fixture prefix must have no current/noncurrent object or
Repository Identity. Record its name, generation, soft-delete time and hard-delete
time through native inspection before the test.

The harness inspects the retained history while current retention is zero,
expects initialization to refuse the prefix and verifies exact history
preservation afterward. It performs no fixture deletion or bucket-control
change. Grant only read inspection on this second prefix. A missing, denied or
incomplete history inventory is not evidence of absence. The same native case
also exercises interrupted head cleanup with historical generations and rejects
missing-upload reconciliation with an inconsistent object size.

## Independently controlled native fixtures

Use the standard four target selectors above for **one** exact case at a time,
with a separate previously empty owned prefix where the case writes. The marker
`POSITRON_RUN_REAL_GCS_NATIVE_CASE` must equal the listed case name. It is a
prerequisite, not authorization. Invoke only the matching ignored test with
`--exact`; running all ignored tests is not an authorized fixture plan.

| Marker | Test under `controlled_cases::` | Required native fixture |
| --- | --- | --- |
| `denial` | `real_google_native_denial` | Exact designated bucket denied to the scoped ADC identity; read request only. |
| `throttle` | `real_google_native_throttle` | Exact designated bucket with externally controlled native quota exhaustion; at most 16 read requests must observe native 429. No quota or pressure generator is provided. |
| `renewal` | `real_google_native_credential_renewal` | Scoped workload identity with recorded initial token expiry; a native request must succeed after that expiry using the same adapter. |
| `retention` | `real_google_native_retention` | Bucket retention with more than 60 seconds remaining on new objects; delete must be denied and direct content lookup must remain valid. |
| `event-hold` | `real_google_native_event_hold` | Bucket default event-based hold already enabled; the new probe must report UntilRelease and refuse deletion. |
| `lifecycle-conflict` | `real_google_native_lifecycle_conflict` | Independently configured expiration lifecycle plus active bucket retention; policy must preserve both observations and deletion must remain denied. |
| `soft-delete` | `real_google_native_soft_delete` | Native soft deletion enabled without retention/hold blocking deletion; initial cleanup and its retry must both remain OutcomeUnknown while recovery is possible. |
| `prepare-hold` | `real_google_native_prepare_temporary_hold` | Creates one non-secret owned immutable probe and reports its checksum for separately authorized native temporary-hold preparation. |
| `temporary-hold` | `real_google_native_temporary_hold` | Previously prepared probe with native temporary hold enabled; checksum given by `POSITRON_GCS_HELD_OBJECT_CHECKSUM`; direct protection and denied deletion must agree. |
| `ambiguous-create` | `real_google_native_ambiguous_creation` | Disposable target permits native resumable Create; interruption after Create deliberately retains a requested checkpoint with no captured URI. Retry and abort must stay OutcomeUnknown, with no final object. |

For example, after the exact retention target has been approved:

```console
cargo test --locked -p positron-backup --features test-support --test google_cloud_storage_conformance controlled_cases::real_google_native_retention -- --ignored --exact
```

The renewal case requires non-secret
`POSITRON_GCS_INITIAL_TOKEN_EXPIRES_IN_SECONDS` and
`POSITRON_GCS_RENEWAL_DELAY_SECONDS`. The delay must exceed the fixture's recorded
initial expiry and is bounded to two hours; its success depends on that external
expiry precondition. The harness does not inspect token values. Native throttle
is qualified only when the designated service actually returns 429; successful
reads without throttling fail the fixture test rather than claiming success.

Protected, soft-deleted, prepared-hold and ambiguous-session cases intentionally
retain owned provider artifacts and owner-only local custody, even on expected
test success. Preserve the reported custody directory and the same target for
subsequently authorized inspection/cleanup. The harness never releases holds,
changes bucket controls or attempts retention override. A denied or incomplete
inspection is not absence proof. No controlled case has been executed during
implementation.
