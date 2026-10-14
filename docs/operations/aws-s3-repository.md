# AWS S3 Repository

The adapter supports AWS general-purpose S3 buckets through the native Rust
SDK's S3 API `2006-03-01`, SDK `1.152.0` and behavior version `v2026_01_12`.
The target binds the bucket, published regional HTTPS endpoint, region,
12-digit expected bucket owner and an explicitly owned prefix. Every native
request carries the expected owner. Custom S3-compatible endpoints, directory
buckets and credential-bearing selectors are rejected. The region allowlist is
an explicit snapshot of the AWS regional endpoints supported by this adapter;
an unknown region fails before credential resolution.

Use the existing authenticated running Repository management command with all
five selector flags: `--aws-bucket`, `--aws-region`, `--aws-endpoint`,
`--aws-expected-owner`, `--aws-prefix`. These replace `--repository-path`.
API credentials still arrive through protected stdin and verified TLS is the
default. AWS credentials are resolved and renewed by the standard native chain,
including workload identity and protected native configuration. They are never
operation parameters, Repository Identity fields, diagnostics or status output.
Acceptance, idempotency, expected generation, cancellation, restart, wait and
terminal lookup retain the existing Administration and Maintenance owners.

Initialization refuses a nonempty or incompletely observed prefix, including
historical object versions and delete markers hidden from current-object
listing. A bounded complete empty version inventory is required before Identity
publication; denied or unavailable history inspection cannot authorize adoption. Identity is
conditionally published and subsequently read directly. Missing observations
cannot disprove an uncertain publication. Object identifiers are full SHA-256
content identities; native ETags remain private conditional tokens. Range reads
use native HEAD and conditional Range GET with exact returned extent and length,
and return a checksum of the selected bytes. They do not qualify the full
object's checksum. Full metadata inspection verifies all returned content.

Multipart input remains bounded to the interface's 64 MiB object limit. The
adapter uses 5 MiB native parts in a unique owned staging object, verifies the
completed staging bytes, then conditionally publishes the immutable final
object. The provider recovery record binds target, upload plan, staging selector
and a per-attempt nonce. An uncertain native Create with no exact owned upload
observation remains `OutcomeUnknown`; an empty advisory listing never authorizes
a duplicate Create. A crash after the requested checkpoint but before the native
Create can therefore require operator reconciliation. Recovery never adopts an
unrelated upload. Aborting and final cleanup validate owned records and object
versions before deleting them. Work limits produce explicit `LimitExceeded`;
they are not a total repository capacity limit.

Bucket versioning, Object Lock defaults and applicable lifecycle rules are
reported as observed, unavailable or unobservable. Object metadata additionally
reports retention mode and expiry, legal hold, and event hold from the same
verified GetObject response. Missing protection headers are unobservable,
including when native permissions hide them. Malformed or future values remain
unavailable. Doctor reports these controls only for its owned probe object;
initialization and verify do not invent a global object-protection observation.
Successful probe cleanup cannot qualify hidden external retention. Delete
reconciles exact native versions and refuses retention or legal-hold denial;
it never sets the governance-retention bypass header. Backup/restore and tenant
cryptographic purge retain their separate workflow authorities.

# Real-service qualification

The real AWS integration case is explicitly ignored and **UNRUN** in the current
local validation. Pure SDK metadata/format tests, local filesystem conformance,
localhost administration tests and ASan fuzzing do not prove AWS conformance.
No emulator is a qualification target.

Before running, obtain explicit authorization for a disposable, previously
empty prefix in a real designated bucket, its region/endpoint/account owner,
versioning mode, lifecycle/retention expectations, and a native workload identity.
Do not discover credentials or create buckets automatically. The test's opt-in
is a prerequisite check, not authorization. The prepared command is:

```console
cargo test --locked -p positron-backup --features test-support --test aws_s3_conformance real_aws_s3_passes_shared_and_native_recovery_cases -- --ignored --exact
```

Set `POSITRON_RUN_REAL_AWS_S3=explicitly-authorized-disposable-prefix` and the
non-secret `POSITRON_AWS_S3_BUCKET`, `POSITRON_AWS_S3_REGION`,
`POSITRON_AWS_S3_ENDPOINT`, `POSITRON_AWS_S3_EXPECTED_OWNER`,
`POSITRON_AWS_S3_PREFIX` selectors only after that authorization. The case uses
real Kernel/Maintenance resource owners, initialization/cold attachment, the
shared conformance suite and Doctor, two-owner conditional CAS, a 6 MiB native
multipart upload, and managed interruptions around native Create, Complete and
final object publication. It reads and deletes its owned object/head/upload
artifacts and explicit historical versions. The immutable prefix Identity is
retained. It does not change bucket configuration or retention controls.

The scoped identity needs bucket read inspection (`s3:ListBucket`,
`s3:GetBucketLocation`, `s3:GetBucketVersioning`, `s3:GetBucketObjectLockConfiguration`,
`s3:GetLifecycleConfiguration`, `s3:ListBucketMultipartUploads`,
`s3:ListBucketVersions`) and prefix-scoped object actions (`s3:GetObject`,
`s3:GetObjectVersion`, `s3:PutObject`, `s3:DeleteObject`, `s3:DeleteObjectVersion`,
`s3:AbortMultipartUpload`, `s3:ListMultipartUploadParts`,
`s3:GetObjectRetention`, `s3:GetObjectLegalHold`). Native credential resolution
may require the designated workload identity's own STS/SSO permissions. Do not
grant bucket configuration writes or governance bypass for this case.

Acceptance still requires real-service evidence for the designated SDK/service
version and target: permission denial, wrong owner/region, credential renewal,
native throttling, delayed/stale observations, checksum corruption, all ambiguous
publication/cleanup windows and configured legal hold/retention/lifecycle
outcomes. Controlled negative IAM/retention/corruption scenarios require separate
explicitly authorized fixtures and permissions. These criteria remain pending;
the prepared happy-path/recovery case alone cannot qualify them.

The native API contracts are documented in the AWS [GetObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html),
[conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html),
[multipart upload](https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html)
and [Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
documentation. These contracts guide the implementation and do not replace
measured qualification on the designated target.

## Historical-prefix refusal fixture

The prepared real case also requires `POSITRON_AWS_S3_FOREIGN_HISTORY_PREFIX`,
a separately authorized, nonoverlapping prefix in the same bucket/region/owner.
The operator must prepare this fixture independently: use an enabled-versioning
bucket, put a small non-secret diagnostic object beneath that prefix, then
perform an ordinary current-object delete without specifying a version ID.
Verify bounded `ListObjectsV2` shows no current object and bounded
`ListObjectVersions` shows the retained object version and delete marker; there
must be no Repository Identity or multipart upload. Retain those exact version
IDs for the before/after preservation check. The scoped workload identity needs
read inspection on this second prefix, not permission to mutate it.

The ignored native case invokes initialize and expects `ForeignPrefix`, then
attach and expects `NotFound` for Identity. It performs no delete on the foreign
fixture. After execution the operator must independently verify the same exact
version/marker IDs remain and no Identity version was published. A missing or
incomplete bounded inventory is not qualification evidence. This fixture and
its preparation/verification require explicit authorization; no actions have
been executed here. Ordinary current deletion is insufficient cleanup because
versions remain; subsequent fixture disposal must name only the operator-owned
versions and marker IDs under separately approved cleanup scope.

## Optional local simulation

A separately named, ignored test can exercise native SDK calls against a
loopback-only Moto server using literal dummy credentials. This test-support
constructor accepts a loopback socket address, retains the same Kernel resource
owner and bounded HTTP body handling, and never reads the native credential
chain or configuration. It does not change the production target parser,
regional HTTPS endpoint requirement or immutable target commitment.

The observed compatible XML context is official Moto image
`ghcr.io/getmoto/motoserver:5.1.22`, digest
`sha256:1e3802c95726373544967b428201c548f0247c15b00db2d96a5ba0a77d8643b8`,
which reports version `5.1.22.dev`. Run it as a disposable container with no host
mounts, a loopback-only published port, 512 MiB memory, one CPU and 128 processes.
Create a disposable bucket named `positron-102-simulation` in `us-east-1` and
enable versioning using explicit dummy credentials:

```console
docker run --detach --rm --name positron-102-moto --memory 512m --cpus 1 --pids-limit 128 --publish 127.0.0.1:0:5000 ghcr.io/getmoto/motoserver@sha256:1e3802c95726373544967b428201c548f0247c15b00db2d96a5ba0a77d8643b8
docker port positron-102-moto 5000
docker exec positron-102-moto python -c 'import boto3; s=boto3.client("s3",endpoint_url="http://127.0.0.1:5000",region_name="us-east-1",aws_access_key_id="test",aws_secret_access_key="test"); s.create_bucket(Bucket="positron-102-simulation"); s.put_bucket_versioning(Bucket="positron-102-simulation",VersioningConfiguration={"Status":"Enabled"})'
```

Pass the reported loopback socket to:

```console
POSITRON_S3_SIMULATOR_ADDRESS=127.0.0.1:5000 cargo test --locked -p positron-backup --features test-support --test aws_s3_conformance local_s3_simulation_checks_objects_cas_and_unverifiable_multipart -- --ignored --exact
```

Use the actual published port. The test verifies object/range/checksum/listing,
conditional registry updates and owned version cleanup. It also submits a 6 MiB
multipart object and asserts that unverifiable completion retains its owned
upload record and publishes no final object. Moto advertises a multipart
composite SHA-256 value without the checksum type needed for full-body
verification; both the native Rust SDK and an independent boto3 read refuse it.
The shared full Doctor/conformance run therefore failed in this context. A newer
image tagged `5.2.0` reported `5.1.23.dev` and returned an incompatible multipart
XML root; its failure was preserved rather than normalized.

These are limited simulation results, not AWS qualification or a successful
Doctor/multipart recovery result. Expected-owner enforcement, real IAM,
credential renewal, retention and service consistency still require the
separately authorized real-service cases above. Stop and remove only the
disposable test container when finished; no cloud configuration is needed.
