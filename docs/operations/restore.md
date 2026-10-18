# Restore a verified snapshot into fresh storage

Stop the target process. Create separate empty data and secrets directories owned
by its OS identity with mode 0700. Restore holds the Primary Data Volume lock;
concurrent startup or another restore owner must wait. An initialized instance,
unrelated Catalog, foreign file or unsafe link is refused. Restore does not merge
with existing data.

Prepare a canonical configuration file whose storage roots name those directories.
Use the same file, source identities, recovery input and idempotency key for every
retry. The accepted target configuration becomes active after restore; ordinary
startup still refuses later immutable changes. Obtain the source instance, root identity and integrity public key from
independently recorded recovery output, rather than trusting repository contents.
Use the original snapshot ID and exact signed manifest checksum from its backup
receipt. The repository must still retain that snapshot.

For a local Recovery Bundle, keep the age identity in a separate owner-only 0600
file inside an owner-only 0700 directory. Its absolute path must have no symbolic
link components. The bundle is separate from the repository. Passphrases are read
only from the protected interactive terminal using `--passphrase` instead of
`--identity-file`; secret values are never accepted in arguments.

```console
positron backup restore start --config /target/positron.toml --locator /repository --repository-id UUID --snapshot-id HEX --expected-manifest-checksum HEX --idempotency-key UUID --instance HEX --root-key-id HEX --root-created-at N --root-fingerprint HEX --integrity-public-key HEX --integrity-fingerprint HEX --bundle /protected/source.age --identity-file /protected/identity.age
```

`start` accepts the durable operation and prints its ID and revision. It performs
no background work after the command exits. Add `--wait-seconds 60` to drive it
immediately, or repeat the same inputs with `wait`. `wait` defaults to 60 seconds;
its supported range is 1–86400 seconds. Deadline expiry retains the same operation
and staged target. Run it again with the original identity and idempotency key.

For native provider recovery, configure the native root provider in the target
configuration, omit `--bundle` and its unlock options, and supply
`--source-root-key-id HEX --source-root-fingerprint HEX
--source-root-created-at N --provider-epoch N`. These identify the source wrapping
anchor and selected overlay epoch; the ordinary `--root-*` fields independently
pin the recovered active root. Native provider credentials remain in that
provider's existing credential mechanism. Restore unwraps SYSTEM custody through
the provider before authenticating the full signed Registry ancestry.

The repository target flags use the same native target forms as repository
inspection:

| Adapter | Target options replacing `--locator` |
| --- | --- |
| AWS S3 | `--aws-bucket --aws-region --aws-endpoint --aws-expected-owner --aws-prefix` |
| Google Cloud Storage | `--gcs-bucket --gcs-project-number --gcs-location --gcs-prefix` |
| Azure Blob | `--azure-account --azure-container --azure-prefix` |

Supply a value for every target option. Bucket, account, region, owner, location
and prefix must match the registered repository identity. Pre-key GCS/Azure
access uses read-only adapter authority; it cannot initialize, upload, delete or
change repository heads.

Use `status` with the same inputs to authenticate an already accepted receipt.
It refuses an unknown fresh target and never accepts or advances work. Optional
`--operation-id HEX` requires that exact operation. A cancelled or failed restore
remains offline; its original target is not a new empty restore destination.

Use `cancel` with the same inputs plus `--expected-operation-revision N` and a
separate `--cancellation-key UUID`. A stale revision refuses without changing the
operation. Cancellation is allowed before the publication phase. Public output
includes status, phase, progress, revision, cancellation disposition, irreversible
boundary, retry guidance and the signed verification report address when present.
Add `--output json` to any restore action for a stable JSON object. It contains
`kind`, `operation_revision`, the public `operation` view, `terminal_error_code`,
and `verification_report`, which is the signed report object's checksum or null.
The operation view uses the same snake-case status, phase, retry, cancellation,
boundary and lookup-expiry fields as other administrative operations. Accepted
operation failures and wait deadlines print the current operation before returning
a nonzero exit code. Recovery secrets and provider credentials are omitted.

Every source ciphertext object is verified, including objects later excluded by
current signed Purge Tombstones. Exclusions block resurrection and reserve tenant
identities; they do not assert completed managed key destruction. A new tombstone
head during staging fences publication; if the staged exclusion plan has changed,
the accepted restore fails and the target stays offline.

`Succeeded` records the irreversible verified Catalog publication. Final root
custody and bootstrap-gate synchronization follow. If that step is interrupted,
ordinary startup remains blocked. Retry the exact restore to finish publication
from the authenticated receipt, then start Positron normally and validate queries
with recovered credentials. Logs, traces, policies, API-key hashes and original
governance audit history are recovered; provider credentials, TLS private keys
and other external secrets must be supplied independently.

Local KMIP, GCS and Azure simulator tests exercise recovery and adapter behavior.
They are simulation evidence and do not establish real-cloud deployment or
credential qualification.
