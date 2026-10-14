# Native Repository inspection

The local adapter uses the serving process's effective OS identity and an
existing protected directory (0700, owned by that identity). Repository files
are 0600 and opened relative to a retained directory descriptor without
following final-component symbolic links. Directory and identity-file custody
are rechecked before each operation. Credentials are native OS access; there
is no stored filesystem password or impersonation API.

Use the authenticated running owner:

```console
positron repository init --endpoint HOST:PORT --server-name HOST --trust-file CA.pem --credential-stdin --locator /server/repository --repository-id UUID --expected-generation N --idempotency-key UUID
positron repository verify --endpoint HOST:PORT --server-name HOST --trust-file CA.pem --credential-stdin --locator /server/repository --repository-id UUID --expected-generation N --idempotency-key UUID
positron repository doctor --endpoint HOST:PORT --server-name HOST --trust-file CA.pem --credential-stdin --locator /server/repository --repository-id UUID --expected-generation N --idempotency-key UUID
positron repository wait --endpoint HOST:PORT --server-name HOST --trust-file CA.pem --credential-stdin --operation-id HEX --wait-seconds 30
```

Supply the System Administration credential through protected stdin. TLS is
the default; `--allow-plaintext` is an explicit transport opt-out. Locators are
server-local absolute paths, never returned in status or errors. Initialization
requires an empty prefix. Attachment requires the exact repository, instance,
Integrity fingerprint, format, and native-prefix commitment. A foreign prefix
is never overwritten or adopted.

Each mutation uses the existing principal-bound Durable Operation and persisted
Maintenance coordinator. `status` without an operation returns the current
Catalog generation. `status --operation-id HEX` and `lookup --idempotency-key
UUID` inspect an accepted operation; retries retain the original operation.
`cancel --operation-id HEX --expected-generation N --idempotency-key UUID`
cancels before draining. Cancellation after draining reports the existing
irreversible boundary. Worker execution revalidates the original creator's
current System Administration grant. Revocation fails closed before native
provider work. Restart recovers accepted work whose task publication was
interrupted and retains terminal lookup receipts.

Doctor has a 30-second runtime work budget and uses stable operation-owned
objects, upload records, and a separate opaque probe head. It checks immutable
put, duplicate publication, checksum/range, resumable multipart, conditional
head publication, and observable deletion. Cleanup addresses only those exact
probes. Interrupted work resumes the same probes; an unknown acknowledgement
requires inspection or retry of the same operation, never a fabricated success.
A bounded CLI wait expires with an unknown outcome, retaining the operation ID,
retry guidance, and lookup expiry. Local observable deletion does not prove
external snapshot or media erasure; external retention is `not_observable`.

These are provider inspection commands. They do not establish signed backup
registry, restore, permanent purge, or remote provider qualification. Listing
is advisory, with pages of at most 128 entries, 1024 entries of scanning per
call, at most eight active owner-bound cursor streams, and a 30-second lease.
Direct HEAD, checksums, exact immutable references, and CAS establish correctness.
