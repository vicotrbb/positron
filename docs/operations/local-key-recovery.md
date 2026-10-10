# Local-key Recovery Bundles

The offline `positron keys recovery` commands require exclusive ownership of an
initialized instance and its protected local key file. Stop Positron before
running them. Recovery does not overwrite an existing or corrupt root key,
create new key entropy, or include the bundle in ordinary backups.

Create an owner-only directory outside both the data and secrets roots. Its
mode must be 0700; the encrypted bundle and identity input must be owner-only
regular files with mode 0600, with no symbolic links or hard links. Store the
bundle independently from the encrypted data and root key. Each supplied
native age X25519 recipient can recover independently; keep the corresponding
private identities under separate owner control. SSH recipients and plugins
are unsupported.

```console
positron keys recovery create --data-dir /srv/positron/data --secrets-dir /srv/positron/secrets --bundle /secure/recovery/instance.age --recipient age1...
positron keys recovery verify --data-dir /srv/positron/data --secrets-dir /srv/positron/secrets --bundle /secure/recovery/instance.age --identity-file /secure/identity/owner.txt
positron keys recovery inspect --data-dir /srv/positron/data --secrets-dir /srv/positron/secrets --bundle /secure/recovery/instance.age --identity-file /secure/identity/owner.txt
```

Creation prints non-secret instance, root-key, and integrity-key identities.
Record these independently while the instance is trusted. Inspection decrypts
and authenticates the signed inner payload and prints only non-secret metadata.
It does not establish backup readiness. Verification compares the recovered
root with the active root and durably publishes the exact artifact digest and
identity in the existing Catalog, together with a Governance Audit entry.
The recovery startup warning persists until this succeeds and returns if the
root is missing or changed, or the separately stored artifact is removed,
replaced, corrupted, or becomes unsafe. The filesystem-custody warning remains
because theft of both the local root and encrypted data defeats local custody.

Use `--passphrase` instead of recipients or an identity file for the interactive
age scrypt fallback. Positron reads and confirms creation passphrases from an
echo-disabled controlling terminal. It never accepts passphrases from arguments,
environment variables, configuration, redirected input, or logs. Passphrases
must contain 12 to 1024 UTF-8 bytes. Native age uses work factor 18; decryption
rejects a higher advertised factor. The Resource Governor admits the expensive
scrypt work and retains admission through file and Catalog publication.

Recipient rotation creates a new separate artifact and proves recovery before
retiring the predecessor:

```console
positron keys recovery rotate --data-dir /srv/positron/data --secrets-dir /srv/positron/secrets --bundle /secure/recovery/replacement.age --recipient age1... --identity-file /secure/identity/replacement.txt
positron keys recovery retire --data-dir /srv/positron/data --secrets-dir /srv/positron/secrets
```

`rotate` retains the predecessor. `retire` rechecks the exact verified
replacement, records retirement preparation in the Catalog, and unlinks only
the exact predecessor previously verified. Another replacement is rejected
until this retirement finishes. Retirement confirms the predecessor deletion
durably, including when a retry finds it already absent. An interrupted
retirement can be retried;
inspect current state after any storage failure. An interrupted creation can
leave a protected encrypted artifact, which must be verified before readiness
can change. Paths are absolute and bundles cannot be created inside either
instance root.

When the original root file is missing, use the recipient or passphrase and all
six independently recorded trust fields. Do not obtain this trust from the
untrusted bundle. Replace the public placeholder values below with the
previously recorded hexadecimal identities and root creation timestamp:

```console
positron keys recovery import --data-dir /srv/positron/data --secrets-dir /srv/positron/secrets --bundle /secure/recovery/instance.age --identity-file /secure/identity/owner.txt --instance INSTANCE_HEX --root-key-id KEY_ID_HEX --root-created-at UNIX_SECONDS --root-fingerprint ROOT_SHA256_HEX --integrity-public-key ED25519_HEX --integrity-fingerprint INTEGRITY_SHA256_HEX
```

Import authenticates the signed bundle, original bootstrap, current Catalog,
Instance Integrity Key and Governance Audit chain before preparing restoration.
It publishes the recovered root at its authenticated epoch through the existing exclusive staging,
file synchronization, no-replace publication and directory synchronization path,
then reopens the original instance. Wrong recipients, wrong trust, corruption,
or missing input do not initialize or replace custody. A complete authenticated
staging file can resume after a synchronization failure; incomplete or
conflicting staging remains rejected. Recovering the root alone does not
replace the instance data or implement backup restore.

Version 1 restores `local-root-key.v1`. Version 2 restores that file for epoch 1
or `local-root-key.epoch-N.v1` for successor epoch N. A retained original root
is authenticated against the immutable bootstrap anchor before successor import;
import preserves it until local-key retirement completes. An existing successor
target, corrupt or foreign original custody, or a symbolic link is refused before
Catalog restoration preparation. Complete authenticated raw staging can resume;
partial raw staging remains refused on retry and is not repaired automatically.

# Persistent format

Recovery signatures, native age operations and artifact hashing use the internal
Rust Crypto Backend. The binary container is native `age-encryption.org/v1`.
The inner deterministic
Protobuf envelope has field 1 (payload) and field 2 (64-byte Ed25519 signature).
The Instance Integrity Key signs `positron-local-root-recovery-payload-v1\0`
followed by the exact canonical payload before age encryption. The payload's
ordered fields are:

| Field | Value |
| --- | --- |
| 1 | Payload version 1, or version 2 with a stable system KEK recovery envelope |
| 2 | Instance identifier (16 bytes) |
| 3 | Local Root KEK identifier (16 bytes) |
| 4 | Root creation time in Unix seconds |
| 5 | Root fingerprint (32 bytes) |
| 6 | Local Root KEK (32 bytes, encrypted container only) |
| 7 | Local-file provider identifier 1 |
| 8 | Immutable Local Root KEK epoch; version 1 requires 1 |
| 9 | Purpose `local-root-recovery` |
| 10 | Bundle creation time in Unix seconds |
| 11 | Instance Integrity Key public key (32 bytes) |
| 12 | Integrity-key fingerprint (32 bytes) |
| 13 | Repeated canonical sorted native recipients, or single `scrypt` marker |
| 14 | Version 2 only: original bootstrap root identifier (16 bytes) |
| 15 | Version 2 only: original bootstrap root fingerprint (32 bytes) |
| 16 | Version 2 only: original bootstrap root creation time |
| 17 | Version 2 only: canonical local-provider Key Envelope for the stable system KEK (at most 1024 bytes) |

Version 1 remains readable and its canonical encoding is unchanged. Version 2
preserves the original system hierarchy when the active local root changes.
Its system envelope binds the instance, original bootstrap root identity,
current root identity and immutable root epoch, fixed format and root-wrapping
purpose. The root identifier and fingerprint in this payload are independently
pinned by the supplied Recovery Identity; the Instance Integrity signature
also authenticates the original identity and system envelope. Import checks the
complete instance before publishing a recovery route or local root. It refuses
an existing root before writing either. The original initialized bootstrap
remains immutable.

The early bootstrap recovery route is ciphertext in
`.positron-system-key-envelopes.v1` in the data root, separate from plaintext
root custody. Its canonical big-endian layout is eight-byte `POSSEK01`,
16-byte Instance ID, the original bootstrap root identity (16-byte identifier,
32-byte fingerprint, eight-byte creation time), and a two-byte envelope count.
Each entry has that same 56-byte identity layout for its wrapping root,
eight-byte immutable root epoch, four-byte ciphertext length, and opaque
serialized canonical Key Envelope containing an AES-256-KWP Wrapped Key Payload.
The existing provider codec and context verifier own this payload. The stable
system child retains epoch 1; a successor root URI version pins both its key
fingerprint and assigned root epoch. The original epoch-1 URI encoding remains
compatible. There are one to sixteen entries, ordered by
strictly increasing nonzero epoch, in at most 16384 bytes. The active root must
match exactly one route; malformed, duplicate, unavailable or wrong-context
routes fail closed. The original identity is subsequently checked against the
authenticated initialized bootstrap. This object supplies recovery bytes;
Catalog state remains the lifecycle authority.

Import publishes this route through an exclusive owner-only no-follow staging
file, verifies its complete bytes, synchronizes the file, publishes without
replacing an existing final route, and synchronizes the data directory before
publishing root custody. Interrupted uncommitted staging is retryable with the
same authenticated bytes and without replacement entropy. A differing final
route is refused unless it already contains the exact authenticated successor
route and immutable instance anchor. In that case import preserves all existing
route bytes and confirms directory durability before publishing successor custody.

Readers reject unknown versions, noncanonical encodings, duplicate or reordered
fields, trailing data, wrong provider, epoch, purpose, identity or fingerprints,
and invalid signatures. Encrypted input is bounded to 8192 bytes, plaintext to
4096 bytes, and recipient sets to sixteen. Root material stays within opaque
Kernel custody and zeroizing temporary buffers. The format does not claim FIPS
validation or protect against rollback of an independently exported old copy
without externally trusted state.
