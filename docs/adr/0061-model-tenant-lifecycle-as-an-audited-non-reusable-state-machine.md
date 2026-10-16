# Model tenant lifecycle as an audited non-reusable state machine

Every Release 1 Tenant has an immutable random Tenant ID, immutable unique non-reusable Tenant Slug, mutable display name, tenant-bound principals, and durable lifecycle state. The default tenant uses the same transactional creation path as every other tenant. `Active` permits scoped traffic, `ReadOnly` drains and rejects ingestion while preserving reads, `Suspended` closes tenant data traffic while preserving system-administrator recovery, `Purging` is irreversible, and `Purged` retains only identity, signed purge state, and governance evidence. Retention continues for read-only and suspended tenants; Release 1 does not infer a legal hold. Creation atomically commits identity, policies, quotas, retention, Tenant KEK, state, and audit evidence and uses idempotency to prevent duplicate retries. Principals cannot be reassigned. Quota reductions never delete data, while retention reductions require a bound impact preview and confirmation. Every transition and policy mutation commits with its Governance Audit Record, destructive operations require Tenant ID, and purged IDs and slugs can never redirect old credentials, data, cursors, or backups to a new tenant.

For the default tenant, the mutable lifecycle authority remains `POSGOV`. For a provisioned secondary tenant, it is the tenant's canonical `POSTNR` record. Epoch-2 `POSTNR02` carries a distinct lifecycle generation after the existing policy generation, so lifecycle, quota, and policy compare-and-swap state remain independent. A legacy `POSTNR01` reads with lifecycle generation `1` and upgrades to `POSTNR02` only when its first lifecycle successor commits. The upgrade preserves the authenticated immutable tenant identity and opaque key envelope exactly. `Purging` is published through this lifecycle authority, while transition to `Purged` remains unavailable until the separately authorized cryptographic purge-completion operation proves it.

Cryptographically verified completion replaces a secondary tenant's `POSTNR`
with a minimal `POSTPT01` terminal identity, lifecycle generation, purge proof,
and immutable alias-reservation evidence. It carries no tenant profile, quota,
retention policy, credential, or KEK. For the default tenant, `POSGOV09` retains
the same terminal identity and the independent instance administration and
integrity authority, omitting the default tenant's profile, quota, retention,
data credentials, and KEK. Readers expose absent profile resources explicitly;
they do not invent policy defaults. These terminal identities remain members
of the immutable tenant directory and reserve their IDs, slugs, and aliases.

The canonical permanent purge reservation additionally retains the original
purge Operation ID and acceptance time as authenticated governance evidence,
independently of expiring Durable Operation history. `POSTRG04` carries this
optional evidence; legacy `POSTRG03` reservations explicitly lack it and must
be reconciled from authenticated purge authority before signing new repository
barriers. Restore imports the original authority from the verified signed
repository tombstone. Later corroborating tombstones cannot overwrite the
canonical original authorization. Future Repository admission uses this same
permanent inventory to install restoration exclusions before activation.
