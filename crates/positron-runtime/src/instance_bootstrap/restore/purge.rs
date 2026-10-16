//! Current signed exclusions are applied before any recoverable tenant key.
use super::*;
use positron_domain::identity::{TenantId, TenantSlug};
use positron_governance::RestorePurgeExclusion;
use positron_kernel::{BackupRestoreOrigin, CatalogObject};
use sha2::{Digest, Sha256};

pub(super) fn apply(
    origin: BackupRestoreOrigin,
    tombstones: &[positron_backup::BackupPurgeTombstone],
    identity: &RepositoryIdentity,
    signer: &positron_kernel::BackupControlSigner,
    available: u64,
    retained: u64,
) -> Result<(BackupRestoreOrigin, Vec<TenantId>), BootstrapFailure> {
    let registered =
        TenantAdministration::registered_tenant_ids(origin.snapshot()).map_err(|_| failure())?;
    let exclusions = tombstones
        .iter()
        .map(|tombstone| {
            let tenant = TenantId::from_bytes(tombstone.tenant()).map_err(|_| failure())?;
            let proof: [u8; 32] = Sha256::digest(
                tombstone
                    .signed_bytes(identity, signer)
                    .map_err(|_| failure())?,
            )
            .into();
            RestorePurgeExclusion::new(
                tenant,
                TenantSlug::parse_canonical(tombstone.slug()).map_err(|_| failure())?,
                proof,
            )
            .and_then(|exclusion| {
                exclusion.with_authorization(tombstone.operation(), tombstone.created_at())
            })
            .map_err(|_| failure())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let excluded = exclusions
        .iter()
        .map(RestorePurgeExclusion::tenant_id)
        .collect::<Vec<_>>();
    let mut objects = Vec::new();
    let mut schemas = Vec::new();
    let mut policies = Vec::new();
    for id in origin.snapshot().object_identities() {
        let bytes = origin
            .snapshot()
            .object(id)
            .map_err(|_| failure())?
            .ok_or_else(failure)?;
        let bound = if bytes.starts_with(b"PSCHEMA1") {
            positron_signals::SchemaCatalog::catalog_memory_bound(bytes).map_err(|_| failure())?
                as u64
        } else if bytes.starts_with(b"PIPACT01") {
            positron_policy::IngestPolicy::activated_object_memory_bound(bytes)
                .map_err(|_| failure())? as u64
        } else {
            0
        };
        if retained
            .checked_add(bound)
            .is_none_or(|peak| peak > available)
        {
            return Err(failure());
        }
        let tenant = if let Some(schema) =
            positron_signals::SchemaCatalog::decode_catalog_object_if_recognized(bytes)
                .map_err(|_| failure())?
        {
            if schemas.contains(&schema.tenant()) {
                return Err(failure());
            }
            schemas.push(schema.tenant());
            Some(schema.tenant())
        } else if let Some(tenant) =
            positron_policy::IngestPolicy::activated_object_tenant(bytes).map_err(|_| failure())?
        {
            if policies.contains(&tenant) {
                return Err(failure());
            }
            policies.push(tenant);
            Some(tenant)
        } else {
            None
        };
        if tenant.is_some_and(|tenant| !registered.contains(&tenant)) {
            return Err(failure());
        }
        if tenant.is_some_and(|tenant| excluded.contains(&tenant)) {
            continue;
        }
        objects.push(CatalogObject::new(bytes.to_vec()).map_err(|_| failure())?);
    }
    let origin = origin
        .with_restored_objects(objects)
        .map_err(|_| failure())?;
    let origin = if exclusions.is_empty() {
        origin
    } else {
        let objects =
            TenantAdministration::apply_restore_purge_exclusions(origin.snapshot(), &exclusions)
                .map_err(|_| failure())?;
        origin
            .with_restored_objects(objects)
            .map_err(|_| failure())?
    };
    let origin = origin
        .without_tenant_segments(&excluded)
        .map_err(|_| failure())?;
    Ok((origin, excluded))
}
