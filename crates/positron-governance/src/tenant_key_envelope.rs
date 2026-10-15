//! Tenant key epochs remain in the existing canonical governance or tenant record.
use crate::tenant_quota_record::replace_tenant_key_envelope_record;
use crate::{TenantAdministration, TenantAdministrationFailure};
use positron_domain::identity::TenantId;
use positron_kernel::{CatalogObject, CatalogSnapshot};

impl TenantAdministration {
    pub fn key_envelope_successor(
        snapshot: &CatalogSnapshot,
        tenant: TenantId,
        envelope: &[u8],
    ) -> Result<Vec<CatalogObject>, TenantAdministrationFailure> {
        if envelope.is_empty() || envelope.len() > 16_384 {
            return Err(TenantAdministrationFailure::InvalidInput);
        }
        let (identity, governance) = snapshot
            .governance_object()
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        if governance.tenant() != tenant {
            return replace_tenant_key_envelope_record(snapshot, tenant, envelope);
        }
        let replacement = governance
            .with_tenant_key_envelope(envelope)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(snapshot.object_count())
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        for id in snapshot.object_identities() {
            let encoded = if id == identity {
                replacement.clone()
            } else {
                snapshot
                    .object(id)
                    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?
                    .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
                    .to_vec()
            };
            objects.push(
                CatalogObject::new(encoded)
                    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
            );
        }
        Ok(objects)
    }
}

impl TenantAdministration {
    /// Produces the complete immutable Backup Catalog view with recoverable
    /// tenant envelopes replaced by typed Registry key identities. This view is
    /// never published as the live Catalog. The registered tenant set is exact.
    pub fn backup_catalog_objects(
        snapshot: &CatalogSnapshot,
        keys: &[(TenantId, u64, [u8; 32])],
    ) -> Result<Vec<positron_kernel::BackupCatalogObject>, TenantAdministrationFailure> {
        use crate::tenant_quota_record::{is_tenant_record, tenant_record_metadata};
        let registered = Self::registered_tenant_ids(snapshot)?;
        if keys.len() != registered.len()
            || keys.iter().any(|(tenant, epoch, fingerprint)| {
                !registered.contains(tenant) || *epoch == 0 || *fingerprint == [0; 32]
            })
        {
            return Err(TenantAdministrationFailure::InvalidInput);
        }
        for (index, (tenant, _, _)) in keys.iter().enumerate() {
            if keys
                .get(..index)
                .is_some_and(|prior| prior.iter().any(|(other, _, _)| other == tenant))
            {
                return Err(TenantAdministrationFailure::InvalidInput);
            }
        }
        let (governance_id, governance) = snapshot
            .governance_object()
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        let marker = |tenant: TenantId| -> Result<Vec<u8>, TenantAdministrationFailure> {
            let (_, epoch, fingerprint) = keys
                .iter()
                .find(|(key, _, _)| *key == tenant)
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
            let mut bytes = b"POSBKR01".to_vec();
            bytes.extend_from_slice(&tenant.to_bytes());
            bytes.extend_from_slice(&epoch.to_be_bytes());
            bytes.extend_from_slice(fingerprint);
            Ok(bytes)
        };
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(snapshot.object_count())
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        for identity in snapshot.object_identities() {
            let original = snapshot
                .object(identity)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
            let bytes = if identity == governance_id {
                governance
                    .with_tenant_key_envelope(&marker(governance.tenant())?)
                    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?
            } else if is_tenant_record(original) {
                let record = tenant_record_metadata(original)?;
                let prefix = original
                    .len()
                    .checked_sub(record.envelope.len())
                    .and_then(|size| size.checked_sub(2))
                    .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
                let mut bytes = original
                    .get(..prefix)
                    .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
                    .to_vec();
                let marker = marker(record.tenant)?;
                bytes.extend_from_slice(&(marker.len() as u16).to_be_bytes());
                bytes.extend_from_slice(&marker);
                bytes
            } else {
                original.to_vec()
            };
            objects.push(positron_kernel::BackupCatalogObject::new(
                identity,
                CatalogObject::new(bytes)
                    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
            ));
        }
        Ok(objects)
    }
}
