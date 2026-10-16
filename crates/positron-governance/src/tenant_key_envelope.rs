//! Tenant key epochs remain in the existing canonical governance or tenant record.
use crate::tenant_quota_record::replace_tenant_key_envelope_record;
use crate::{TenantAdministration, TenantAdministrationFailure};
use positron_domain::identity::TenantId;
use positron_kernel::{CatalogObject, CatalogSnapshot};

impl TenantAdministration {
    /// Extracts only the exact authenticated sanitized key references captured
    /// by backup_catalog_objects; no wrapping key or placeholder envelope exists.
    pub fn backup_catalog_key_identities(
        snapshot: &CatalogSnapshot,
    ) -> Result<Vec<(TenantId, u64, [u8; 32])>, TenantAdministrationFailure> {
        let identity = crate::Identity::open(snapshot)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        Self::restore_key_tenant_ids(snapshot)?
            .into_iter()
            .map(|tenant| {
                let bytes = identity
                    .tenant_key_envelope(tenant)
                    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
                if bytes.len() != 64
                    || bytes.get(..8) != Some(b"POSBKR01")
                    || bytes.get(8..24) != Some(tenant.to_bytes().as_slice())
                {
                    return Err(TenantAdministrationFailure::InvalidInput);
                }
                let epoch = u64::from_be_bytes(
                    bytes
                        .get(24..32)
                        .and_then(|value| value.try_into().ok())
                        .ok_or(TenantAdministrationFailure::InvalidInput)?,
                );
                let fingerprint: [u8; 32] = bytes
                    .get(32..64)
                    .and_then(|value| value.try_into().ok())
                    .ok_or(TenantAdministrationFailure::InvalidInput)?;
                if epoch == 0 || fingerprint == [0; 32] {
                    return Err(TenantAdministrationFailure::InvalidInput);
                }
                Ok((tenant, epoch, fingerprint))
            })
            .collect()
    }
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

impl TenantAdministration {
    /// Rehydrates the exact sanitized key inventory only after Data Protection
    /// authenticates each tenant envelope under the captured instance context.
    /// Purge exclusions are applied by the restore owner before publication.
    pub fn restore_catalog_objects(
        snapshot: &CatalogSnapshot,
        custody: &positron_kernel::BootstrapKeyCustody,
        envelopes: &[(TenantId, Vec<u8>)],
    ) -> Result<Vec<CatalogObject>, TenantAdministrationFailure> {
        use crate::tenant_quota_record::{is_tenant_record, tenant_record_metadata};
        let registered = Self::restore_key_tenant_ids(snapshot)?;
        if envelopes.len() != registered.len() {
            return Err(TenantAdministrationFailure::InvalidInput);
        }
        let (governance_id, governance) = snapshot
            .governance_object()
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        let instance = positron_kernel::InstanceId::new(governance.instance())
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        let identity = crate::Identity::open(snapshot)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        let mut recovered = std::collections::BTreeMap::new();
        for (tenant, envelope) in envelopes {
            if !registered.contains(tenant)
                || recovered.contains_key(tenant)
                || envelope.is_empty()
                || envelope.len() > 16_384
            {
                return Err(TenantAdministrationFailure::InvalidInput);
            }
            let (epoch, fingerprint) = custody
                .backup_tenant_key_identity(instance, *tenant, envelope)
                .map_err(|_| TenantAdministrationFailure::InvalidInput)?;
            let mut expected = b"POSBKR01".to_vec();
            expected.extend_from_slice(&tenant.to_bytes());
            expected.extend_from_slice(&epoch.to_be_bytes());
            expected.extend_from_slice(&fingerprint);
            if identity
                .tenant_key_envelope(*tenant)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?
                != expected
            {
                return Err(TenantAdministrationFailure::InvalidInput);
            }
            recovered.insert(*tenant, envelope.as_slice());
        }
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(snapshot.object_count())
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        for id in snapshot.object_identities() {
            let original = snapshot
                .object(id)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
            let bytes = if id == governance_id && !registered.contains(&governance.tenant()) {
                original.to_vec()
            } else if id == governance_id {
                governance
                    .with_tenant_key_envelope(
                        recovered
                            .get(&governance.tenant())
                            .copied()
                            .ok_or(TenantAdministrationFailure::InvalidInput)?,
                    )
                    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?
            } else if is_tenant_record(original) {
                let record = tenant_record_metadata(original)?;
                let Some(envelope) = recovered.get(&record.tenant).copied() else {
                    objects.push(
                        CatalogObject::new(original.to_vec())
                            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
                    );
                    continue;
                };
                let prefix = original
                    .len()
                    .checked_sub(record.envelope.len())
                    .and_then(|size| size.checked_sub(2))
                    .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
                let mut bytes = original
                    .get(..prefix)
                    .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
                    .to_vec();
                bytes.extend_from_slice(&(envelope.len() as u16).to_be_bytes());
                bytes.extend_from_slice(envelope);
                bytes
            } else {
                original.to_vec()
            };
            objects.push(
                CatalogObject::new(bytes)
                    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
            );
        }
        Ok(objects)
    }
}
