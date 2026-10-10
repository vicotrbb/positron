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
