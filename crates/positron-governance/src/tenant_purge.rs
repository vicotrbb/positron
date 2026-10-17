//! Live purge uses the same permanent identity authority as authenticated restore.
use super::*;
use positron_domain::lifecycle::TenantLifecycleState;
use positron_kernel::{CatalogObject, CatalogSnapshot, TenantKeyReclamationProof};
impl TenantAdministration {
    /// The governance gate for physical live-key reclamation. Kernel owns the
    /// exact-file authority; only this owner interprets tenant lifecycle and
    /// permanent identity reservations.
    pub fn reclaim_live_purge(
        catalog: &positron_kernel::Catalog<'_>,
        tenant: TenantId,
        proof: [u8; 32],
    ) -> Result<TenantKeyReclamationProof, TenantAdministrationFailure> {
        Self::validate_live_purge(catalog, tenant, proof)?;
        catalog
            .reclaim_tenant_key_objects(tenant, proof)
            .map_err(map_catalog)
    }

    pub fn begin_live_purge_inventory(
        catalog: &positron_kernel::Catalog<'_>,
        tenant: TenantId,
        proof: [u8; 32],
    ) -> Result<positron_kernel::TenantKeyInventory, TenantAdministrationFailure> {
        Self::validate_live_purge(catalog, tenant, proof)?;
        catalog
            .begin_tenant_key_inventory(tenant, proof)
            .map_err(map_catalog)
    }
    pub fn reclaim_live_purge_step(
        catalog: &positron_kernel::Catalog<'_>,
        tenant: TenantId,
        proof: [u8; 32],
        cursor: Option<&[u8]>,
    ) -> Result<positron_kernel::TenantKeyReclamationStep, TenantAdministrationFailure> {
        Self::validate_live_purge(catalog, tenant, proof)?;
        catalog
            .reclaim_tenant_key_objects_step(tenant, proof, cursor)
            .map_err(map_catalog)
    }
    fn validate_live_purge(
        catalog: &positron_kernel::Catalog<'_>,
        tenant: TenantId,
        proof: [u8; 32],
    ) -> Result<(), TenantAdministrationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        if !matches!(
            Self::lifecycle_state(&snapshot, tenant)?.0,
            TenantLifecycleState::Purging | TenantLifecycleState::Purged
        ) || !Self::restore_purge_exclusions(&snapshot)?
            .iter()
            .any(|v| v.tenant_id() == tenant && v.proof_digest() == proof)
        {
            return Err(TenantAdministrationFailure::InvalidInput);
        }
        for id in snapshot.object_identities() {
            if Self::is_tenant_key_object(
                snapshot
                    .object(id)
                    .map_err(map_catalog)?
                    .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
                tenant,
            )? {
                return Err(TenantAdministrationFailure::InvalidInput);
            }
        }
        Ok(())
    }

    pub fn lifecycle_state(
        snapshot: &CatalogSnapshot,
        tenant: TenantId,
    ) -> Result<(TenantLifecycleState, ResourceGeneration), TenantAdministrationFailure> {
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        if governance.tenant() == tenant {
            return Ok((
                governance.lifecycle(),
                ResourceGeneration::new(governance.lifecycle_generation())
                    .map_err(|_| TenantAdministrationFailure::InvalidInput)?,
            ));
        }
        for id in snapshot.object_identities() {
            if let Some(record) = super::tenant_purge_record::decode(
                snapshot
                    .object(id)
                    .map_err(map_catalog)?
                    .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
            )? && record.tenant == tenant
            {
                return Ok((TenantLifecycleState::Purged, record.generation));
            }
        }
        let state = crate::tenant_quota_record::tenant_lifecycle_record(snapshot, tenant)?
            .ok_or(TenantAdministrationFailure::InvalidInput)?;
        Ok((state.state, state.generation))
    }

    /// Identifies recoverable canonical tenant key records, including history.
    pub fn is_tenant_key_object(
        bytes: &[u8],
        tenant: TenantId,
    ) -> Result<bool, TenantAdministrationFailure> {
        if bytes.starts_with(b"POSGOV") {
            let record =
                positron_kernel::CatalogGovernanceObject::decode(bytes).map_err(map_catalog)?;
            return Ok(record.tenant() == tenant
                && !record.tenant_key_envelope().is_empty()
                && !record.tenant_key_envelope().starts_with(b"POSBPD01"));
        }
        if crate::tenant_quota_record::is_tenant_record(bytes) {
            let record = crate::tenant_quota_record::tenant_record_metadata(bytes)?;
            return Ok(record.tenant == tenant && !record.envelope.starts_with(b"POSBPD01"));
        }
        Ok(false)
    }
    /// The caller atomically publishes this replacement with the kernel's exact
    /// key-reclamation descriptor and its governed durable-operation audit.
    pub fn live_purge_objects(
        snapshot: &CatalogSnapshot,
        tenant: TenantId,
        proof: [u8; 32],
        operation: [u8; 16],
        accepted_at: u64,
    ) -> Result<Vec<CatalogObject>, TenantAdministrationFailure> {
        let inspection = Self::inspect(snapshot, tenant)?;
        if inspection.lifecycle() != TenantLifecycleState::Purging {
            return Err(TenantAdministrationFailure::InvalidInput);
        }
        let exclusion = Self::restore_purge_exclusions(snapshot)?
            .into_iter()
            .find(|v| v.tenant_id() == tenant)
            .map(Ok)
            .unwrap_or_else(|| {
                RestorePurgeExclusion::new(
                    tenant,
                    TenantSlug::parse_canonical(inspection.slug())
                        .map_err(|_| TenantAdministrationFailure::InvalidInput)?,
                    proof,
                )
            })?;
        let exclusion = if exclusion.operation_id().is_none() {
            exclusion.with_authorization(operation, accepted_at)?
        } else {
            exclusion
        };
        let objects = Self::apply_restore_purge_exclusions(snapshot, &[exclusion])?;
        let mut retained = Vec::new();
        for object in objects {
            let bytes = object.canonical_bytes();
            if positron_policy::IngestPolicy::decode_activated_object(tenant, bytes)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?
                .is_some()
                || crate::api_key_administration::purge_keyring_owner(bytes)
                    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?
                    == Some(tenant)
            {
                continue;
            }
            if bytes.starts_with(b"POSGOV") {
                let governance =
                    positron_kernel::CatalogGovernanceObject::decode(bytes).map_err(map_catalog)?;
                if governance.tenant() == tenant {
                    let credentials = governance
                        .credentials()
                        .iter()
                        .copied()
                        .filter(|value| value.scope_code() == 4)
                        .collect::<Vec<_>>();
                    retained.push(
                        CatalogObject::new(
                            governance
                                .with_credentials(
                                    governance
                                        .credential_generation()
                                        .checked_add(1)
                                        .ok_or(TenantAdministrationFailure::InvalidInput)?,
                                    &credentials,
                                )
                                .map_err(map_catalog)?,
                        )
                        .map_err(map_catalog)?,
                    );
                    continue;
                }
            }
            retained.push(object);
        }
        snapshot
            .without_tenant_segment_objects(retained, tenant)
            .map_err(map_catalog)
    }
    /// Remote registry proof is owned by Backup/Runtime. This boundary additionally
    /// requires the kernel's unforgeable proof that live historical files are gone.
    pub fn complete_live_purge_objects(
        snapshot: &CatalogSnapshot,
        tenant: TenantId,
        proof: &TenantKeyReclamationProof,
    ) -> Result<Vec<CatalogObject>, TenantAdministrationFailure> {
        if proof.tenant_id() != tenant
            || !Self::restore_purge_exclusions(snapshot)?
                .iter()
                .any(|v| v.tenant_id() == tenant && v.proof_digest() == proof.proof_digest())
        {
            return Err(TenantAdministrationFailure::InvalidInput);
        }
        for id in snapshot.object_identities() {
            if Self::is_tenant_key_object(
                snapshot
                    .object(id)
                    .map_err(map_catalog)?
                    .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
                tenant,
            )? {
                return Err(TenantAdministrationFailure::InvalidInput);
            }
        }
        if snapshot
            .governance_object()
            .map_err(map_catalog)?
            .1
            .instance()
            != proof.instance_id().to_bytes()
        {
            return Err(TenantAdministrationFailure::InvalidInput);
        }
        let (state, _) = Self::lifecycle_state(snapshot, tenant)?;
        if state == TenantLifecycleState::Purged {
            return snapshot
                .object_identities()
                .map(|id| {
                    CatalogObject::new(
                        snapshot
                            .object(id)
                            .map_err(map_catalog)?
                            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
                            .to_vec(),
                    )
                    .map_err(map_catalog)
                })
                .collect();
        }
        if state != TenantLifecycleState::Purging {
            return Err(TenantAdministrationFailure::InvalidInput);
        }
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        if governance.tenant() != tenant {
            let (_, current) = Self::lifecycle_state(snapshot, tenant)?;
            let inspection = Self::inspect(snapshot, tenant)?;
            let alias = crate::tenant_quota_record::tenant_alias_record(snapshot, tenant)?
                .and_then(|record| record.alias);
            let terminal = super::tenant_purge_record::encode(
                super::tenant_purge_record::PurgedTenantRecord {
                    tenant,
                    slug: TenantSlug::parse_canonical(inspection.slug())
                        .map_err(|_| TenantAdministrationFailure::InvalidInput)?,
                    generation: ResourceGeneration::new(
                        current
                            .get()
                            .checked_add(1)
                            .ok_or(TenantAdministrationFailure::InvalidInput)?,
                    )
                    .map_err(|_| TenantAdministrationFailure::InvalidInput)?,
                    proof: proof.proof_digest(),
                    alias,
                },
            )?;
            let mut objects = Vec::new();
            for id in snapshot.object_identities() {
                let bytes = snapshot
                    .object(id)
                    .map_err(map_catalog)?
                    .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
                if crate::tenant_quota_record::is_tenant_record(bytes)
                    && crate::tenant_quota_record::tenant_record_metadata(bytes)?.tenant == tenant
                {
                    continue;
                }
                objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog)?);
            }
            objects.push(terminal);
            return Ok(objects);
        }
        let mut objects = Vec::new();
        for id in snapshot.object_identities() {
            let bytes = snapshot
                .object(id)
                .map_err(map_catalog)?
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
            let replacement = if bytes.starts_with(b"POSGOV") && governance.tenant() == tenant {
                if governance.lifecycle() != TenantLifecycleState::Purging {
                    return Err(TenantAdministrationFailure::InvalidInput);
                }
                governance
                    .with_purged_tenant(
                        governance
                            .lifecycle_generation()
                            .checked_add(1)
                            .ok_or(TenantAdministrationFailure::InvalidInput)?,
                        proof.proof_digest(),
                    )
                    .map_err(map_catalog)?
            } else {
                bytes.to_vec()
            };
            objects.push(CatalogObject::new(replacement).map_err(map_catalog)?);
        }
        Ok(objects)
    }
}
