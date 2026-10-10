//! Tenant write cutover uses its existing envelope owner and authenticated active metadata.
use super::{InitializedInstance, LocalKeyRotationFailure};
use positron_domain::identity::TenantId;
use positron_governance::{
    AuthorizedContext, Identity, TenantAdministration, TenantKeyRotationStage,
    tenant_key_rotation_audit_intent,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogProposal, CatalogSnapshot, RootRewrapSession,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantKeyRotationStatus {
    active_epoch: u64,
    successor_epoch: Option<u64>,
}
impl TenantKeyRotationStatus {
    pub const fn active_epoch(self) -> u64 {
        self.active_epoch
    }
    pub const fn successor_epoch(self) -> Option<u64> {
        self.successor_epoch
    }
}
impl InitializedInstance {
    fn tenant_rotation_status(
        &self,
        tenant: TenantId,
        envelope: &[u8],
    ) -> Result<TenantKeyRotationStatus, LocalKeyRotationFailure> {
        Ok(TenantKeyRotationStatus {
            active_epoch: self
                .key
                .tenant_key_epoch(self.instance, tenant, envelope)
                .map_err(|_| LocalKeyRotationFailure::Authentication)?,
            successor_epoch: self
                .key
                .pending_tenant_key_epoch(self.instance, tenant, envelope)
                .map_err(|_| LocalKeyRotationFailure::Authentication)?,
        })
    }
    pub fn tenant_key_rotation_status(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
    ) -> Result<TenantKeyRotationStatus, LocalKeyRotationFailure> {
        let session = RootRewrapSession::admit(&self._authority)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        self.inspect_tenant(actor, tenant)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let catalog = self.rotation_catalog(&session)?;
        let basis = catalog
            .pin()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        let identity =
            Identity::open(&basis).map_err(|_| LocalKeyRotationFailure::Authentication)?;
        self.tenant_rotation_status(
            tenant,
            identity
                .tenant_key_envelope(tenant)
                .map_err(|_| LocalKeyRotationFailure::Authentication)?,
        )
    }
    pub fn begin_tenant_key_rotation(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
    ) -> Result<TenantKeyRotationStatus, LocalKeyRotationFailure> {
        let session = RootRewrapSession::admit(&self._authority)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        self.inspect_tenant(actor, tenant)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let catalog = self.rotation_catalog(&session)?;
        let basis = catalog
            .pin()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        let identity =
            Identity::open(&basis).map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let envelope = identity
            .tenant_key_envelope(tenant)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let status = self.tenant_rotation_status(tenant, envelope)?;
        if status.successor_epoch.is_some() {
            return Ok(status);
        }
        let prepared = session
            .prepare_tenant_envelope(&self.key, self.instance, tenant, envelope)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let status = self.tenant_rotation_status(tenant, &prepared)?;
        self.publish_tenant_rotation(
            &catalog,
            &basis,
            actor,
            tenant,
            &prepared,
            TenantKeyRotationStage::Prepared,
        )?;
        Ok(status)
    }
    pub fn advance_tenant_key_rotation(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
    ) -> Result<TenantKeyRotationStatus, LocalKeyRotationFailure> {
        let session = RootRewrapSession::admit(&self._authority)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        self.inspect_tenant(actor, tenant)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let catalog = self.rotation_catalog(&session)?;
        let basis = catalog
            .pin()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        let identity =
            Identity::open(&basis).map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let envelope = identity
            .tenant_key_envelope(tenant)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let status = self.tenant_rotation_status(tenant, envelope)?;
        let Some(_) = status.successor_epoch else {
            return Ok(status);
        };
        if let Some(scope) = basis
            .next_active_ledger_scope(tenant)
            .map_err(|_| LocalKeyRotationFailure::Storage)?
        {
            let protection = session
                .tenant_segment_key(&self.key, self.instance, scope, envelope)
                .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
            ActiveSegmentLedger::open_for_maintenance_with_retention_time(
                &self._authority,
                &self.retention_time,
                &catalog,
                scope,
                protection,
            )
            .map_err(|_| LocalKeyRotationFailure::Storage)?
            .seal()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        }
        let current = catalog
            .pin()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        if current
            .next_active_ledger_scope(tenant)
            .map_err(|_| LocalKeyRotationFailure::Storage)?
            .is_some()
        {
            self.publish_tenant_rotation(
                &catalog,
                &current,
                actor,
                tenant,
                envelope,
                TenantKeyRotationStage::Progress,
            )?;
            return Ok(status);
        }
        let activated = session
            .activate_tenant_envelope(&self.key, self.instance, tenant, envelope)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        self.publish_tenant_rotation(
            &catalog,
            &current,
            actor,
            tenant,
            &activated,
            TenantKeyRotationStage::Cutover,
        )?;
        self.tenant_rotation_status(tenant, &activated)
    }
    pub(super) fn publish_tenant_rotation(
        &self,
        catalog: &Catalog<'_>,
        basis: &CatalogSnapshot,
        actor: AuthorizedContext,
        tenant: TenantId,
        envelope: &[u8],
        stage: TenantKeyRotationStage,
    ) -> Result<(), LocalKeyRotationFailure> {
        let _copy = catalog
            .reserve_catalog_proposal_copy(basis)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        let status = self.tenant_rotation_status(tenant, envelope)?;
        let epoch = status.successor_epoch.unwrap_or(status.active_epoch);
        let objects = TenantAdministration::key_envelope_successor(basis, tenant, envelope)
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        let transaction = self.rotation_transaction()?;
        let intent = tenant_key_rotation_audit_intent(stage, tenant, epoch, actor.principal_id())
            .map_err(|_| LocalKeyRotationFailure::InvalidInput)?;
        let proposal = CatalogProposal::new(
            transaction,
            basis
                .format_epoch()
                .ok_or(LocalKeyRotationFailure::Authentication)?,
            objects,
        )
        .map_err(|_| LocalKeyRotationFailure::Storage)?;
        let commit = catalog
            .commit(basis.identity(), proposal, Some(intent))
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        self.record_catalog_generation(commit.number());
        Ok(())
    }
}
