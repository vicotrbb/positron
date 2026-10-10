//! A stale verifier is explicitly requeued; its immutable contract is retained.
use super::{InitializedInstance, LocalKeyRotationFailure};
use positron_domain::identity::TenantId;
use positron_governance::{AuthorizedContext, Identity};
use positron_kernel::{
    EnvelopeVerificationCheckpoint, MaintenanceScope, MaintenanceTaskClass, MaintenanceTaskPhase,
    RootRewrapSession,
};
impl InitializedInstance {
    pub fn restart_tenant_key_verification(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
    ) -> Result<(), LocalKeyRotationFailure> {
        let session = RootRewrapSession::admit(&self._authority)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        self.inspect_tenant(actor, tenant)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let catalog = self.rotation_catalog(&session)?;
        let basis = catalog
            .pin()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        let _inspection = catalog
            .reserve_catalog_proposal_copy(&basis)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        let identity =
            Identity::open(&basis).map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let envelope = identity
            .tenant_key_envelope(tenant)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        if self
            .key
            .pending_tenant_key_epoch(self.instance, tenant, envelope)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?
            .is_some()
        {
            return Err(LocalKeyRotationFailure::Busy);
        }
        let epoch = self
            .key
            .tenant_key_epoch(self.instance, tenant, envelope)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        if epoch < 2 {
            return Err(LocalKeyRotationFailure::Busy);
        }
        let coordinator = self.maintenance_coordinator();
        let mut selected = None;
        for status in coordinator
            .statuses()
            .map_err(|_| LocalKeyRotationFailure::Storage)?
        {
            if status.task().class() != MaintenanceTaskClass::EnvelopeVerification
                || status.task().scope() != MaintenanceScope::tenant(tenant)
            {
                continue;
            }
            if let Some(checkpoint) = status.checkpoint() {
                let bound_epoch = checkpoint
                    .opaque_progress()
                    .get(40..48)
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(u64::from_be_bytes)
                    .ok_or(LocalKeyRotationFailure::Authentication)?;
                let progress = EnvelopeVerificationCheckpoint::from_checkpoint(
                    checkpoint,
                    self.instance,
                    tenant,
                    bound_epoch,
                )
                .map_err(|_| LocalKeyRotationFailure::Authentication)?;
                if bound_epoch < epoch
                    && status.phase() == MaintenanceTaskPhase::Succeeded
                    && progress.is_complete()
                {
                    continue;
                }
                if bound_epoch != epoch {
                    return Err(LocalKeyRotationFailure::Authentication);
                }
            }
            if selected.replace(status.task().identity()).is_some() {
                return Err(LocalKeyRotationFailure::Authentication);
            }
        }
        let task = selected.ok_or(LocalKeyRotationFailure::InvalidInput)?;
        coordinator
            .restart_envelope_verification_at_basis(&catalog, &basis, task, epoch)
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        self.record_catalog_generation(
            catalog
                .pin()
                .map_err(|_| LocalKeyRotationFailure::Storage)?
                .number(),
        );
        Ok(())
    }
}
