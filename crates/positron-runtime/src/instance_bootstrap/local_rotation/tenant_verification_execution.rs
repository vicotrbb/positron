//! One admitted target-only execution shared by foreground and native maintenance.
use super::{InitializedInstance, LocalKeyRotationFailure, TenantKeyVerificationProgress};
use positron_governance::{Identity, TenantKeyRotationStage, tenant_key_rotation_audit_intent};
use positron_kernel::{
    Catalog, EnvelopeVerificationPublication, MaintenanceExecution, RootRewrapSession,
};

impl InitializedInstance {
    pub(crate) fn complete_tenant_key_verification_execution(
        &self,
        catalog: &Catalog<'_>,
        execution: &MaintenanceExecution<'_>,
        epoch: u64,
    ) -> Result<TenantKeyVerificationProgress, LocalKeyRotationFailure> {
        let session = RootRewrapSession::admit(&self._authority)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        let tenant = execution
            .task()
            .scope()
            .tenant_id()
            .ok_or(LocalKeyRotationFailure::Authentication)?;
        let coordinator = self.maintenance_coordinator();
        let basis = catalog
            .pin()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        if epoch < 2
            || basis
                .next_unmigrated_ledger_scope(tenant, epoch)
                .map_err(|_| LocalKeyRotationFailure::Authentication)?
                .is_some()
        {
            return Err(LocalKeyRotationFailure::Busy);
        }
        let scope = execution
            .next_envelope_verification_scope(&basis, self.instance, epoch)
            .map_err(|_| LocalKeyRotationFailure::Busy)?;
        let identity =
            Identity::open(&basis).map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let original = identity
            .tenant_key_envelope(tenant)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        if self
            .key
            .tenant_key_epoch(self.instance, tenant, original)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?
            != epoch
            || self
                .key
                .pending_tenant_key_epoch(self.instance, tenant, original)
                .map_err(|_| LocalKeyRotationFailure::Authentication)?
                .is_some()
        {
            return Err(LocalKeyRotationFailure::Busy);
        }
        let protection = if let Some(scope) = scope {
            let target = session
                .retain_active_tenant_envelope(&self.key, self.instance, tenant, original)
                .map_err(|_| LocalKeyRotationFailure::Authentication)?;
            Some(
                session
                    .tenant_segment_key(&self.key, self.instance, scope, &target)
                    .map_err(|_| LocalKeyRotationFailure::Authentication)?,
            )
        } else {
            None
        };
        let progress = execution
            .verify_and_checkpoint_envelope_at_basis(
                coordinator,
                catalog,
                &basis,
                protection,
                EnvelopeVerificationPublication::new(
                    epoch,
                    self.rotation_transaction()?,
                    Some(
                        tenant_key_rotation_audit_intent(
                            TenantKeyRotationStage::Verified,
                            tenant,
                            epoch,
                            self.administrator,
                        )
                        .map_err(|_| LocalKeyRotationFailure::InvalidInput)?,
                    ),
                ),
            )
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        let current = catalog
            .pin()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        self.record_catalog_generation(current.number());
        Ok(TenantKeyVerificationProgress {
            complete: progress.is_complete(),
            examined: progress.examined_segments(),
        })
    }
}
