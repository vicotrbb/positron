//! Retirement consumes proof under the existing reader-acquisition barrier.
use super::{InitializedInstance, LocalKeyRotationFailure};
use crate::instance_bootstrap::{BackupRepositoryInspection, RecoveryReadiness};
use positron_domain::{
    identity::TenantId,
    routing::{SignalKind, VirtualShardId},
};
use positron_governance::{
    AuthorizedContext, Identity, TenantAdministration, TenantKeyRotationStage,
    tenant_key_rotation_audit_intent,
};
use positron_kernel::{
    ActiveSegmentLedger, CatalogProposal, LedgerFailureCode, RootRewrapSession, SegmentScope,
};

impl InitializedInstance {
    pub fn retire_tenant_key_predecessors(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
    ) -> Result<(), LocalKeyRotationFailure> {
        let session = RootRewrapSession::admit(&self._authority)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        self.inspect_tenant(actor, tenant)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        // Independent verification is checked before any task, envelope or
        // audit mutation. Bundle creation and inspection cannot authorize it.
        if self
            .backup_key_recovery_readiness()
            .map_err(|_| LocalKeyRotationFailure::Custody)?
            != RecoveryReadiness::Verified
        {
            return Err(LocalKeyRotationFailure::Custody);
        }
        let catalog = self.rotation_catalog(&session)?;
        let basis = catalog
            .pin()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        let _copy = catalog
            .reserve_catalog_proposal_copy(&basis)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        BackupRepositoryInspection::from_authenticated_catalog(&basis)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let identity =
            Identity::open(&basis).map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let original = identity
            .tenant_key_envelope(tenant)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let epoch = self
            .key
            .tenant_key_epoch(self.instance, tenant, original)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        if epoch < 2
            || self
                .key
                .pending_tenant_key_epoch(self.instance, tenant, original)
                .map_err(|_| LocalKeyRotationFailure::Authentication)?
                .is_some()
        {
            drop(_copy);
            self.publish_tenant_rotation(
                &catalog,
                &basis,
                actor,
                tenant,
                original,
                TenantKeyRotationStage::RetirementRefused,
            )?;
            return Err(LocalKeyRotationFailure::Busy);
        }
        let retained = session
            .retain_active_tenant_envelope(&self.key, self.instance, tenant, original)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        if retained == original {
            catalog
                .confirm_current_publication()
                .map_err(|_| LocalKeyRotationFailure::Storage)?;
            return Ok(());
        }
        let scope = SegmentScope::new(
            tenant,
            SignalKind::Logs,
            VirtualShardId::new(1).map_err(|_| LocalKeyRotationFailure::InvalidInput)?,
        );
        let protection = session
            .tenant_segment_key(&self.key, self.instance, scope, &retained)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        let guard = match ActiveSegmentLedger::guard_tenant_epoch_retirement(
            &self._authority,
            &catalog,
            tenant,
            &protection,
        ) {
            Ok(guard) => guard,
            Err(failure) if failure.code() == LedgerFailureCode::ConcurrentWriter => {
                drop(_copy);
                self.publish_tenant_rotation(
                    &catalog,
                    &basis,
                    actor,
                    tenant,
                    original,
                    TenantKeyRotationStage::RetirementRefused,
                )?;
                return Err(LocalKeyRotationFailure::Busy);
            },
            Err(failure) if failure.code() == LedgerFailureCode::ResourceAdmissionRefused => {
                return Err(LocalKeyRotationFailure::LimitExceeded);
            },
            Err(_) => return Err(LocalKeyRotationFailure::Authentication),
        };
        if guard.catalog_basis().identity() != basis.identity() {
            return Err(LocalKeyRotationFailure::Busy);
        }
        let objects = TenantAdministration::key_envelope_successor(&basis, tenant, &retained)
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        let audit = tenant_key_rotation_audit_intent(
            TenantKeyRotationStage::Completed,
            tenant,
            epoch,
            actor.principal_id(),
        )
        .map_err(|_| LocalKeyRotationFailure::InvalidInput)?;
        let proposal = CatalogProposal::new(
            self.rotation_transaction()?,
            basis
                .format_epoch()
                .ok_or(LocalKeyRotationFailure::Authentication)?,
            objects,
        )
        .map_err(|_| LocalKeyRotationFailure::Storage)?;
        let commit = match self
            .maintenance_coordinator()
            .consume_envelope_verification_with_catalog_proposal(
                &catalog,
                guard.catalog_basis(),
                tenant,
                epoch,
                proposal,
                audit,
            ) {
            Ok(commit) => commit,
            Err(positron_kernel::MaintenanceFailure::PreconditionFailed) => {
                drop(_copy);
                self.publish_tenant_rotation(
                    &catalog,
                    &basis,
                    actor,
                    tenant,
                    original,
                    TenantKeyRotationStage::RetirementRefused,
                )?;
                return Err(LocalKeyRotationFailure::Busy);
            },
            Err(positron_kernel::MaintenanceFailure::ResourceAdmissionRefused) => {
                return Err(LocalKeyRotationFailure::LimitExceeded);
            },
            Err(_) => return Err(LocalKeyRotationFailure::Storage),
        };
        self.record_catalog_generation(commit.number());
        Ok(())
    }
}
