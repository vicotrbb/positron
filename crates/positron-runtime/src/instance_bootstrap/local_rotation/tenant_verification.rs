//! Bounded target-only verification uses the existing durable maintenance owner.
use super::{InitializedInstance, LocalKeyRotationFailure};
use positron_domain::identity::TenantId;
use positron_governance::{AuthorizedContext, Identity};
use positron_kernel::{
    EnvelopeVerificationCheckpoint, MaintenancePreconditions, MaintenanceScope, MaintenanceTask,
    MaintenanceTaskClass, MaintenanceTaskId, MaintenanceTaskPhase, MaintenanceTrigger,
    RootRewrapSession,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantKeyVerificationProgress {
    pub(super) complete: bool,
    pub(super) examined: usize,
}
impl TenantKeyVerificationProgress {
    pub const fn is_complete(self) -> bool {
        self.complete
    }
    pub const fn examined_segments(self) -> usize {
        self.examined
    }
}
impl InitializedInstance {
    pub fn advance_tenant_key_verification(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
    ) -> Result<TenantKeyVerificationProgress, LocalKeyRotationFailure> {
        let session = RootRewrapSession::admit(&self._authority)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        self.inspect_tenant(actor, tenant)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let catalog = self.rotation_catalog(&session)?;
        let initial = catalog
            .pin()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        let inspection = catalog
            .reserve_catalog_proposal_copy(&initial)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        let identity =
            Identity::open(&initial).map_err(|_| LocalKeyRotationFailure::Authentication)?;
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
        if epoch < 2
            || initial
                .next_unmigrated_ledger_scope(tenant, epoch)
                .map_err(|_| LocalKeyRotationFailure::Authentication)?
                .is_some()
        {
            return Err(LocalKeyRotationFailure::Busy);
        }
        let coordinator = self.maintenance_coordinator();
        let mut selected = None;
        for status in coordinator
            .statuses()
            .map_err(|_| LocalKeyRotationFailure::Storage)?
        {
            let task = status.task();
            if task.class() != MaintenanceTaskClass::EnvelopeVerification
                || task.scope() != MaintenanceScope::tenant(tenant)
            {
                continue;
            }
            if task.reservations() != positron_kernel::integrity_scrub_resource_claim()
                || !task.inputs().is_empty()
                || !task.outputs().is_empty()
                || task.source_binding().is_some()
                || task.preconditions().resource_generation() != 1
            {
                return Err(LocalKeyRotationFailure::Authentication);
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
                    return Err(LocalKeyRotationFailure::Busy);
                }
            }
            if matches!(
                status.phase(),
                MaintenanceTaskPhase::Failed | MaintenanceTaskPhase::Cancelled
            ) {
                continue;
            }
            if selected.replace(status).is_some() {
                return Err(LocalKeyRotationFailure::Authentication);
            }
        }
        let now = self
            .retention_time
            .inspect_governance_now_seconds()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        let task = if let Some(status) = selected {
            if status.phase() == MaintenanceTaskPhase::Succeeded {
                let checkpoint = status
                    .checkpoint()
                    .ok_or(LocalKeyRotationFailure::Authentication)?;
                let progress = EnvelopeVerificationCheckpoint::from_checkpoint(
                    checkpoint,
                    self.instance,
                    tenant,
                    epoch,
                )
                .map_err(|_| LocalKeyRotationFailure::Authentication)?;
                if !progress.is_complete()
                    || progress.source_identity()
                        != initial
                            .envelope_verification_source_identity(self.instance, status.task())
                            .map_err(|_| LocalKeyRotationFailure::Authentication)?
                {
                    return Err(LocalKeyRotationFailure::Busy);
                }
                return Ok(TenantKeyVerificationProgress {
                    complete: true,
                    examined: 0,
                });
            }
            status.task().clone()
        } else {
            let task = MaintenanceTask::with_contract(
                MaintenanceTaskId::new(
                    self.key
                        .random_identifier()
                        .map_err(|_| LocalKeyRotationFailure::Custody)?,
                )
                .map_err(|_| LocalKeyRotationFailure::InvalidInput)?,
                MaintenanceTaskClass::EnvelopeVerification,
                MaintenanceScope::tenant(tenant),
                MaintenanceTrigger::Event,
                MaintenancePreconditions::new(initial.number(), 1)
                    .map_err(|_| LocalKeyRotationFailure::InvalidInput)?,
                Vec::new(),
                Vec::new(),
                positron_kernel::integrity_scrub_resource_claim(),
            )
            .map_err(|_| LocalKeyRotationFailure::InvalidInput)?;
            coordinator
                .submit_and_persist(&catalog, task, now)
                .map_err(|_| LocalKeyRotationFailure::Storage)?
        };
        drop(inspection);
        let execution = coordinator
            .start_envelope_verification_task_with_reservation_and_persist(
                &catalog,
                &self._authority,
                now,
                self.retention_time.status().state()
                    == positron_kernel::LifecycleClockState::ClockUncertain,
                task.identity(),
            )
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?
            .ok_or(LocalKeyRotationFailure::Busy)?;
        let result = self.complete_tenant_key_verification_execution(&catalog, &execution, epoch);
        if result.is_err() {
            execution
                .release_for_same_process_recovery(coordinator)
                .map_err(|_| LocalKeyRotationFailure::Storage)?;
        }
        result
    }
}
