//! Cooperative cancellation retains one existing Maintenance cleanup owner.
use super::*;
use positron_backup::{BackupCleanupPlan, BackupCleanupProgress, BackupCleanupReason};
pub(in crate::services) struct CancellationWork {
    pub(super) owner: owner::BackupOwner,
    state: State,
}
enum State {
    RecoverClaim,
    FindCandidate,
    Scan(BackupCleanupPlan),
    Delete(BackupCleanupProgress),
    Cleaning(Option<BackupCleanupProgress>),
}
fn validate(
    progress: BackupCleanupProgress,
    operation: DurableOperation,
) -> Result<(), ServiceFailure> {
    if progress.owner() != operation.operation_id().to_bytes()
        || progress.snapshot_id() != progress.owner()
        || progress.reason() != BackupCleanupReason::Cancellation
    {
        return Err(ServiceFailure::CorruptState);
    }
    Ok(())
}
pub(super) fn complete(
    services: &ServiceHandle,
    execution: &mut MaintenanceExecution<'_>,
    work: &mut Option<BackupWork>,
    operation: DurableOperation,
    actor: positron_governance::AuthorizedContext,
    cancellation: Option<&crate::TaskCancellation>,
) -> Result<bool, ServiceFailure> {
    let binding = RepositoryOperationBinding::from_execution(execution)
        .map_err(super::super::super::maintenance::map_failure)?;
    if !matches!(work, Some(BackupWork::Cancellation(_))) {
        *work = None;
        let mut owner = owner::BackupOwner::open(services, execution, operation)?;
        if !owner.registry_ready(services, execution, 0)? {
            return Ok(false);
        }
        let (_, owner_checkpoint) = checkpoint::current(services, execution, binding)?;
        let (_, progress) = checkpoint::unpack(&owner_checkpoint)?;
        let state = if let Some(proof) = progress.strip_prefix(b"POSBKC02") {
            let completed = owner
                .runtime
                .block_on(
                    owner
                        .publisher(0)
                        .map_err(provider_failure)?
                        .verify_cleanup_checkpoint(proof),
                )
                .map_err(provider_failure)?;
            validate(completed, operation)?;
            State::Cleaning(Some(completed))
        } else if progress == b"POSBKC01" {
            State::Cleaning(None)
        } else {
            State::RecoverClaim
        };
        *work = Some(BackupWork::Cancellation(Box::new(CancellationWork {
            owner,
            state,
        })));
    }
    let Some(BackupWork::Cancellation(work)) = work.as_mut() else {
        return Err(ServiceFailure::CorruptState);
    };
    let retained = match &work.state {
        State::Scan(plan) => plan.retained_memory_bytes().map_err(provider_failure)?,
        _ => 0,
    };
    if !work.owner.registry_ready(services, execution, retained)? {
        return Ok(false);
    }
    let publisher = work.owner.publisher(0).map_err(provider_failure)?;
    let snapshot = binding.operation_id();
    match &mut work.state {
        State::RecoverClaim => {
            work.state = match work
                .owner
                .runtime
                .block_on(publisher.cleanup_for_owner(snapshot))
                .map_err(provider_failure)?
            {
                Some(progress) => {
                    validate(progress, operation)?;
                    State::Delete(progress)
                },
                None => State::FindCandidate,
            };
        },
        State::FindCandidate => {
            if let Some(candidate) = work
                .owner
                .runtime
                .block_on(publisher.cancellation_candidate(snapshot))
                .map_err(provider_failure)?
            {
                work.state = State::Scan(
                    work.owner
                        .runtime
                        .block_on(
                            publisher
                                .prepare_cancellation(snapshot, candidate.manifest().checksum()),
                        )
                        .map_err(provider_failure)?,
                );
            } else {
                checkpoint(services, execution, binding, b"POSBKC01")?;
                work.state = State::Cleaning(None);
            }
        },
        State::Scan(plan) => {
            let started = std::time::Instant::now();
            let mut bytes = 4 * 1024 * 1024u64;
            let mut finished = false;
            for step in 0..8 {
                if cancellation.is_some_and(crate::TaskCancellation::is_cancelled) {
                    return Err(ServiceFailure::Cancelled);
                }
                let charge = plan.next_upload_reconciliation_bytes();
                if step != 0 && charge.is_some_and(|charge| charge > bytes) {
                    break;
                }
                finished = work
                    .owner
                    .runtime
                    .block_on(publisher.scan_cancellation_step(plan))
                    .map_err(provider_failure)?;
                bytes = bytes.saturating_sub(charge.unwrap_or(0));
                if finished
                    || charge.is_none()
                    || bytes == 0
                    || work.owner.identity.provider_kind() != "localFilesystem"
                    || started.elapsed() >= std::time::Duration::from_millis(10)
                {
                    break;
                }
            }
            if finished {
                let progress = work
                    .owner
                    .runtime
                    .block_on(publisher.claim_cancellation(plan))
                    .map_err(provider_failure)?;
                validate(progress, operation)?;
                work.state = State::Delete(progress);
            }
        },
        State::Delete(progress) => {
            if progress.complete() {
                let proof = publisher
                    .cleanup_checkpoint(*progress)
                    .map_err(provider_failure)?;
                let mut marker = b"POSBKC02".to_vec();
                marker.extend_from_slice(&proof);
                checkpoint(services, execution, binding, &marker)?;
                work.state = State::Cleaning(Some(*progress));
            } else {
                *progress = work
                    .owner
                    .runtime
                    .block_on(
                        publisher.delete_expired_step(snapshot, progress.manifest().checksum()),
                    )
                    .map_err(provider_failure)?;
            }
        },
        State::Cleaning(progress) => {
            if operation.status() == DurableOperationStatus::Cancelled
                || (operation.status() == DurableOperationStatus::Failed
                    && operation.backup_cleanup_receipt().is_some())
            {
                if let Some(progress) = progress {
                    work.owner
                        .runtime
                        .block_on(
                            publisher.acknowledge_expiry(snapshot, progress.manifest().checksum()),
                        )
                        .map_err(provider_failure)?;
                }
                let _gate = services.catalog_operation()?;
                let catalog = services
                    .open_maintenance_catalog()
                    .map_err(|_| ServiceFailure::CatalogUnavailable)?;
                let coordinator = services.instance.maintenance_coordinator();
                if operation.status() == DurableOperationStatus::Cancelled {
                    coordinator
                        .cancel_and_persist(&catalog, execution.task().identity())
                        .map_err(super::super::super::maintenance::map_failure)?;
                }
                execution
                    .complete_and_persist(coordinator, &catalog, false)
                    .map_err(super::super::super::maintenance::map_failure)?;
                return Ok(true);
            }
            let _gate = services.catalog_operation()?;
            let catalog = services
                .open_maintenance_catalog()
                .map_err(|_| ServiceFailure::CatalogUnavailable)?;
            #[cfg(test)]
            let cleanup = if test_stops::armed(test_stops::StopPoint::CaptureCleanupBatch)? {
                positron_kernel::with_catalog_publication_fault_after(
                    positron_kernel::CatalogPublicationFault::RemoveBackupCaptureRegistry,
                    0,
                    || catalog.release_backup_capture(snapshot, binding.intent_digest()),
                )
            } else {
                catalog.release_backup_capture(snapshot, binding.intent_digest())
            };
            #[cfg(not(test))]
            let cleanup = catalog.release_backup_capture(snapshot, binding.intent_digest());
            let cleanup = cleanup.map_err(|_| ServiceFailure::StorageUnavailable);
            if cleanup.is_err() {
                #[cfg(test)]
                test_stops::after_cleanup_error(cancellation)?;
            }
            if !cleanup? {
                return Ok(false);
            }
            let now = services
                .maintenance_status_now()
                .map_err(|_| ServiceFailure::StorageUnavailable)?;
            if let Some(progress) = progress {
                let basis = catalog
                    .pin()
                    .map_err(|_| ServiceFailure::CatalogUnavailable)?;
                let (previous, registration) = positron_backup::BackupRepositoryRegistration::find(
                    &basis,
                    services.instance.instance.to_bytes(),
                    work.owner.identity.repository_id(),
                )
                .map_err(provider_failure)?
                .ok_or(ServiceFailure::CorruptState)?;
                if registration.identity() != &work.owner.identity {
                    return Err(ServiceFailure::CorruptState);
                }
                let successor = registration
                    .with_registry_generation(progress.registry_generation())
                    .and_then(|registration| registration.catalog_object())
                    .map_err(provider_failure)?;
                let receipt = positron_governance::BackupCleanupReceipt::new(
                    snapshot,
                    progress.manifest().checksum(),
                    progress.registry_generation(),
                    progress.deleted_objects(),
                    progress.already_absent_objects(),
                    progress.retained_shared_objects(),
                )
                .map_err(|_| ServiceFailure::CorruptState)?;
                if operation.status() == DurableOperationStatus::Failed {
                    DurableOperationAdministration::complete_backup_failure_cleanup_with_registration(&catalog, actor, operation.operation_id(), receipt, previous, successor, now).map_err(|_| ServiceFailure::CatalogUnavailable)?;
                } else {
                    DurableOperationAdministration::complete_backup_cancellation_with_registration(
                        &catalog,
                        actor,
                        operation.operation_id(),
                        receipt,
                        previous,
                        successor,
                        now,
                    )
                    .map_err(|_| ServiceFailure::CatalogUnavailable)?;
                }
                work.owner.set_trusted(progress.registry_generation());
            } else {
                if operation.status() == DurableOperationStatus::Failed {
                    DurableOperationAdministration::complete_backup_failure_cleanup(
                        &catalog,
                        actor,
                        operation.operation_id(),
                        now,
                    )
                    .map_err(|_| ServiceFailure::CatalogUnavailable)?;
                    execution
                        .complete_and_persist(
                            services.instance.maintenance_coordinator(),
                            &catalog,
                            false,
                        )
                        .map_err(super::super::super::maintenance::map_failure)?;
                    return Ok(true);
                } else {
                    DurableOperationAdministration::complete_backup_cancellation(
                        &catalog,
                        actor,
                        operation.operation_id(),
                        now,
                    )
                    .map_err(|_| ServiceFailure::CatalogUnavailable)?;
                }
            }
            #[cfg(test)]
            test_stops::hit(test_stops::StopPoint::CancellationCommitted, cancellation)?;
        },
    }
    Ok(false)
}
pub(super) fn checkpoint(
    services: &ServiceHandle,
    execution: &mut MaintenanceExecution<'_>,
    binding: RepositoryOperationBinding,
    progress: &[u8],
) -> Result<(), ServiceFailure> {
    checkpoint::persist(services, execution, binding, None, Some(progress))
}
