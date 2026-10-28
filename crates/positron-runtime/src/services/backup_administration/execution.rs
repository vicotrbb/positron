//! One admitted Runtime turn advances one bounded capture or native upload step.
// Existing bounded backup cadence; a failed checkpoint may replay this many advances.
pub(super) const MAX_BACKUP_STEP_ADVANCES: usize = 8;
#[path = "execution_cancellation.rs"]
mod cancellation;
#[path = "execution_capture.rs"]
mod capture;
#[path = "execution_checkpoint.rs"]
pub(super) mod checkpoint;
#[path = "execution_owner.rs"]
pub(super) mod owner;
#[path = "execution_retention.rs"]
mod retention;
#[cfg(test)]
#[path = "execution_test_stops.rs"]
pub(in crate::services) mod test_stops;
use super::*;
use positron_backup::{
    BackupCaptureContext, BackupManifest, BackupManifestBuilder, BackupObjectVerification,
    BackupPublicationCheck, BackupPublisher, BackupTransfer, Repository, RepositoryFailure,
    RepositoryIdentity,
};
use positron_governance::{
    BackupOperationReceipt, BackupOperationStage, DurableOperationPhase, DurableOperationStatus,
};
use positron_kernel::{
    BackupCapture, BackupCapturePreparation, BackupControlSigner, MaintenanceExecution,
};
#[cfg(test)]
#[path = "execution_diagnostic_tests.rs"]
mod diagnostic_tests;
pub(in crate::services) enum BackupWork {
    Snapshot(Box<SnapshotWork>),
    Verification(Box<super::verification::VerificationWork>),
    Cancellation(Box<cancellation::CancellationWork>),
    Retention(Box<retention::RetentionWork>),
}
pub(in crate::services) struct SnapshotWork {
    owner: owner::BackupOwner,
    context: BackupCaptureContext,
    capture: Option<BackupCapture>,
    preparation: Option<BackupCapturePreparation>,
    builder: Option<BackupManifestBuilder>,
    manifest: Option<BackupManifest>,
    transfer: Option<BackupTransfer>,
    verification: Option<BackupPublicationCheck>,
    object_verification: Option<BackupObjectVerification>,
    saved_verification: Vec<u8>,
    reservation_established: bool,
    next_key: u32,
}
pub(in crate::services) fn recover_accepted_task(
    services: &ServiceHandle,
    catalog: &positron_kernel::Catalog<'_>,
) -> Result<(), ServiceFailure> {
    let coordinator = services.instance.maintenance_coordinator();
    let mut after = None;
    while let Some(operation) =
        DurableOperationAdministration::next_backup_operation(catalog, after)
            .map_err(|_| ServiceFailure::CorruptState)?
    {
        require_operation(operation, services.instance.instance.to_bytes())?;
        after = Some(operation.operation_id());
        let task = positron_kernel::MaintenanceTaskId::new(operation.operation_id().to_bytes())
            .map_err(|_| ServiceFailure::CorruptState)?;
        match coordinator.status(task) {
            Ok(_) => continue,
            Err(positron_kernel::MaintenanceFailure::UnknownTask) => {},
            Err(failure) => return Err(super::super::maintenance::map_failure(failure)),
        }
        submit(
            &services.instance,
            catalog,
            operation,
            services
                .maintenance_status_now()
                .map_err(|_| ServiceFailure::StorageUnavailable)?,
        )?;
        break;
    }
    Ok(())
}
pub(in crate::services) fn complete(
    services: &ServiceHandle,
    execution: &mut MaintenanceExecution<'_>,
    work: &mut Option<BackupWork>,
    cancellation: Option<&crate::TaskCancellation>,
) -> Result<bool, ServiceFailure> {
    let binding = RepositoryOperationBinding::from_execution(execution)
        .map_err(|_| ServiceFailure::CorruptState)?;
    let id = OperationId::from_bytes(binding.operation_id())
        .map_err(|_| ServiceFailure::CorruptState)?;
    enum Prepared {
        Verification(
            DurableOperation,
            Option<positron_governance::AuthorizedContext>,
        ),
        Retention,
        Snapshot(
            std::ops::ControlFlow<bool, (DurableOperation, positron_governance::AuthorizedContext)>,
        ),
    }
    let prepared = {
        let _gate = services.catalog_operation()?;
        let catalog = services
            .open_maintenance_catalog()
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        let operation = DurableOperationAdministration::inspect(&catalog, id)
            .map_err(|_| ServiceFailure::CorruptState)?
            .ok_or(ServiceFailure::CorruptState)?;
        if operation.kind() == DurableOperationKind::BackupVerification {
            let actor = if operation.status().is_terminal() {
                None
            } else {
                Some(super::verification::prepare(
                    services, execution, operation, &catalog,
                )?)
            };
            Prepared::Verification(operation, actor)
        } else if execution.task().class()
            == positron_kernel::MaintenanceTaskClass::RepositoryCleanup
        {
            Prepared::Retention
        } else {
            Prepared::Snapshot(prepare_snapshot(
                services, execution, work, operation, binding, &catalog,
            )?)
        }
    };
    if let Prepared::Verification(operation, actor) = prepared {
        return super::verification::complete(
            services,
            execution,
            work,
            operation,
            cancellation,
            actor,
        );
    }
    if execution.task().class() == positron_kernel::MaintenanceTaskClass::RepositoryCleanup {
        let (operation, actor) = {
            let _gate = services.catalog_operation()?;
            let catalog = services
                .open_maintenance_catalog()
                .map_err(|_| ServiceFailure::CatalogUnavailable)?;
            let operation = DurableOperationAdministration::inspect(&catalog, id)
                .map_err(|_| ServiceFailure::CorruptState)?
                .ok_or(ServiceFailure::CorruptState)?;
            require_operation(operation, services.instance.instance.to_bytes())?;
            if operation.kind() != DurableOperationKind::BackupRetention
                || operation
                    .backup_binding()
                    .ok_or(ServiceFailure::CorruptState)?
                    .intent_digest()
                    != binding.intent_digest()
            {
                return Err(ServiceFailure::CorruptState);
            }
            let now = services
                .maintenance_status_now()
                .map_err(|_| ServiceFailure::StorageUnavailable)?;
            let actor = DurableOperationAdministration::resume_backup_actor(&catalog, id, now)
                .map_err(|_| ServiceFailure::Unauthorized)?;
            let operation = if operation.status() == DurableOperationStatus::Pending {
                DurableOperationAdministration::begin(&catalog, actor, id, now)
                    .map_err(|_| ServiceFailure::CatalogUnavailable)?
            } else {
                operation
            };
            let operation = if operation.phase() == DurableOperationPhase::Preflight {
                DurableOperationAdministration::advance_backup_retention(
                    &catalog,
                    actor,
                    id,
                    positron_governance::BackupRetentionStage::Scanning,
                    now,
                )
                .map_err(|_| ServiceFailure::CatalogUnavailable)?
            } else {
                operation
            };
            (operation, actor)
        };
        return retention::complete(services, execution, work, operation, actor, cancellation);
    }
    let Prepared::Snapshot(prepared) = prepared else {
        return Err(ServiceFailure::CorruptState);
    };
    let (operation, actor) = match prepared {
        std::ops::ControlFlow::Break(complete) => return Ok(complete),
        std::ops::ControlFlow::Continue(prepared) => prepared,
    };
    if operation.phase() == DurableOperationPhase::BackupCancellation
        || matches!(
            operation.status(),
            DurableOperationStatus::Cancelled | DurableOperationStatus::Failed
        )
    {
        return cancellation::complete(services, execution, work, operation, actor, cancellation);
    }
    if work.is_none() {
        if operation.phase() != DurableOperationPhase::BackupPublication
            && readiness(services)? != crate::RecoveryReadiness::Verified
        {
            return fail(services, actor, id, ServiceFailure::KeyUnavailable);
        }
        let owner = owner::BackupOwner::open(services, execution, operation)?;
        let (context, capture, preparation) =
            capture::prepare(services, execution, operation, &owner.identity)?;
        *work = Some(BackupWork::Snapshot(Box::new(SnapshotWork {
            owner,
            context,
            capture,
            preparation,
            builder: None,
            manifest: None,
            transfer: None,
            verification: None,
            object_verification: None,
            saved_verification: Vec::new(),
            reservation_established: false,
            next_key: 0,
        })));
    }
    let Some(BackupWork::Snapshot(work)) = work.as_mut() else {
        return Err(ServiceFailure::CorruptState);
    };
    if let Some(preparation) = work.preparation.as_mut() {
        work.capture = preparation
            .copy_step(4 * 1024 * 1024)
            .map_err(|failure| super::super::classify_catalog_failure_code(failure.code()))?;
        if work.capture.is_none() {
            return Ok(false);
        }
        work.preparation = None;
    }
    let capture = work.capture.as_ref().ok_or(ServiceFailure::CorruptState)?;
    if work.manifest.is_none() {
        if work.builder.is_none() {
            work.builder = Some(
                BackupManifestBuilder::new(
                    capture,
                    binding.operation_id(),
                    work.owner.identity.clone(),
                    work.context.retention(),
                    work.context.key_context().map_err(capture_failure)?,
                )
                .map_err(capture_failure)?,
            );
        }
        // The authenticated capture index already defines candidate dimensions.
        // Validate its complete control peak and current Registry before hashing
        // any source bytes, so resource re-admission cannot repeatedly redo I/O.
        let external = work
            .context
            .retained_memory_bytes()
            .map_err(provider_failure)?
            .checked_add(
                capture
                    .retained_memory_bytes()
                    .map_err(|_| ServiceFailure::CorruptState)?,
            )
            .and_then(|bytes| bytes.checked_add(checkpoint::MAX_OWNER_FIELD as u64))
            .ok_or(ServiceFailure::CorruptState)?;
        let builder = work.builder.as_ref().ok_or(ServiceFailure::Internal)?;
        let registry_external = external
            .checked_add(builder.retained_memory_bytes().map_err(provider_failure)?)
            .ok_or(ServiceFailure::CorruptState)?;
        if !work
            .owner
            .registry_ready(services, execution, registry_external)?
        {
            return Ok(false);
        }
        work.builder
            .as_ref()
            .ok_or(ServiceFailure::Internal)?
            .preflight(
                &work.owner.publisher(external).map_err(provider_failure)?,
                work.context.keys(),
            )
            .map_err(provider_failure)?;
        work.manifest = work
            .builder
            .as_mut()
            .ok_or(ServiceFailure::Internal)?
            .step(capture, 4 * 1024 * 1024)
            .map_err(capture_failure)?;
        if work.manifest.is_none() {
            return Ok(false);
        }
        work.builder = None;
    }
    let manifest = work.manifest.as_ref().ok_or(ServiceFailure::CorruptState)?;
    if work.transfer.is_none() {
        let (_, owner_checkpoint) = checkpoint::current(services, execution, binding)?;
        let (_, progress) = checkpoint::unpack(&owner_checkpoint)?;
        let (progress, next_key, verification) = checkpoint::decode(progress)?;
        if next_key as usize > work.context.keys().len() {
            return Err(ServiceFailure::CorruptState);
        }
        work.next_key = next_key;
        work.saved_verification = verification.to_vec();
        work.transfer = Some(
            if progress.is_empty() {
                BackupTransfer::start(manifest)
            } else {
                BackupTransfer::decode(progress, manifest)
            }
            .map_err(provider_failure)?,
        );
    }
    let external_retained_bytes = work
        .context
        .retained_memory_bytes()
        .map_err(provider_failure)?
        .checked_add(
            capture
                .retained_memory_bytes()
                .map_err(|_| ServiceFailure::CorruptState)?,
        )
        .and_then(|bytes| bytes.checked_add(checkpoint::MAX_OWNER_FIELD as u64))
        .ok_or(ServiceFailure::CorruptState)?;
    let verification_retained = work
        .verification
        .as_ref()
        .map(|state| state.retained_memory_bytes())
        .transpose()
        .map_err(capture_failure)?
        .unwrap_or(0);
    let registry_retained = external_retained_bytes
        .checked_add(manifest.retained_memory_bytes().map_err(capture_failure)?)
        .and_then(|bytes| bytes.checked_add(verification_retained))
        .ok_or(ServiceFailure::CorruptState)?;
    #[cfg(feature = "test-support")]
    let registry_started = std::time::Instant::now();
    let ready = work
        .owner
        .registry_ready(services, execution, registry_retained)?;
    #[cfg(feature = "test-support")]
    super::verification::report_snapshot_stage(
        "publication_registry_ready",
        registry_started.elapsed(),
        work.verification.as_ref(),
    );
    if !ready {
        return Ok(false);
    }
    if operation.phase() == DurableOperationPhase::BackupPublication {
        let publisher = work
            .owner
            .publisher(external_retained_bytes)
            .map_err(provider_failure)?;
        match work
            .owner
            .runtime
            .block_on(publisher.reconcile_publication(manifest))
        {
            Ok(Some(receipt)) => {
                return record_publication(
                    services,
                    actor,
                    id,
                    &work.owner.identity,
                    manifest,
                    work.transfer.ok_or(ServiceFailure::Internal)?,
                    receipt,
                );
            },
            Ok(None) => {
                if readiness(services)? != crate::RecoveryReadiness::Verified {
                    return Err(ServiceFailure::StorageUnavailable);
                }
            },
            Err(_) => return Err(ServiceFailure::StorageUnavailable),
        }
    }
    if !work.transfer.ok_or(ServiceFailure::Internal)?.complete() {
        if !matches!(
            operation.phase(),
            DurableOperationPhase::BackupTransfer
                | DurableOperationPhase::BackupVerification
                | DurableOperationPhase::BackupPublication
        ) {
            advance(services, actor, id, BackupOperationStage::Transferring)?;
        }
        let publisher = work
            .owner
            .publisher(external_retained_bytes)
            .map_err(provider_failure)?;
        if !work.reservation_established {
            work.owner
                .runtime
                .block_on(publisher.reserve(manifest, work.context.keys()))
                .map_err(provider_failure)?;
            work.reservation_established = true;
            #[cfg(test)]
            test_stops::hit(
                services.instance.instance.to_bytes(),
                binding.operation_id(),
                test_stops::StopPoint::ReservationRegistered,
                cancellation,
            )?;
            let registry = work.owner.registry_checkpoint()?;
            checkpoint::persist(
                services,
                execution,
                binding,
                registry.as_deref(),
                Some(&checkpoint::encode(
                    work.transfer.ok_or(ServiceFailure::Internal)?,
                    work.next_key,
                    &[],
                )?),
            )?;
            return Ok(false);
        }
        if (work.next_key as usize) < work.context.keys().len() {
            let started = std::time::Instant::now();
            for _ in 0..MAX_BACKUP_STEP_ADVANCES {
                if cancellation.is_some_and(crate::TaskCancellation::is_cancelled) {
                    return Err(ServiceFailure::Cancelled);
                }
                #[cfg(test)]
                test_stops::hit(
                    services.instance.instance.to_bytes(),
                    binding.operation_id(),
                    test_stops::StopPoint::BeforeKeyUpload,
                    cancellation,
                )?;
                work.next_key = work
                    .owner
                    .runtime
                    .block_on(publisher.prepare_key_step(
                        manifest,
                        work.context.keys(),
                        work.next_key,
                    ))
                    .map_err(provider_failure)?;
                #[cfg(test)]
                if test_stops::armed(
                    services.instance.instance.to_bytes(),
                    binding.operation_id(),
                    test_stops::StopPoint::KeyPreparationPersisted,
                )? {
                    break;
                }
                if work.next_key as usize == work.context.keys().len()
                    || work.owner.identity.provider_kind() != "localFilesystem"
                    || started.elapsed() >= std::time::Duration::from_millis(10)
                {
                    break;
                }
            }
            let registry = work.owner.registry_checkpoint()?;
            checkpoint::persist(
                services,
                execution,
                binding,
                registry.as_deref(),
                Some(&checkpoint::encode(
                    work.transfer.ok_or(ServiceFailure::Internal)?,
                    work.next_key,
                    &[],
                )?),
            )?;
            #[cfg(test)]
            test_stops::hit(
                services.instance.instance.to_bytes(),
                binding.operation_id(),
                test_stops::StopPoint::KeyPreparationPersisted,
                cancellation,
            )?;
            return Ok(false);
        }
        let mut transfer = work.transfer.ok_or(ServiceFailure::Internal)?;
        #[cfg(test)]
        let starting_next = transfer.next_object();
        #[cfg(test)]
        let fault_checkpoint = test_stops::armed(
            services.instance.instance.to_bytes(),
            binding.operation_id(),
            test_stops::StopPoint::TransferCheckpointPublication,
        )?;
        let started = std::time::Instant::now();
        let mut remaining = 4 * 1024 * 1024u64;
        for _ in 0..MAX_BACKUP_STEP_ADVANCES {
            if cancellation.is_some_and(crate::TaskCancellation::is_cancelled) {
                return Err(ServiceFailure::Cancelled);
            }
            let charge = manifest
                .objects()
                .get(transfer.next_object() as usize)
                .ok_or(ServiceFailure::CorruptState)?
                .length()
                .min(4 * 1024 * 1024);
            if charge > remaining {
                break;
            }
            transfer = work
                .owner
                .runtime
                .block_on(publisher.transfer_step_bounded(
                    manifest,
                    capture,
                    transfer,
                    &mut work.object_verification,
                ))
                .map_err(|failure| {
                    #[cfg(feature = "test-support")]
                    if failure == RepositoryFailure::CorruptState {
                        eprintln!("backup_runtime_corrupt phase=transfer_call");
                    }
                    provider_failure(failure)
                })?;
            remaining -= charge;
            #[cfg(test)]
            if fault_checkpoint
                && transfer.next_object() > starting_next
                && work.object_verification.is_some()
            {
                break;
            }
            if transfer.complete()
                || work.owner.identity.provider_kind() != "localFilesystem"
                || started.elapsed() >= std::time::Duration::from_millis(10)
            {
                break;
            }
        }
        // The verifier advances in place. Retain its matching volatile cursor
        // even when the following durable checkpoint must be retried.
        work.transfer = Some(transfer);
        let registry = work.owner.registry_checkpoint()?;
        let persist = || {
            checkpoint::persist(
                services,
                execution,
                binding,
                registry.as_deref(),
                Some(&checkpoint::encode(transfer, work.next_key, &[])?),
            )
        };
        #[cfg(test)]
        let persisted = if fault_checkpoint
            && transfer.next_object() > starting_next
            && work.object_verification.is_some()
        {
            test_stops::hit(
                services.instance.instance.to_bytes(),
                binding.operation_id(),
                test_stops::StopPoint::TransferCheckpointPublication,
                None,
            )?;
            positron_kernel::with_catalog_publication_fault_after(
                positron_kernel::CatalogPublicationFault::RenameMarker,
                0,
                persist,
            )
        } else {
            persist()
        };
        #[cfg(not(test))]
        let persisted = persist();
        persisted?;
        return Ok(false);
    }
    if !matches!(
        operation.phase(),
        DurableOperationPhase::BackupVerification | DurableOperationPhase::BackupPublication
    ) {
        advance(services, actor, id, BackupOperationStage::Verifying)?;
    }
    let publisher = work
        .owner
        .publisher(external_retained_bytes)
        .map_err(provider_failure)?;
    if work.verification.is_none() {
        #[cfg(feature = "test-support")]
        let initialization_started = std::time::Instant::now();
        work.verification = Some(
            work.owner
                .runtime
                .block_on(async {
                    if work.saved_verification.is_empty() {
                        publisher.prepare_publication(manifest).await
                    } else {
                        publisher
                            .resume_publication(manifest, &work.saved_verification)
                            .await
                    }
                })
                .map_err(provider_failure)?,
        );
        work.saved_verification.clear();
        #[cfg(feature = "test-support")]
        super::verification::report_snapshot_stage(
            "publication_initialize_resume",
            initialization_started.elapsed(),
            work.verification.as_ref(),
        );
    }
    let verification = work.verification.as_mut().ok_or(ServiceFailure::Internal)?;
    let started = std::time::Instant::now();
    let mut remaining = 4 * 1024 * 1024u64;
    let mut complete = verification.complete();
    for _ in 0..MAX_BACKUP_STEP_ADVANCES {
        if complete {
            break;
        }
        if cancellation.is_some_and(crate::TaskCancellation::is_cancelled) {
            return Err(ServiceFailure::Cancelled);
        }
        let charge = verification
            .next_step_bytes(manifest)
            .map_err(provider_failure)?;
        if charge > remaining {
            break;
        }
        complete = match work
            .owner
            .runtime
            .block_on(publisher.verify_publication_step(manifest, verification))
        {
            Ok(complete) => complete,
            Err(RepositoryFailure::PreconditionFailed) => {
                work.verification = None;
                return Ok(false);
            },
            Err(failure) => return Err(provider_failure(failure)),
        };
        remaining -= charge;
        if work.owner.identity.provider_kind() != "localFilesystem"
            || started.elapsed() >= std::time::Duration::from_millis(10)
        {
            break;
        }
    }
    #[cfg(feature = "test-support")]
    let batch_elapsed = started.elapsed();
    #[cfg(feature = "test-support")]
    let checkpoint_started = std::time::Instant::now();
    let progress = checkpoint::encode(
        work.transfer.ok_or(ServiceFailure::Internal)?,
        work.next_key,
        &publisher
            .publication_checkpoint(verification)
            .map_err(provider_failure)?,
    )?;
    let registry = work.owner.registry_checkpoint()?;
    checkpoint::persist(
        services,
        execution,
        binding,
        registry.as_deref(),
        Some(&progress),
    )?;
    #[cfg(feature = "test-support")]
    {
        let checkpoint_elapsed = checkpoint_started.elapsed();
        super::verification::report_snapshot_stage(
            "publication_verify_batch",
            batch_elapsed,
            Some(verification),
        );
        super::verification::report_snapshot_stage(
            "publication_checkpoint_publish",
            checkpoint_elapsed,
            Some(verification),
        );
    }
    if !complete {
        return Ok(false);
    }
    if readiness(services)? != crate::RecoveryReadiness::Verified {
        return fail(services, actor, id, ServiceFailure::KeyUnavailable);
    }
    advance(services, actor, id, BackupOperationStage::Publishing)?;
    let receipt = match work
        .owner
        .runtime
        .block_on(publisher.commit_publication(manifest, verification))
    {
        Ok(receipt) => receipt,
        Err(RepositoryFailure::PreconditionFailed) => {
            work.verification = None;
            return Ok(false);
        },
        Err(failure) => return Err(provider_failure(failure)),
    };
    #[cfg(test)]
    test_stops::hit(
        services.instance.instance.to_bytes(),
        binding.operation_id(),
        test_stops::StopPoint::RegistryPublished,
        cancellation,
    )?;
    record_publication(
        services,
        actor,
        id,
        &work.owner.identity,
        manifest,
        work.transfer.ok_or(ServiceFailure::Internal)?,
        receipt,
    )
}
fn record_publication(
    services: &ServiceHandle,
    actor: positron_governance::AuthorizedContext,
    id: OperationId,
    identity: &RepositoryIdentity,
    manifest: &BackupManifest,
    transfer: BackupTransfer,
    receipt: positron_backup::BackupPublication,
) -> Result<bool, ServiceFailure> {
    let evidence = BackupOperationReceipt::new(
        receipt.manifest().checksum(),
        receipt.registry_generation(),
        manifest.catalog_generation(),
        manifest.catalog_identity(),
        transfer.uploaded_bytes(),
        transfer.reused_bytes(),
        receipt.retain_until(),
    )
    .map_err(|_| ServiceFailure::CorruptState)?;
    let _gate = services.catalog_operation()?;
    let catalog = services
        .open_maintenance_catalog()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    let basis = catalog
        .pin()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    let (previous, registration) = positron_backup::BackupRepositoryRegistration::find(
        &basis,
        services.instance.instance.to_bytes(),
        identity.repository_id(),
    )
    .map_err(provider_failure)?
    .ok_or(ServiceFailure::CorruptState)?;
    if registration.identity() != identity {
        return Err(ServiceFailure::CorruptState);
    }
    let successor = registration
        .with_registry_generation(receipt.registry_generation())
        .and_then(|registration| registration.catalog_object())
        .map_err(provider_failure)?;
    DurableOperationAdministration::succeed_backup_with_registration(
        &catalog,
        actor,
        id,
        evidence,
        previous,
        successor,
        services
            .maintenance_status_now()
            .map_err(|_| ServiceFailure::StorageUnavailable)?,
    )
    .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    Ok(false)
}
fn advance(
    services: &ServiceHandle,
    actor: positron_governance::AuthorizedContext,
    id: OperationId,
    stage: BackupOperationStage,
) -> Result<(), ServiceFailure> {
    let _gate = services.catalog_operation()?;
    let catalog = services
        .open_maintenance_catalog()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    let operation = DurableOperationAdministration::inspect(&catalog, id)
        .map_err(|_| ServiceFailure::CorruptState)?
        .ok_or(ServiceFailure::CorruptState)?;
    let later = match operation.phase() {
        DurableOperationPhase::BackupPublication => true,
        DurableOperationPhase::BackupVerification => stage != BackupOperationStage::Publishing,
        DurableOperationPhase::BackupTransfer => stage == BackupOperationStage::Capturing,
        _ => false,
    };
    if !later {
        DurableOperationAdministration::advance_backup(
            &catalog,
            actor,
            id,
            stage,
            services
                .maintenance_status_now()
                .map_err(|_| ServiceFailure::StorageUnavailable)?,
        )
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    }
    Ok(())
}
fn fail(
    services: &ServiceHandle,
    actor: positron_governance::AuthorizedContext,
    id: OperationId,
    failure: ServiceFailure,
) -> Result<bool, ServiceFailure> {
    let _gate = services.catalog_operation()?;
    let catalog = services
        .open_maintenance_catalog()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    DurableOperationAdministration::fail_backup(
        &catalog,
        actor,
        id,
        services
            .maintenance_status_now()
            .map_err(|_| ServiceFailure::StorageUnavailable)?,
    )
    .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    Err(failure)
}
pub(super) fn provider_failure(failure: RepositoryFailure) -> ServiceFailure {
    static REMAINING: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(32);
    provider_failure_with(failure, &REMAINING, crate::write_operational_diagnostic)
}

fn provider_failure_with(
    failure: RepositoryFailure,
    remaining: &std::sync::atomic::AtomicU8,
    report: impl FnOnce(crate::OperationalDiagnostic) -> std::io::Result<()>,
) -> ServiceFailure {
    match failure {
        RepositoryFailure::ControlMemoryRequired { memory_bytes } => {
            ServiceFailure::BackupControlMemoryRequired { memory_bytes }
        },
        RepositoryFailure::Busy | RepositoryFailure::Throttled { .. } => {
            ServiceFailure::CapacityUnavailable
        },
        RepositoryFailure::Interrupted
        | RepositoryFailure::PreconditionFailed
        | RepositoryFailure::OutcomeUnknown
        | RepositoryFailure::StorageUnavailable => ServiceFailure::StorageUnavailable,
        RepositoryFailure::SourceIntegrityCorruption => ServiceFailure::CorruptState,
        RepositoryFailure::InvalidInput => ServiceFailure::Internal,
        _ => {
            use std::sync::atomic::Ordering;
            if remaining
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                // The closed Repository failure carries no paths, credentials
                // or provider error strings. Reporting cannot alter rejection.
                match report(crate::OperationalDiagnostic::BackupRepositoryRejected(
                    failure,
                )) {
                    Ok(()) | Err(_) => {},
                }
            }
            ServiceFailure::BackupRepositoryRejected
        },
    }
}
fn capture_failure(failure: RepositoryFailure) -> ServiceFailure {
    match failure {
        RepositoryFailure::ControlMemoryRequired { memory_bytes } => {
            ServiceFailure::BackupControlMemoryRequired { memory_bytes }
        },
        RepositoryFailure::Busy | RepositoryFailure::LimitExceeded => {
            ServiceFailure::CapacityUnavailable
        },
        RepositoryFailure::StorageUnavailable | RepositoryFailure::Interrupted => {
            ServiceFailure::StorageUnavailable
        },
        _ => ServiceFailure::CorruptState,
    }
}

pub(in crate::services) fn reject_repository(
    services: &ServiceHandle,
    execution: &MaintenanceExecution<'_>,
) -> Result<bool, ServiceFailure> {
    let binding = RepositoryOperationBinding::from_execution(execution)
        .map_err(super::super::maintenance::map_failure)?;
    let id = OperationId::from_bytes(binding.operation_id())
        .map_err(|_| ServiceFailure::CorruptState)?;
    let _gate = services.catalog_operation()?;
    let catalog = services
        .open_maintenance_catalog()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    let operation = DurableOperationAdministration::inspect(&catalog, id)
        .map_err(|_| ServiceFailure::CatalogUnavailable)?
        .ok_or(ServiceFailure::CorruptState)?;
    if operation.kind() == DurableOperationKind::BackupVerification
        && !operation.status().is_terminal()
    {
        let now = services
            .maintenance_status_now()
            .map_err(|_| ServiceFailure::StorageUnavailable)?;
        let actor = DurableOperationAdministration::resume_backup_actor(&catalog, id, now)
            .map_err(|_| ServiceFailure::Unauthorized)?;
        DurableOperationAdministration::fail_backup(&catalog, actor, id, now)
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        return Ok(false);
    }
    // Failed/cancellation cleanup and any possible irreversible mutation retain
    // their existing proof owner until the Repository becomes verifiable again.
    if operation.status().is_terminal()
        || matches!(
            operation.phase(),
            DurableOperationPhase::BackupPublication
                | DurableOperationPhase::BackupRetentionPublication
                | DurableOperationPhase::BackupRetentionCleanup
                | DurableOperationPhase::BackupCancellation
        )
    {
        return Err(ServiceFailure::StorageUnavailable);
    }
    let now = services
        .maintenance_status_now()
        .map_err(|_| ServiceFailure::StorageUnavailable)?;
    let actor = DurableOperationAdministration::resume_backup_actor(&catalog, id, now)
        .map_err(|_| ServiceFailure::Unauthorized)?;
    DurableOperationAdministration::fail_backup(&catalog, actor, id, now)
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    Ok(false)
}

impl BackupWork {
    pub(in crate::services) fn persist_registry(
        &self,
        services: &ServiceHandle,
        execution: &MaintenanceExecution<'_>,
    ) -> Result<(), ServiceFailure> {
        let owner = match self {
            Self::Snapshot(work) => &work.owner,
            Self::Verification(work) => &work.owner,
            Self::Cancellation(work) => &work.owner,
            Self::Retention(work) => &work.owner,
        };
        if let Some(registry) = owner.registry_checkpoint()? {
            let binding = RepositoryOperationBinding::from_execution(execution)
                .map_err(super::super::maintenance::map_failure)?;
            checkpoint::persist(services, execution, binding, Some(&registry), None)?;
        }
        Ok(())
    }
}

fn prepare_snapshot(
    services: &ServiceHandle,
    execution: &mut MaintenanceExecution<'_>,
    work: &mut Option<BackupWork>,
    operation: DurableOperation,
    binding: RepositoryOperationBinding,
    catalog: &positron_kernel::Catalog<'_>,
) -> Result<
    std::ops::ControlFlow<bool, (DurableOperation, positron_governance::AuthorizedContext)>,
    ServiceFailure,
> {
    let id = operation.operation_id();
    require_operation(operation, services.instance.instance.to_bytes())?;
    if operation
        .backup_parameters()
        .ok_or(ServiceFailure::CorruptState)?
        .intent_digest()
        != binding.intent_digest()
    {
        return Err(ServiceFailure::CorruptState);
    }
    let (sequence, owner_checkpoint) = checkpoint::current(services, execution, binding)?;
    let (registry_checkpoint, terminal_checkpoint) = checkpoint::unpack(&owner_checkpoint)?;
    let cleanup_ack_pending = operation.status() == DurableOperationStatus::Cancelled
        && terminal_checkpoint.starts_with(b"POSBKC02");
    if operation.status().is_terminal()
        && operation.status() != DurableOperationStatus::Failed
        && !cleanup_ack_pending
    {
        let coordinator = services.instance.maintenance_coordinator();
        if terminal_checkpoint != b"POSBKC01" {
            let sequence = sequence
                .checked_add(1)
                .ok_or(ServiceFailure::CorruptState)?;
            execution
                .checkpoint_and_persist(
                    coordinator,
                    catalog,
                    binding
                        .backup_checkpoint(
                            sequence,
                            &checkpoint::pack(registry_checkpoint, b"POSBKC01")?,
                        )
                        .map_err(super::super::maintenance::map_failure)?,
                )
                .map_err(super::super::maintenance::map_failure)?;
        }
        *work = None;
        if !catalog
            .release_backup_capture(binding.operation_id(), binding.intent_digest())
            .map_err(|_| ServiceFailure::StorageUnavailable)?
        {
            return Ok(std::ops::ControlFlow::Break(false));
        }
        if operation.status() == DurableOperationStatus::Cancelled {
            coordinator
                .cancel_and_persist(catalog, execution.task().identity())
                .map_err(super::super::maintenance::map_failure)?;
        }
        execution
            .complete_and_persist(
                services.instance.maintenance_coordinator(),
                catalog,
                operation.status() == DurableOperationStatus::Succeeded,
            )
            .map_err(super::super::maintenance::map_failure)?;
        return Ok(std::ops::ControlFlow::Break(true));
    }
    let now = services
        .maintenance_status_now()
        .map_err(|_| ServiceFailure::StorageUnavailable)?;
    let actor = DurableOperationAdministration::resume_backup_actor(catalog, id, now)
        .map_err(|_| ServiceFailure::Unauthorized)?;
    let operation = if operation.status() == DurableOperationStatus::Pending {
        DurableOperationAdministration::begin(catalog, actor, id, now)
            .map_err(|_| ServiceFailure::CatalogUnavailable)?
    } else {
        operation
    };
    let operation = if operation.phase() == DurableOperationPhase::Preflight {
        DurableOperationAdministration::advance_backup(
            catalog,
            actor,
            id,
            BackupOperationStage::Capturing,
            now,
        )
        .map_err(|_| ServiceFailure::CatalogUnavailable)?
    } else {
        operation
    };
    Ok(std::ops::ControlFlow::Continue((operation, actor)))
}
