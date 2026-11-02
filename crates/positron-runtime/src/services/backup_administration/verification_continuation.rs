//! Native verification state is sealed by Catalog and referenced by Maintenance.
use super::*;
use positron_kernel::{
    BackupVerificationBinding, BackupVerificationNativeState, BackupVerificationProgress,
    ResourceAmounts, ResourceDimension,
};
use sha2::{Digest, Sha256};

/// Builds a valid pre-prospective-admission reference through the same public
/// Kernel publication contract, without injecting private verification work.
#[cfg(test)]
pub(in crate::services) fn publish_old_empty_native_reference(
    services: &ServiceHandle,
    operation: DurableOperation,
) -> Result<ResourceAmounts, Box<dyn std::error::Error>> {
    let coordinator = services.instance.maintenance_coordinator();
    let task = positron_kernel::MaintenanceTaskId::new(operation.operation_id().to_bytes())
        .map_err(|failure| format!("old task: {failure:?}"))?;
    let mut execution = {
        let _gate = services.catalog_operation()?;
        let catalog = services
            .open_maintenance_catalog()
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        coordinator
            .start_backup_operation_with_reservation_and_persist(
                &catalog,
                &services.instance._authority,
                services
                    .maintenance_status_now()
                    .map_err(|_| ServiceFailure::StorageUnavailable)?,
                false,
                task,
            )
            .map_err(|failure| format!("old dispatch: {failure:?}"))?
            .ok_or("old dispatch")?
    };
    let binding = RepositoryOperationBinding::from_execution(&execution)
        .map_err(|failure| format!("old binding: {failure:?}"))?;
    let owner = BackupOwner::open(services, &mut execution, operation)?;
    let (_, checkpoint) = execution::checkpoint::current(services, &execution, binding)?;
    let (_, encoded) = execution::checkpoint::unpack(&checkpoint)?;
    let parameters = operation
        .backup_verification_parameters()
        .ok_or("verification parameters")?;
    let publisher = owner.publisher(0)?;
    let mut remote = owner.runtime.block_on(async {
        if encoded.is_empty() {
            publisher
                .begin_snapshot_verification(
                    parameters.snapshot_id(),
                    binding.operation_id(),
                    binding.intent_digest(),
                )
                .await
        } else {
            publisher
                .resume_snapshot_verification(
                    encoded,
                    binding.operation_id(),
                    binding.intent_digest(),
                )
                .await
        }
    })?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !remote.complete() {
        if std::time::Instant::now() >= deadline {
            return Err("old remote fixture deadline".into());
        }
        owner
            .runtime
            .block_on(publisher.snapshot_verification_step(&mut remote))?;
    }
    let remote_progress = publisher.snapshot_verification_checkpoint(&remote)?;
    let index = owner.runtime.block_on(publisher.read_snapshot_file(
        remote.manifest(),
        remote.manifest().capture_index(),
        8 * 1024 * 1024,
    ))?;
    drop(publisher);
    execution::checkpoint::persist(services, &execution, binding, None, Some(&remote_progress))?;
    let (capture_operation, capture_request) = remote
        .manifest()
        .capture_binding()
        .ok_or("capture binding")?;
    let native_binding = BackupVerificationBinding {
        operation: binding.operation_id(),
        intent: binding.intent_digest(),
        capture_operation,
        capture_request,
        manifest: remote.manifest_checksum(),
        index: Sha256::digest(&index).into(),
        registry: Sha256::digest(owner.registry_checkpoint()?.ok_or("registry checkpoint")?).into(),
    };
    let reference = {
        let _gate = services.catalog_operation()?;
        let catalog = services
            .open_maintenance_catalog()
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        let metadata = catalog.begin_backup_capture_verification(
            capture_operation,
            capture_request,
            &index,
        )?;
        let mut semantic = b"POSBVS01".to_vec();
        semantic.extend_from_slice(&[0; 16]);
        let progress = BackupVerificationProgress {
            native: BackupVerificationNativeState::Metadata(Box::new(metadata)),
            semantic,
        };
        let reference = catalog.persist_backup_verification_continuation(
            coordinator,
            &mut execution,
            native_binding,
            None,
            &index,
            &progress,
        )?;
        catalog.resume_backup_verification_continuation(
            native_binding,
            reference,
            &index,
            progress.continuation_resources(&index)?,
        )?;
        reference
    };
    execution::checkpoint::set_native_reference(services, &execution, binding, Some(reference))?;
    drop(owner);
    let resources = execution.task().reservations();
    let _gate = services.catalog_operation()?;
    let catalog = services
        .open_maintenance_catalog()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    execution
        .requeue_backup_with_resources_and_persist(
            coordinator,
            &catalog,
            binding,
            resources,
            services
                .maintenance_status_now()
                .map_err(|_| ServiceFailure::StorageUnavailable)?,
        )
        .map_err(|failure| format!("old requeue: {failure:?}"))?;
    Ok(resources)
}

fn binding(
    work: &VerificationWork,
    owner: RepositoryOperationBinding,
) -> Result<BackupVerificationBinding, ServiceFailure> {
    let remote = work.remote.as_ref().ok_or(ServiceFailure::CorruptState)?;
    let (capture_operation, capture_request) = remote
        .manifest()
        .capture_binding()
        .ok_or(ServiceFailure::BackupRepositoryRejected)?;
    let registry = work
        .owner
        .registry_checkpoint()?
        .ok_or(ServiceFailure::CorruptState)?;
    Ok(BackupVerificationBinding {
        operation: owner.operation_id(),
        intent: owner.intent_digest(),
        capture_operation,
        capture_request,
        manifest: remote.manifest_checksum(),
        index: Sha256::digest(&work.native_index).into(),
        registry: Sha256::digest(registry).into(),
    })
}
fn encode(work: &VerificationWork) -> Result<Vec<u8>, ServiceFailure> {
    let mut bytes = b"POSBVS01".to_vec();
    for value in [
        work.next_schema,
        work.recovered_keys,
        work.schema_tenants.len(),
        work.policy_tenants.len(),
    ] {
        bytes.extend_from_slice(
            &u32::try_from(value)
                .map_err(|_| ServiceFailure::CorruptState)?
                .to_be_bytes(),
        );
    }
    for tenants in [&work.schema_tenants, &work.policy_tenants] {
        if tenants.len() > 1024 {
            return Err(ServiceFailure::CorruptState);
        }
        for tenant in tenants {
            bytes.extend_from_slice(&tenant.to_bytes());
        }
    }
    Ok(bytes)
}
fn decode(work: &mut VerificationWork, bytes: &[u8]) -> Result<(), ServiceFailure> {
    if bytes.get(..8) != Some(b"POSBVS01") {
        return Err(ServiceFailure::BackupRepositoryRejected);
    }
    let mut cursor = 8usize;
    let mut read = || -> Result<usize, ServiceFailure> {
        let value = bytes
            .get(cursor..cursor + 4)
            .ok_or(ServiceFailure::BackupRepositoryRejected)?;
        cursor += 4;
        Ok(u32::from_be_bytes(
            value
                .try_into()
                .map_err(|_| ServiceFailure::BackupRepositoryRejected)?,
        ) as usize)
    };
    let next_schema = read()?;
    let recovered_keys = read()?;
    let schemas = read()?;
    let policies = read()?;
    if schemas > 1024 || policies > 1024 {
        return Err(ServiceFailure::BackupRepositoryRejected);
    }
    let mut sets = [Vec::new(), Vec::new()];
    for (set, count) in sets.iter_mut().zip([schemas, policies]) {
        for _ in 0..count {
            let value = bytes
                .get(cursor..cursor + 16)
                .ok_or(ServiceFailure::BackupRepositoryRejected)?;
            cursor += 16;
            let tenant = positron_domain::identity::TenantId::from_bytes(
                value
                    .try_into()
                    .map_err(|_| ServiceFailure::BackupRepositoryRejected)?,
            )
            .map_err(|_| ServiceFailure::BackupRepositoryRejected)?;
            if set.contains(&tenant) {
                return Err(ServiceFailure::BackupRepositoryRejected);
            }
            set.push(tenant);
        }
    }
    let objects = work
        .catalog
        .as_ref()
        .map_or(0, |snapshot| snapshot.object_identities().count());
    let keys = work
        .owner
        .publisher(0)
        .map_err(provider_failure)?
        .verification_key_count(work.remote.as_ref().ok_or(ServiceFailure::CorruptState)?);
    if cursor != bytes.len()
        || next_schema > objects
        || recovered_keys > keys
        || (work.metadata.is_some()
            && (next_schema != 0 || recovered_keys != 0 || schemas != 0 || policies != 0))
    {
        return Err(ServiceFailure::BackupRepositoryRejected);
    }
    work.next_schema = next_schema;
    work.recovered_keys = recovered_keys;
    let [schema_tenants, policy_tenants] = sets;
    work.schema_tenants = schema_tenants;
    work.policy_tenants = policy_tenants;
    Ok(())
}

pub(super) fn restore(
    services: &ServiceHandle,
    execution: &MaintenanceExecution<'_>,
    work: &mut VerificationWork,
    owner: RepositoryOperationBinding,
) -> Result<(), ServiceFailure> {
    let reference = work.native_reference.ok_or(ServiceFailure::CorruptState)?;
    let binding = binding(work, owner)?;
    let _gate = services.catalog_operation()?;
    let catalog = services
        .open_maintenance_catalog()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    let progress = catalog
        .resume_backup_verification_continuation(
            binding,
            reference,
            &work.native_index,
            execution.task().reservations(),
        )
        .map_err(|_| ServiceFailure::BackupRepositoryRejected)?;
    match progress.native {
        BackupVerificationNativeState::Metadata(metadata) => {
            work.next_file = metadata
                .next_pending_file()
                .map_err(|_| ServiceFailure::BackupRepositoryRejected)?;
            work.metadata_required = metadata
                .prospective_memory_bytes()
                .map_err(|_| ServiceFailure::BackupRepositoryRejected)?;
            work.metadata = Some(*metadata);
        },
        BackupVerificationNativeState::Catalog(snapshot) => {
            work.governance_required = semantic_memory_requirement(&snapshot)?;
            work.catalog = Some(snapshot);
        },
    }
    decode(work, &progress.semantic)?;
    // Remote continuation stores a signed inventory digest/cursor, not the
    // inventory itself. Reauthenticate it before accepting native progress.
    let inventory = catalog
        .begin_backup_capture_verification(
            binding.capture_operation,
            binding.capture_request,
            &work.native_index,
        )
        .map_err(|_| ServiceFailure::BackupRepositoryRejected)?;
    let external = work
        .remote
        .as_ref()
        .map(BackupSnapshotVerification::retained_memory_bytes)
        .transpose()
        .map_err(provider_failure)?
        .unwrap_or(0)
        .checked_add(work.metadata_required)
        .and_then(|bytes| bytes.checked_add(work.governance_required))
        .ok_or(ServiceFailure::CapacityUnavailable)?;
    work.owner
        .publisher(external)
        .map_err(provider_failure)?
        .validate_snapshot_inventory(
            work.remote.as_mut().ok_or(ServiceFailure::CorruptState)?,
            inventory.files(),
        )
        .map_err(provider_failure)?;
    Ok(())
}

pub(super) fn checkpoint(
    services: &ServiceHandle,
    execution: &mut MaintenanceExecution<'_>,
    work: &mut VerificationWork,
    force: bool,
) -> Result<Option<ResourceAmounts>, ServiceFailure> {
    let needs_admission =
        work.continuation_bound.is_none() && (work.metadata.is_some() || work.catalog.is_some());
    if !needs_admission
        && (work.native_steps == 0
            || (!force && work.native_steps < execution::MAX_BACKUP_STEP_ADVANCES))
    {
        return Ok(None);
    }
    let owner = RepositoryOperationBinding::from_execution(execution)
        .map_err(super::super::super::maintenance::map_failure)?;
    let binding = binding(work, owner)?;
    let semantic = encode(work)?;
    let native = match (work.metadata.take(), work.catalog.take()) {
        (Some(metadata), None) => BackupVerificationNativeState::Metadata(Box::new(metadata)),
        (None, Some(snapshot)) => BackupVerificationNativeState::Catalog(snapshot),
        _ => return Err(ServiceFailure::CorruptState),
    };
    let progress = BackupVerificationProgress { native, semantic };
    let result = (|| {
        let mut required = match work.continuation_bound {
            Some(required) => required,
            None => {
                let required = progress
                    .prospective_continuation_resources(&work.native_index)
                    .map_err(|_| ServiceFailure::CapacityUnavailable)?;
                work.continuation_bound = Some(required);
                required
            },
        };
        let remote = work
            .remote
            .as_ref()
            .map(BackupSnapshotVerification::retained_memory_bytes)
            .transpose()
            .map_err(provider_failure)?
            .unwrap_or(0);
        let memory = required
            .get(ResourceDimension::MemoryBytes)
            .checked_add(remote)
            .ok_or(ServiceFailure::CapacityUnavailable)?;
        required = ResourceAmounts::new(ResourceDimension::ALL.map(|dimension| {
            if dimension == ResourceDimension::MemoryBytes {
                memory
            } else {
                required.get(dimension)
            }
        }));
        if ResourceDimension::ALL.iter().any(|dimension| {
            required.get(*dimension) > execution.task().reservations().get(*dimension)
        }) {
            return Ok(Some(required));
        }
        if work.native_steps == 0
            || (!force && work.native_steps < execution::MAX_BACKUP_STEP_ADVANCES)
        {
            return Ok(None);
        }
        let reference = {
            let _gate = services.catalog_operation()?;
            let catalog = services
                .open_maintenance_catalog()
                .map_err(|_| ServiceFailure::CatalogUnavailable)?;
            catalog
                .persist_backup_verification_continuation(
                    services.instance.maintenance_coordinator(),
                    execution,
                    binding,
                    work.native_reference,
                    &work.native_index,
                    &progress,
                )
                .map_err(|_| ServiceFailure::CatalogUnavailable)?
        };
        execution::checkpoint::set_native_reference(services, execution, owner, Some(reference))?;
        work.native_reference = Some(reference);
        work.native_steps = 0;
        Ok(None)
    })();
    match progress.native {
        BackupVerificationNativeState::Metadata(metadata) => work.metadata = Some(*metadata),
        BackupVerificationNativeState::Catalog(snapshot) => work.catalog = Some(snapshot),
    }
    result
}
