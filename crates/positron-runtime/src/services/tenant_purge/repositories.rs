//! Registered repository identity remains the sole inventory and trust anchor.
use super::*;
use positron_backup::{
    BackupPublisher, BackupPurgeTombstone, BackupRepositoryRegistration, RepositoryFailure,
};
use positron_kernel::{
    NativeAwsResources, RecoveryWorkClaim, RecoveryWorkKind, ResourceAmounts, ResourceDimension,
};
pub(super) struct RepositoryPurgeProof {
    generation: positron_kernel::CatalogGenerationId,
}
impl RepositoryPurgeProof {
    pub(super) fn still_current(
        &self,
        catalog: &positron_kernel::Catalog<'_>,
    ) -> Result<bool, ServiceFailure> {
        Ok(catalog
            .pin()
            .map_err(|_| ServiceFailure::CatalogUnavailable)?
            .identity()
            == self.generation)
    }
}
pub(super) fn purge(
    services: &ServiceHandle,
    operation: DurableOperation,
    tenant: TenantId,
    slug: &str,
    execution: &positron_kernel::MaintenanceExecution<'_>,
) -> Result<Option<RepositoryPurgeProof>, ServiceFailure> {
    // Freeze registration, backup publication, and root migration while the complete
    // registered inventory is proved. Provider calls are bounded by their adapters.
    let _gate = services.catalog_operation()?;
    let catalog = services
        .open_maintenance_catalog()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    let snapshot = catalog
        .pin()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    if catalog
        .has_backup_capture_references()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?
    {
        return Err(ServiceFailure::CatalogBusy);
    }
    let (_, governance) = snapshot
        .governance_object()
        .map_err(|_| ServiceFailure::CorruptState)?;
    let signer = services
        .instance
        .key
        .backup_control_signer(
            services.instance.instance,
            governance.protected_integrity_key(),
        )
        .map_err(|_| ServiceFailure::KeyUnavailable)?;
    let exclusion = TenantAdministration::restore_purge_exclusions(&snapshot)
        .map_err(|_| ServiceFailure::CorruptState)?
        .into_iter()
        .find(|exclusion| exclusion.tenant_id() == tenant)
        .ok_or(ServiceFailure::CorruptState)?;
    let tombstone = BackupPurgeTombstone::new(
        tenant.to_bytes(),
        slug,
        exclusion
            .operation_id()
            .ok_or(ServiceFailure::CorruptState)?,
        exclusion
            .accepted_at_unix_seconds()
            .ok_or(ServiceFailure::CorruptState)?,
    )
    .map_err(failure)?;
    let binding = RepositoryOperationBinding::from_execution(execution)
        .map_err(|_| ServiceFailure::CorruptState)?;
    let mut progress = super::checkpoint::current(services, execution, binding)?;
    let captured_inventory = inventory(&snapshot)?;
    if progress.inventory != captured_inventory {
        progress.inventory = captured_inventory;
        progress.after = [0; 16];
        progress.repository = [0; 16];
        progress.verification.clear();
        progress.purge.clear();
    }
    let mut selected = None;
    for id in snapshot.object_identities() {
        let bytes = snapshot
            .object(id)
            .map_err(|_| ServiceFailure::CorruptState)?
            .ok_or(ServiceFailure::CorruptState)?;
        let Some(registration) = BackupRepositoryRegistration::decode(bytes).map_err(failure)?
        else {
            continue;
        };
        let repository_id = registration.identity().repository_id();
        if repository_id > progress.after
            && selected
                .as_ref()
                .is_none_or(|(_, prior): &(_, BackupRepositoryRegistration)| {
                    repository_id < prior.identity().repository_id()
                })
        {
            selected = Some((id, registration));
        }
    }
    if let Some((id, registration)) = selected {
        if progress.repository != registration.identity().repository_id() {
            progress.repository = registration.identity().repository_id();
            progress.verification.clear();
            progress.purge.clear();
        }
        let identity = registration.identity();
        let constructor = match identity.provider_kind() {
            "localFilesystem" => positron_governance::RepositoryOperationParameters::local,
            "awsS3" => positron_governance::RepositoryOperationParameters::aws_s3,
            "googleCloudStorage" => {
                positron_governance::RepositoryOperationParameters::google_cloud_storage
            },
            "azureBlob" => positron_governance::RepositoryOperationParameters::azure_blob,
            _ => return Err(ServiceFailure::CorruptState),
        };
        let parameters = constructor(
            positron_governance::RepositoryAction::Verify,
            registration.locator(),
            identity.repository_id(),
            identity.integrity_fingerprint(),
            identity.prefix_commitment(),
        )
        .map_err(|_| ServiceFailure::CorruptState)?;
        let native = super::super::repository_administration::repository_resources(
            parameters.provider_kind(),
        );
        let memory = native
            .get(ResourceDimension::MemoryBytes)
            .checked_add(
                BackupPublisher::registry_read_memory_bytes()
                    .checked_add(
                        BackupPublisher::control_read_memory_bytes()
                            .checked_mul(2)
                            .ok_or(ServiceFailure::CapacityUnavailable)?,
                    )
                    .ok_or(ServiceFailure::CapacityUnavailable)?,
            )
            .ok_or(ServiceFailure::CapacityUnavailable)?;
        let amounts = ResourceAmounts::new(ResourceDimension::ALL.map(|dimension| {
            if dimension == ResourceDimension::MemoryBytes {
                memory
            } else {
                native.get(dimension)
            }
        }));
        let claim = RecoveryWorkClaim::tenant(tenant, RecoveryWorkKind::Purge, amounts)
            .map_err(|_| ServiceFailure::CapacityUnavailable)?;
        let resources = NativeAwsResources::new(
            services
                .instance
                ._authority
                .recovery()
                .reserve(claim)
                .map_err(|_| ServiceFailure::CapacityUnavailable)?
                .transfer(),
        );
        // Keep the admitted owner older than this dedicated runtime. On a
        // timeout, Rust drops providers and shuts down spawned SDK async tasks
        // before releasing the grant. An already accepted remote mutation can
        // still be ambiguous; the signed cursor/CAS reconciles that on retry.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .map_err(|_| ServiceFailure::StorageUnavailable)?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let (opened, provider) = provider_turn(
            &runtime,
            deadline,
            super::super::repository_administration::open_repository(
                services,
                parameters,
                Some(resources.clone()),
            ),
        )?;
        if &opened != identity {
            return Err(ServiceFailure::BackupRepositoryRejected);
        }
        let mut publisher = BackupPublisher::new(provider.as_ref(), &opened, &signer)
            .with_control_resources(&resources, 0)
            .map_err(failure)?;
        if let Some(anchor) = registration.registry_generation() {
            publisher = publisher.with_trusted_generation(anchor).map_err(failure)?;
        }
        let owner = operation.operation_id().to_bytes();
        let request = operation.request().canonical_digest();
        let mut verification = if progress.verification.is_empty() {
            provider_turn(
                &runtime,
                deadline,
                publisher.begin_registry_verification(owner, request),
            )?
        } else {
            publisher
                .resume_registry_verification(&progress.verification, owner, request)
                .map_err(failure)?
        };
        if !verification.complete().map_err(failure)? {
            provider_turn(
                &runtime,
                deadline,
                publisher.registry_verification_step(&mut verification),
            )?;
            progress.verification = publisher
                .registry_verification_checkpoint(&verification)
                .map_err(failure)?;
            super::checkpoint::persist(services, &catalog, execution, binding, &progress)?;
            return Ok(None);
        }
        progress.verification = publisher
            .registry_verification_checkpoint(&verification)
            .map_err(failure)?;
        let publisher = publisher
            .with_registry_verification(&verification)
            .map_err(failure)?;
        let mut purge = if progress.purge.is_empty() {
            provider_turn(
                &runtime,
                deadline,
                publisher.begin_tenant_purge(&tombstone, owner, request),
            )?
        } else {
            publisher
                .resume_tenant_purge_checkpoint(&progress.purge, owner, request)
                .map_err(failure)?
        };
        provider_turn(&runtime, deadline, publisher.tenant_purge_step(&mut purge))?;
        progress.purge = publisher.tenant_purge_checkpoint(&purge).map_err(failure)?;
        if !purge.complete() {
            super::checkpoint::persist(services, &catalog, execution, binding, &progress)?;
            return Ok(None);
        }
        let head = purge
            .registry_generation()
            .ok_or(ServiceFailure::CorruptState)?;
        if registration.registry_generation() != Some(head) {
            let replacement = registration
                .with_registry_generation(head)
                .and_then(|registration| registration.catalog_object())
                .map_err(failure)?;
            let actor = DurableOperationAdministration::resume_tenant_purge_actor(
                &catalog,
                operation.operation_id(),
                services
                    .maintenance_status_now()
                    .map_err(|_| ServiceFailure::StorageUnavailable)?,
            )
            .map_err(|_| ServiceFailure::Unauthorized)?;
            DurableOperationAdministration::publish_tenant_purge_repository(
                &catalog,
                actor,
                operation.operation_id(),
                id,
                replacement,
                services
                    .maintenance_status_now()
                    .map_err(|_| ServiceFailure::StorageUnavailable)?,
            )
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        }
        progress.after = progress.repository;
        progress.repository = [0; 16];
        progress.verification.clear();
        progress.purge.clear();
        progress.inventory = inventory(
            &catalog
                .pin()
                .map_err(|_| ServiceFailure::CatalogUnavailable)?,
        )?;
        super::checkpoint::persist(services, &catalog, execution, binding, &progress)?;
        return Ok(None);
    }
    Ok(Some(RepositoryPurgeProof {
        generation: catalog
            .pin()
            .map_err(|_| ServiceFailure::CatalogUnavailable)?
            .identity(),
    }))
}
fn inventory(snapshot: &positron_kernel::CatalogSnapshot) -> Result<[u8; 32], ServiceFailure> {
    let mut hash = Sha256::new();
    hash.update(b"positron.tenant-purge.repositories.v1\0");
    for id in snapshot.object_identities() {
        let bytes = snapshot
            .object(id)
            .map_err(|_| ServiceFailure::CorruptState)?
            .ok_or(ServiceFailure::CorruptState)?;
        if BackupRepositoryRegistration::decode(bytes)
            .map_err(failure)?
            .is_some()
        {
            hash.update(id.to_bytes());
        }
    }
    Ok(hash.finalize().into())
}
// A full-version deletion may contain many verified requests. The entire
// provider turn shares the existing native 15-second request deadline, so a
// slow/ambiguous attempt yields without advancing its persisted signed cursor.
fn provider_turn<T>(
    runtime: &tokio::runtime::Runtime,
    deadline: std::time::Instant,
    future: impl std::future::Future<Output = Result<T, RepositoryFailure>>,
) -> Result<T, ServiceFailure> {
    runtime.block_on(async {
        tokio::time::timeout(
            deadline.saturating_duration_since(std::time::Instant::now()),
            future,
        )
        .await
        .map_err(|_| ServiceFailure::StorageUnavailable)?
        .map_err(failure)
    })
}
fn failure(failure: RepositoryFailure) -> ServiceFailure {
    match failure {
        RepositoryFailure::LimitExceeded | RepositoryFailure::ControlMemoryRequired { .. } => {
            ServiceFailure::CapacityUnavailable
        },
        RepositoryFailure::CorruptState | RepositoryFailure::IdentityMismatch => {
            ServiceFailure::BackupRepositoryRejected
        },
        _ => ServiceFailure::StorageUnavailable,
    }
}
