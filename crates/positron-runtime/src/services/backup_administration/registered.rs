//! Authenticated registered Repository inputs shared by creation-free reads and retention.
use super::*;
pub(in crate::services) fn registered(
    services: &ServiceHandle,
    repository: [u8; 16],
) -> Result<
    (
        positron_kernel::CatalogObjectId,
        positron_backup::BackupRepositoryRegistration,
        RepositoryOperationParameters,
        positron_kernel::BackupControlSigner,
    ),
    MaintenanceServiceFailure,
> {
    let _gate = services
        .catalog_operation()
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
    let catalog = services.open_maintenance_catalog()?;
    let basis = catalog
        .pin()
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
    let (address, registration) = positron_backup::BackupRepositoryRegistration::find(
        &basis,
        services.instance.instance.to_bytes(),
        repository,
    )
    .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
    .ok_or(MaintenanceServiceFailure::SourceUnavailable)?;
    let identity = registration.identity();
    let constructor = match identity.provider_kind() {
        "localFilesystem" => RepositoryOperationParameters::local,
        "awsS3" => RepositoryOperationParameters::aws_s3,
        "googleCloudStorage" => RepositoryOperationParameters::google_cloud_storage,
        "azureBlob" => RepositoryOperationParameters::azure_blob,
        _ => return Err(MaintenanceServiceFailure::AdministrationUnavailable),
    };
    let parameters = constructor(
        RepositoryAction::Verify,
        registration.locator(),
        identity.repository_id(),
        identity.integrity_fingerprint(),
        identity.prefix_commitment(),
    )
    .map_err(super::super::provider_migration::operation_failure)?;
    let (_, governance) = basis
        .governance_object()
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
    let signer = services
        .instance
        .key
        .backup_control_signer(
            services.instance.instance,
            governance.protected_integrity_key(),
        )
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
    Ok((address, registration, parameters, signer))
}

impl ServiceHandle {
    pub(crate) fn list_backups(
        &self,
        bearer: &str,
        bytes: &[u8],
    ) -> Result<positron_api::backup::BackupListResponse, MaintenanceServiceFailure> {
        {
            let _gate = self
                .catalog_operation()
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
            self.authorize_system_administration(bearer)?;
        }
        let request = positron_api::backup::BackupListRequest::decode(bytes)
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let repository =
            positron_domain::identity::TenantId::parse_canonical(&request.repository_id)
                .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?
                .to_bytes();
        let (_, registration, parameters, signer) = registered(self, repository)?;
        let native = super::super::repository_administration::repository_resources(
            parameters.provider_kind(),
        );
        // Control decoding overlaps the provider transport and resolver peak.
        let memory = native
            .get(positron_kernel::ResourceDimension::MemoryBytes)
            .checked_add(positron_backup::BackupPublisher::registry_read_memory_bytes())
            .ok_or(MaintenanceServiceFailure::CapacityUnavailable)?;
        let resources = positron_kernel::ResourceAmounts::new(
            positron_kernel::ResourceDimension::ALL.map(|dimension| match dimension {
                positron_kernel::ResourceDimension::MemoryBytes => memory,
                _ => native.get(dimension),
            }),
        );
        let claim = positron_kernel::WorkClaim::backup_repository_read(resources)
            .map_err(|_| MaintenanceServiceFailure::CapacityUnavailable)?;
        let reservation = self
            .instance
            .resource_governor()
            .reserve(claim)
            .map_err(|_| MaintenanceServiceFailure::CapacityUnavailable)?
            .transfer();
        let grant = positron_kernel::NativeAwsResources::new(reservation);
        let page = std::thread::scope(|scope| {
            let worker = std::thread::Builder::new()
                .name("positron-backup-list".into())
                .spawn_scoped(scope, || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .max_blocking_threads(1)
                        .build()
                        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
                    let (identity, provider) = runtime
                        .block_on(super::super::repository_administration::open_repository(
                            self,
                            parameters,
                            Some(grant.clone()),
                        ))
                        .map_err(read_failure)?;
                    if registration.identity() != &identity {
                        return Err(MaintenanceServiceFailure::PreconditionFailed);
                    }
                    let mut publisher = positron_backup::BackupPublisher::new(
                        provider.as_ref(),
                        &identity,
                        &signer,
                    )
                    .with_control_resources(&grant, 0)
                    .map_err(read_failure)?;
                    if let Some(anchor) = registration.registry_generation() {
                        publisher = publisher
                            .with_trusted_generation(anchor)
                            .map_err(read_failure)?;
                    }
                    let cursor = request.cursor.as_deref().map(decode_cursor).transpose()?;
                    // A terminal cleanup acknowledgement advances the head once
                    // beyond its Catalog receipt anchor. Prove that small gap
                    // without turning a read request into an unbounded walk:
                    // current frame, immediate predecessor, then head recheck.
                    use sha2::Digest;
                    let mut request_digest = sha2::Sha256::new();
                    request_digest.update(b"Positron Backup Registry list proof v1\0");
                    request_digest.update(bytes);
                    let request_digest = request_digest.finalize().into();
                    let mut verification = runtime
                        .block_on(publisher.begin_registry_verification(repository, request_digest))
                        .map_err(read_failure)?;
                    for _ in 0..3 {
                        if verification.complete().map_err(read_failure)? {
                            break;
                        }
                        runtime
                            .block_on(publisher.registry_verification_step(&mut verification))
                            .map_err(read_failure)?;
                    }
                    if !verification.complete().map_err(read_failure)? {
                        return Err(MaintenanceServiceFailure::CapacityUnavailable);
                    }
                    let publisher = publisher
                        .with_registry_verification(&verification)
                        .map_err(read_failure)?;
                    let page = runtime
                        .block_on(publisher.list(cursor, request.limit as usize))
                        .map_err(read_failure)?;
                    Ok::<_, MaintenanceServiceFailure>(page)
                })
                .map_err(|_| MaintenanceServiceFailure::CapacityUnavailable)?;
            worker
                .join()
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
        })?;
        // The Catalog trust anchor may advance while provider I/O is in flight.
        // Refuse a response based on an older trusted row after that advance.
        let (_, current, _, _) = registered(self, repository)?;
        if current.identity() != registration.identity()
            || current.registry_generation() != registration.registry_generation()
        {
            return Err(MaintenanceServiceFailure::PreconditionFailed);
        }
        let hex = super::super::maintenance_api::hex;
        Ok(positron_api::backup::BackupListResponse {
            repository: super::wire::repository_response(
                parameters,
                self.instance.instance.to_bytes(),
            )?,
            registry_generation_checksum: page.registry_generation().map(hex),
            entries: page
                .snapshots()
                .iter()
                .map(|entry| positron_api::backup::BackupListEntry {
                    snapshot_id: super::super::maintenance_api::hex(entry.snapshot_id()),
                    manifest_checksum: hex(entry.manifest().checksum()),
                    created_unix_seconds: entry.created_at(),
                    retain_until_unix_seconds: entry.retain_until(),
                })
                .collect(),
            next_cursor: page.next_cursor().map(|cursor| {
                cursor
                    .encode()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect()
            }),
        })
    }
}
fn decode_cursor(
    text: &str,
) -> Result<positron_backup::BackupListCursor, MaintenanceServiceFailure> {
    let mut bytes = Vec::with_capacity(88);
    for pair in text.as_bytes().chunks_exact(2) {
        let value = std::str::from_utf8(pair)
            .ok()
            .and_then(|text| u8::from_str_radix(text, 16).ok())
            .ok_or(MaintenanceServiceFailure::InvalidRequest)?;
        bytes.push(value);
    }
    positron_backup::BackupListCursor::decode(&bytes)
        .map_err(|_| MaintenanceServiceFailure::InvalidRequest)
}
fn read_failure(failure: positron_backup::RepositoryFailure) -> MaintenanceServiceFailure {
    use positron_backup::RepositoryFailure as F;
    match failure {
        F::InvalidInput => MaintenanceServiceFailure::InvalidRequest,
        F::NotFound => MaintenanceServiceFailure::SourceUnavailable,
        F::PreconditionFailed | F::IdentityMismatch => {
            MaintenanceServiceFailure::PreconditionFailed
        },
        F::Busy | F::Throttled { .. } | F::LimitExceeded | F::ControlMemoryRequired { .. } => {
            MaintenanceServiceFailure::CapacityUnavailable
        },
        _ => MaintenanceServiceFailure::AdministrationUnavailable,
    }
}
