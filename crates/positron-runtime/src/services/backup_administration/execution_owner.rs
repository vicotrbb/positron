//! Exact admitted native Repository and signing custody shared by worker phases.
use super::*;
pub(in crate::services::backup_administration) struct BackupOwner {
    pub(in crate::services::backup_administration) runtime: tokio::runtime::Runtime,
    pub(in crate::services::backup_administration) repository: Box<dyn Repository>,
    pub(in crate::services::backup_administration) identity: RepositoryIdentity,
    pub(in crate::services::backup_administration) signer: BackupControlSigner,
    pub(in crate::services::backup_administration) trusted: Option<[u8; 32]>,
    pub(in crate::services::backup_administration) resources:
        std::sync::Arc<positron_kernel::NativeAwsResources>,
    registry: Option<positron_backup::BackupRegistryVerification>,
}
impl BackupOwner {
    pub(in crate::services::backup_administration) fn open(
        services: &ServiceHandle,
        execution: &mut MaintenanceExecution<'_>,
        operation: DurableOperation,
    ) -> Result<Self, ServiceFailure> {
        let binding = RepositoryOperationBinding::from_execution(execution)
            .map_err(|_| ServiceFailure::CorruptState)?;
        let parameters = operation
            .backup_binding()
            .ok_or(ServiceFailure::CorruptState)?
            .repository();
        let resources = match execution
            .retained_repository_resources(binding)
            .map_err(crate::services::maintenance::map_failure)?
        {
            Some(resources) => resources,
            None => execution
                .transfer_repository_resources(binding)
                .map_err(crate::services::maintenance::map_failure)?,
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .map_err(|_| ServiceFailure::StorageUnavailable)?;
        let (identity, repository) = runtime
            .block_on(crate::services::repository_administration::open_repository(
                services,
                parameters,
                Some(resources.clone()),
            ))
            .map_err(provider_failure)?;
        let (signer, trusted) = {
            let _gate = services.catalog_operation()?;
            let catalog = services
                .open_maintenance_catalog()
                .map_err(|_| ServiceFailure::CatalogUnavailable)?;
            let basis = catalog
                .pin()
                .map_err(|_| ServiceFailure::CatalogUnavailable)?;
            let (_, governance) = basis
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
            let (_, registration) = positron_backup::BackupRepositoryRegistration::find(
                &basis,
                services.instance.instance.to_bytes(),
                identity.repository_id(),
            )
            .map_err(provider_failure)?
            .ok_or(ServiceFailure::CorruptState)?;
            if registration.identity() != &identity
                || registration.binding_identity().map_err(provider_failure)?
                    != operation
                        .backup_binding()
                        .ok_or(ServiceFailure::CorruptState)?
                        .registration_identity()
            {
                return Err(ServiceFailure::CorruptState);
            }
            (signer, registration.registry_generation())
        };
        let mut owner = Self {
            runtime,
            repository,
            identity,
            signer,
            trusted,
            resources,
            registry: None,
        };
        let (_, bytes) = checkpoint::current(services, execution, binding)?;
        let (registry, _) = checkpoint::unpack(&bytes)?;
        if !registry.is_empty() {
            owner.registry = match owner
                .base_publisher(0)
                .map_err(provider_failure)?
                .resume_registry_verification(
                    registry,
                    binding.operation_id(),
                    binding.intent_digest(),
                ) {
                Ok(registry) => Some(registry),
                // A newer authoritative Catalog anchor supersedes this older
                // checkpoint. Rebase through that owner rather than downgrade it.
                Err(RepositoryFailure::PreconditionFailed) => None,
                Err(failure) => return Err(capture_failure(failure)),
            };
        }
        Ok(owner)
    }
    pub(in crate::services::backup_administration) fn set_trusted(&mut self, trusted: [u8; 32]) {
        if self.trusted != Some(trusted) {
            self.trusted = Some(trusted);
            self.registry = None;
        }
    }
    fn base_publisher(
        &self,
        external_retained_bytes: u64,
    ) -> Result<BackupPublisher<'_>, RepositoryFailure> {
        let publisher =
            BackupPublisher::new(self.repository.as_ref(), &self.identity, &self.signer)
                .with_control_resources(&self.resources, external_retained_bytes)?;
        match self.trusted {
            Some(trusted) => publisher.with_trusted_generation(trusted),
            None => Ok(publisher),
        }
    }
    pub(in crate::services::backup_administration) fn publisher(
        &self,
        external_retained_bytes: u64,
    ) -> Result<BackupPublisher<'_>, RepositoryFailure> {
        let publisher = self.base_publisher(external_retained_bytes)?;
        match &self.registry {
            Some(registry) if registry.complete()? => {
                publisher.with_registry_verification(registry)
            },
            _ => Ok(publisher),
        }
    }
    pub(in crate::services::backup_administration) fn registry_checkpoint(
        &self,
    ) -> Result<Option<Vec<u8>>, ServiceFailure> {
        self.registry
            .as_ref()
            .map(|registry| {
                self.base_publisher(0)
                    .and_then(|publisher| publisher.registry_verification_checkpoint(registry))
                    .map_err(provider_failure)
            })
            .transpose()
    }
    /// One signed Registry frame per turn. A changed proof is durable before
    /// any subsequent operation step can use its newly established authority.
    pub(in crate::services::backup_administration) fn registry_ready(
        &mut self,
        services: &ServiceHandle,
        execution: &MaintenanceExecution<'_>,
        external: u64,
    ) -> Result<bool, ServiceFailure> {
        let binding = RepositoryOperationBinding::from_execution(execution)
            .map_err(super::super::super::maintenance::map_failure)?;
        let mut registry = self.registry.take();
        let publisher = self.base_publisher(external).map_err(provider_failure)?;
        let before = registry
            .as_ref()
            .map(|registry| publisher.registry_verification_checkpoint(registry))
            .transpose()
            .map_err(provider_failure)?;
        let complete = if let Some(registry) = registry.as_mut() {
            self.runtime
                .block_on(publisher.registry_verification_step(registry))
                .map_err(provider_failure)?
        } else {
            registry = Some(
                self.runtime
                    .block_on(publisher.begin_registry_verification(
                        binding.operation_id(),
                        binding.intent_digest(),
                    ))
                    .map_err(provider_failure)?,
            );
            false
        };
        let after = registry
            .as_ref()
            .map(|registry| publisher.registry_verification_checkpoint(registry))
            .transpose()
            .map_err(provider_failure)?;
        drop(publisher);
        self.registry = registry;
        if before != after {
            checkpoint::persist(services, execution, binding, after.as_deref(), None)?;
            return Ok(false);
        }
        Ok(complete)
    }
}
