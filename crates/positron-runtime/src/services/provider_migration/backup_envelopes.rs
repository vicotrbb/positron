//! Signed Registry state is the restartable progress owner for additive rewraps.
use super::*;
use crate::ServiceFailure;
use crate::instance_bootstrap::BackupRootRetirementProof;
use positron_backup::{BackupEnvelopeOverlay, BackupPublisher, BackupRepositoryRegistration};
use positron_kernel::{NativeAwsResources, ResourceAmounts, ResourceDimension, WorkClaim};
use sha2::{Digest, Sha256};

/// A turn publishes at most one overlay. Restart discovers that immutable
/// publication again and repairs its Catalog anchor before proceeding.
pub(super) fn step(
    services: &ServiceHandle,
    operation: DurableOperation,
    actor: positron_governance::AuthorizedContext,
    configuration: Option<&positron_config::EffectiveConfiguration>,
    context: crate::instance_bootstrap::RootMigrationContext<'_>,
    cancellation: Option<&crate::TaskCancellation>,
) -> Result<Option<BackupRootRetirementProof>, ServiceFailure> {
    if cancellation.is_some_and(crate::TaskCancellation::is_cancelled) {
        return Err(ServiceFailure::Cancelled);
    }
    let (registrations, inventory_digest) = {
        let _gate = services.catalog_operation()?;
        let catalog = services
            .open_maintenance_catalog()
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        let basis = catalog
            .pin()
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        let mut registrations = Vec::new();
        for address in basis.object_identities() {
            let bytes = basis
                .object(address)
                .map_err(|_| ServiceFailure::CorruptState)?
                .ok_or(ServiceFailure::CorruptState)?;
            if let Some(registration) =
                BackupRepositoryRegistration::decode(bytes).map_err(failure)?
            {
                if registrations.len() == 1024 {
                    return Err(ServiceFailure::CapacityUnavailable);
                }
                registrations.push(registration.identity().repository_id());
            }
        }
        (
            registrations,
            crate::instance_bootstrap::registration_digest(&basis)
                .map_err(super::super::tenant_rotation::rotation_failure)?,
        )
    };
    if registrations.is_empty() {
        let _gate = services.catalog_operation()?;
        let catalog = services
            .open_maintenance_catalog()
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        let basis = catalog
            .pin()
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        return Ok(Some(BackupRootRetirementProof {
            registrations: crate::instance_bootstrap::registration_digest(&basis)
                .map_err(super::super::tenant_rotation::rotation_failure)?,
            target: [0; 32],
        }));
    }
    let (source, target) = services
        .instance
        .backup_migration_envelopes(Some(context))
        .map_err(super::super::tenant_rotation::rotation_failure)?;
    for repository_id in registrations {
        let (_, registration, parameters, signer) =
            super::super::backup_administration::registered::registered(services, repository_id)
                .map_err(registration_failure)?;
        let native = super::super::repository_administration::repository_resources(
            parameters.provider_kind(),
        );
        let memory = native
            .get(ResourceDimension::MemoryBytes)
            .checked_add(
                BackupPublisher::registry_read_memory_bytes().max(
                    BackupPublisher::control_read_memory_bytes()
                        .checked_mul(9)
                        .ok_or(ServiceFailure::CapacityUnavailable)?,
                ),
            )
            .and_then(|n| n.checked_add(source.retained_memory_bytes()))
            .and_then(|n| n.checked_add(target.retained_memory_bytes()))
            .ok_or(ServiceFailure::CapacityUnavailable)?;
        let amounts = ResourceAmounts::new(ResourceDimension::ALL.map(|dimension| {
            if dimension == ResourceDimension::MemoryBytes {
                memory
            } else {
                native.get(dimension)
            }
        }));
        let claim = WorkClaim::backup_repository_read(amounts)
            .map_err(|_| ServiceFailure::CapacityUnavailable)?;
        let grant = NativeAwsResources::new(
            services
                .instance
                .resource_governor()
                .reserve(claim)
                .map_err(|_| ServiceFailure::CapacityUnavailable)?
                .transfer(),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .map_err(|_| ServiceFailure::StorageUnavailable)?;
        let (identity, repository) = runtime
            .block_on(super::super::repository_administration::open_repository(
                services,
                parameters,
                Some(grant.clone()),
            ))
            .map_err(failure)?;
        if registration.identity() != &identity {
            return Err(ServiceFailure::BackupRepositoryRejected);
        }
        let external = source
            .retained_memory_bytes()
            .checked_add(target.retained_memory_bytes())
            .ok_or(ServiceFailure::CapacityUnavailable)?;
        let mut publisher = BackupPublisher::new(repository.as_ref(), &identity, &signer)
            .with_control_resources(&grant, external)
            .map_err(failure)?;
        if let Some(anchor) = registration.registry_generation() {
            publisher = publisher.with_trusted_generation(anchor).map_err(failure)?;
        }
        // A retained Catalog anchor normally needs only the current frame and
        // head recheck. The existing signed walker also handles a lost CAS ack.
        let mut ancestry = runtime
            .block_on(publisher.begin_registry_verification(
                operation.operation_id().to_bytes(),
                parameters.intent_digest(),
            ))
            .map_err(failure)?;
        while !ancestry.complete().map_err(failure)? {
            runtime
                .block_on(publisher.registry_verification_step(&mut ancestry))
                .map_err(failure)?;
        }
        let publisher = publisher
            .with_registry_verification(&ancestry)
            .map_err(failure)?;
        let mut cursor = None;
        let mut head = None;
        loop {
            let page = runtime
                .block_on(publisher.list(cursor, 128))
                .map_err(failure)?;
            head = page.registry_generation().or(head);
            for receipt in page.snapshots() {
                let verification = runtime
                    .block_on(publisher.begin_snapshot_verification(
                        receipt.snapshot_id(),
                        operation.operation_id().to_bytes(),
                        parameters.intent_digest(),
                    ))
                    .map_err(failure)?;
                // Actual recovered key identities, rather than protected byte
                // equality, prove each historical epoch against the stable SYSTEM KEK.
                for index in 0..publisher.verification_key_count(&verification) {
                    let envelope = runtime
                        .block_on(publisher.read_verification_key(&verification, index))
                        .map_err(failure)?;
                    let tenant = positron_domain::identity::TenantId::from_bytes(envelope.tenant())
                        .map_err(|_| ServiceFailure::CorruptState)?;
                    let recovered = services
                        .instance
                        .key
                        .backup_tenant_key_identity(
                            services.instance.instance,
                            tenant,
                            envelope.protected(),
                        )
                        .map_err(|failure| match failure {
                            positron_kernel::BootstrapKeyFailure::Authentication
                            | positron_kernel::BootstrapKeyFailure::InvalidInput => {
                                ServiceFailure::BackupRepositoryRejected
                            },
                            positron_kernel::BootstrapKeyFailure::LimitExceeded => {
                                ServiceFailure::CapacityUnavailable
                            },
                            _ => ServiceFailure::KeyUnavailable,
                        })?;
                    if recovered != (envelope.epoch(), envelope.fingerprint()) {
                        return Err(ServiceFailure::BackupRepositoryRejected);
                    }
                }
                match runtime
                    .block_on(
                        publisher.read_envelope_overlay(receipt.snapshot_id(), target.identity()),
                    )
                    .map_err(failure)?
                {
                    Some(overlay) => {
                        verify_target(services, configuration, overlay.target(), &target)?
                    },
                    None => {
                        verify_target(services, configuration, &target, &target)?;
                        let overlay = BackupEnvelopeOverlay::new(
                            receipt.snapshot_id(),
                            receipt.manifest(),
                            verification.manifest().key_context(),
                            operation.operation_id().to_bytes(),
                            source.clone(),
                            target.clone(),
                        )
                        .map_err(failure)?;
                        let generation = runtime
                            .block_on(publisher.publish_envelope_overlay(&overlay))
                            .map_err(failure)?;
                        #[cfg(test)]
                        super::super::backup_administration::hit_stop(
                            super::super::backup_administration::StopPoint::BackupOverlayPublished,
                            cancellation,
                        )?;
                        anchor(services, operation, actor, &registration, generation)?;
                        return Ok(None);
                    },
                }
            }
            cursor = page.next_cursor();
            if cursor.is_none() {
                break;
            }
        }
        if head != registration.registry_generation() {
            if let Some(head) = head {
                anchor(services, operation, actor, &registration, head)?;
                return Ok(None);
            }
            return Err(ServiceFailure::BackupRepositoryRejected);
        }
    }
    let _gate = services.catalog_operation()?;
    let catalog = services
        .open_maintenance_catalog()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    let basis = catalog
        .pin()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    if crate::instance_bootstrap::registration_digest(&basis)
        .map_err(super::super::tenant_rotation::rotation_failure)?
        != inventory_digest
    {
        return Err(ServiceFailure::CatalogBusy);
    }
    Ok(Some(BackupRootRetirementProof {
        registrations: crate::instance_bootstrap::registration_digest(&basis)
            .map_err(super::super::tenant_rotation::rotation_failure)?,
        target: Sha256::digest(target.encode()).into(),
    }))
}
fn registration_failure(failure: MaintenanceServiceFailure) -> ServiceFailure {
    match failure {
        MaintenanceServiceFailure::AdministrationUnavailable => ServiceFailure::CatalogUnavailable,
        MaintenanceServiceFailure::CapacityUnavailable => ServiceFailure::CapacityUnavailable,
        _ => ServiceFailure::BackupRepositoryRejected,
    }
}
fn failure(failure: positron_backup::RepositoryFailure) -> ServiceFailure {
    use positron_backup::RepositoryFailure as F;
    match failure {
        F::ControlMemoryRequired { .. } | F::Busy | F::Throttled { .. } => {
            ServiceFailure::CapacityUnavailable
        },
        F::Interrupted | F::StorageUnavailable | F::OutcomeUnknown => {
            ServiceFailure::StorageUnavailable
        },
        F::PreconditionFailed => ServiceFailure::CatalogBusy,
        _ => ServiceFailure::BackupRepositoryRejected,
    }
}
fn anchor(
    services: &ServiceHandle,
    operation: DurableOperation,
    actor: positron_governance::AuthorizedContext,
    registration: &BackupRepositoryRegistration,
    generation: [u8; 32],
) -> Result<(), ServiceFailure> {
    let _gate = services.catalog_operation()?;
    let catalog = services
        .open_maintenance_catalog()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    let basis = catalog
        .pin()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    let (previous, current) = BackupRepositoryRegistration::find(
        &basis,
        services.instance.instance.to_bytes(),
        registration.identity().repository_id(),
    )
    .map_err(failure)?
    .ok_or(ServiceFailure::CorruptState)?;
    if current.encode().map_err(failure)? != registration.encode().map_err(failure)? {
        return Err(ServiceFailure::CatalogBusy);
    }
    let successor = current
        .with_registry_generation(generation)
        .map_err(failure)?
        .catalog_object()
        .map_err(failure)?;
    DurableOperationAdministration::publish_key_provider_backup_registry(
        &catalog,
        actor,
        operation.operation_id(),
        previous,
        successor,
        services
            .maintenance_status_now()
            .map_err(|_| ServiceFailure::StorageUnavailable)?,
    )
    .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    Ok(())
}

fn verify_target(
    services: &ServiceHandle,
    configuration: Option<&positron_config::EffectiveConfiguration>,
    envelope: &positron_kernel::key_provider::KeyEnvelope,
    current: &positron_kernel::key_provider::KeyEnvelope,
) -> Result<(), ServiceFailure> {
    if let Some(access) =
        configuration.and_then(positron_config::EffectiveConfiguration::provider_access)
    {
        let configuration =
            crate::native_root_configuration(access).map_err(|_| ServiceFailure::KeyUnavailable)?;
        let session =
            positron_kernel::RootRewrapSession::admit_provider(&services.instance._authority)
                .map_err(|_| ServiceFailure::CapacityUnavailable)?;
        let epoch = services
            .instance
            .key
            .active_root_epoch()
            .map_err(|_| ServiceFailure::KeyUnavailable)?;
        session
            .verify_backup_provider_root_envelope(
                configuration,
                &services.instance.key,
                services.instance.instance,
                epoch,
                &envelope.encode(),
            )
            .map_err(|failure| match failure {
                positron_kernel::key_provider::KeyProviderFailure::WrongKey
                | positron_kernel::key_provider::KeyProviderFailure::ContextMismatch
                | positron_kernel::key_provider::KeyProviderFailure::InvalidConfiguration => {
                    ServiceFailure::BackupRepositoryRejected
                },
                positron_kernel::key_provider::KeyProviderFailure::LimitExceeded => {
                    ServiceFailure::CapacityUnavailable
                },
                _ => ServiceFailure::KeyUnavailable,
            })
    } else if envelope == current {
        Ok(())
    } else {
        Err(ServiceFailure::BackupRepositoryRejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unavailable_registered_catalog_preserves_migration_retry() {
        let failure = registration_failure(MaintenanceServiceFailure::AdministrationUnavailable);
        assert!(!matches!(failure, ServiceFailure::BackupRepositoryRejected));
        assert_eq!(failure, ServiceFailure::CatalogUnavailable);
    }
}
