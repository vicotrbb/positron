use super::*;

#[test]
fn accepted_migration_rejects_changed_configuration_without_preparing_route()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let configuration = fixture.migration_configuration()?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(initialized)?;
    let current = services
        .manage_provider_migration(&administrator, br#"{"action":"status"}"#)
        .expect("status");
    let accepted = services
        .manage_provider_migration(
            &administrator,
            &ProviderMigrationRequest {
                action: "prepare".into(),
                expected_catalog_generation: Some(current.catalog_generation),
                idempotency_key: Some("15151515-1515-4515-8515-151515151515".into()),
                configuration_reference: Some(configuration.to_string_lossy().into_owned()),
                operation_id: None,
            }
            .encode()?,
        )
        .expect("accepted");
    let original = std::fs::read_to_string(&configuration)?;
    std::fs::write(
        &configuration,
        original.replace("successor.key", "changed.key"),
    )?;
    crate::services::maintenance::wake_runtime_maintenance(&services, None)
        .expect("known rejection persisted");
    let request = ProviderMigrationRequest {
        action: "status".into(),
        expected_catalog_generation: None,
        idempotency_key: None,
        configuration_reference: None,
        operation_id: accepted.operation.map(|operation| operation.id),
    }
    .encode()?;
    let rejected = services
        .manage_provider_migration(&administrator, &request)
        .expect("failed lookup");
    assert_eq!(rejected.root_phase, "active");
    assert_eq!(rejected.active_epoch, 1);
    assert_eq!(rejected.successor_epoch, None);
    assert_eq!(
        rejected
            .operation
            .as_ref()
            .map(|operation| operation.status.as_str()),
        Some("failed")
    );
    assert_eq!(
        services
            .manage_provider_migration(&administrator, &request)
            .expect("stable failure")
            .operation,
        rejected.operation
    );
    Ok(())
}

#[test]
fn serving_root_handler_does_not_dispatch_unrelated_migration_tasks()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(initialized)?;
    let identity = positron_kernel::MaintenanceTaskId::new([0xd2; 16]).expect("identity");
    {
        let catalog = services.open_maintenance_catalog().expect("setup catalog");
        let task = positron_kernel::MaintenanceTask::with_contract(
            identity,
            positron_kernel::MaintenanceTaskClass::Migration,
            positron_kernel::MaintenanceScope::system(),
            positron_kernel::MaintenanceTrigger::Event,
            positron_kernel::MaintenancePreconditions::new(catalog.pin()?.number(), 1)
                .expect("preconditions"),
            Vec::new(),
            Vec::new(),
            positron_kernel::ResourceAmounts::new([1; 11]),
        )
        .expect("unrelated task");
        services
            .instance
            .maintenance_coordinator()
            .submit_and_persist(&catalog, task, 1)
            .expect("submit");
    }
    assert!(matches!(
        crate::services::maintenance::wake_runtime_maintenance(&services, None),
        Ok(false) | Err(crate::ServiceFailure::CapacityUnavailable)
    ));
    assert_eq!(
        services
            .instance
            .maintenance_coordinator()
            .status(identity)
            .expect("task status")
            .phase(),
        positron_kernel::MaintenanceTaskPhase::Queued
    );
    assert_eq!(
        services
            .manage_provider_migration(&administrator, br#"{"action":"status"}"#)
            .expect("serving status")
            .active_epoch,
        1
    );
    Ok(())
}

#[test]
fn accepted_migration_fails_closed_when_original_system_grant_is_revoked()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let configuration = fixture.migration_configuration()?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(initialized)?;
    let current = services
        .manage_provider_migration(&administrator, br#"{"action":"status"}"#)
        .expect("status");
    let accepted = services
        .manage_provider_migration(
            &administrator,
            &ProviderMigrationRequest {
                action: "prepare".into(),
                expected_catalog_generation: Some(current.catalog_generation),
                idempotency_key: Some("16161616-1616-4616-8616-161616161616".into()),
                configuration_reference: Some(configuration.to_string_lossy().into_owned()),
                operation_id: None,
            }
            .encode()?,
        )
        .expect("accepted");
    let id = positron_governance::OperationId::from_bytes(
        crate::services::maintenance_verification::decode_fixed_hex(
            &accepted.operation.ok_or("operation")?.id,
        )
        .ok_or("operation ID")?,
    )?;
    // The owning persistent credential schema permits a revoked grant. The
    // operator API deliberately has no system-credential rotation surface.
    {
        let catalog = services
            .open_maintenance_catalog()
            .expect("credential fixture catalog");
        let basis = catalog.pin()?;
        let (identity, governance) = basis.governance_object()?;
        let credentials = governance
            .credentials()
            .iter()
            .map(|credential| {
                if credential.scope_code() == 4 {
                    credential.with_active(false)
                } else {
                    *credential
                }
            })
            .collect::<Vec<_>>();
        let changed = positron_kernel::CatalogObject::new(
            governance.with_credentials(governance.credential_generation() + 1, &credentials)?,
        )?;
        let mut objects = basis
            .object_identities()
            .map(|identity| {
                let bytes = basis.object(identity)?.expect("fixture object missing");
                positron_kernel::CatalogObject::new(bytes.to_vec())
            })
            .collect::<Result<Vec<_>, _>>()?;
        objects.retain(|object| object.identity() != identity);
        objects.push(changed);
        catalog.commit(
            basis.identity(),
            positron_kernel::CatalogProposal::new(
                positron_kernel::TransactionId::new([0xd3; 16])?,
                positron_kernel::FormatEpoch::CATALOG_V1,
                objects,
            )?,
            None,
        )?;
    }
    crate::services::maintenance::wake_runtime_maintenance(&services, None)
        .expect("revoked grant becomes known failure");
    let catalog = services
        .open_maintenance_catalog()
        .expect("outcome catalog");
    let failed = positron_governance::DurableOperationAdministration::inspect(&catalog, id)?
        .ok_or("failed operation")?;
    assert_eq!(
        failed.status(),
        positron_governance::DurableOperationStatus::Failed
    );
    drop(catalog);
    assert_eq!(
        services
            .instance
            .local_key_rotation_status()?
            .active_epoch(),
        1
    );
    assert_eq!(
        services.manage_provider_migration(&administrator, br#"{"action":"status"}"#),
        Err(MaintenanceServiceFailure::AuthenticationRejected)
    );
    Ok(())
}

#[test]
fn migration_configuration_cannot_change_initialized_immutable_settings()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let configuration = fixture.migration_configuration()?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let active = crate::services::provider_migration::load_configuration(
        configuration.to_str().ok_or("path")?,
    )
    .expect("active configuration");
    crate::CatalogConfigurationPublication::new(Arc::clone(&initialized))
        .establish(&active)
        .expect("configuration authority");
    let original = std::fs::read_to_string(&configuration)?;
    std::fs::write(
        &configuration,
        original.replace("successor.key", "foreign-anchor.key"),
    )?;
    let services = ServiceHandle::new(initialized)?;
    let status = services
        .manage_provider_migration(&administrator, br#"{"action":"status"}"#)
        .expect("status");
    assert_eq!(
        services.manage_provider_migration(
            &administrator,
            &ProviderMigrationRequest {
                action: "prepare".into(),
                expected_catalog_generation: Some(status.catalog_generation),
                idempotency_key: Some("17171717-1717-4717-8717-171717171717".into()),
                configuration_reference: Some(configuration.to_string_lossy().into_owned()),
                operation_id: None,
            }
            .encode()?
        ),
        Err(MaintenanceServiceFailure::InvalidRequest)
    );
    assert_eq!(
        services.instance.local_key_rotation_status()?.phase(),
        crate::LocalKeyRotationPhase::Active
    );
    Ok(())
}

#[test]
fn cancelling_pending_phase_keeps_route_and_original_terminal_operation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let configuration = fixture.migration_configuration()?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(initialized)?;
    let current = services
        .manage_provider_migration(&administrator, br#"{"action":"status"}"#)
        .expect("status");
    let accepted = services
        .manage_provider_migration(
            &administrator,
            &ProviderMigrationRequest {
                action: "prepare".into(),
                expected_catalog_generation: Some(current.catalog_generation),
                idempotency_key: Some("18181818-1818-4818-8818-181818181818".into()),
                configuration_reference: Some(configuration.to_string_lossy().into_owned()),
                operation_id: None,
            }
            .encode()?,
        )
        .expect("accepted");
    let operation_id = accepted.operation.ok_or("operation")?.id;
    let cancellation = ProviderMigrationRequest {
        action: "cancel_operation".into(),
        expected_catalog_generation: Some(accepted.catalog_generation),
        idempotency_key: Some("19191919-1919-4919-8919-191919191919".into()),
        configuration_reference: None,
        operation_id: Some(operation_id.clone()),
    }
    .encode()?;
    let cancelled = services
        .manage_provider_migration(&administrator, &cancellation)
        .expect("cancelled");
    assert_eq!(
        cancelled
            .operation
            .as_ref()
            .map(|operation| operation.status.as_str()),
        Some("cancelled")
    );
    assert_eq!(
        services
            .manage_provider_migration(&administrator, &cancellation)
            .expect("cancel retry")
            .operation,
        cancelled.operation
    );
    let mut conflicting = ProviderMigrationRequest::decode(&cancellation)?;
    conflicting.expected_catalog_generation = Some(cancelled.catalog_generation);
    assert!(matches!(
        services.manage_provider_migration(&administrator, &conflicting.encode()?),
        Err(MaintenanceServiceFailure::IdempotencyConflict)
    ));
    crate::services::maintenance::wake_runtime_maintenance(&services, None)?;
    drop(services);
    let services = ServiceHandle::new(fixture.reopen()?)?;
    let lookup = ProviderMigrationRequest {
        action: "status".into(),
        expected_catalog_generation: None,
        idempotency_key: None,
        configuration_reference: None,
        operation_id: Some(operation_id),
    }
    .encode()?;
    let reopened = services
        .manage_provider_migration(&administrator, &lookup)
        .expect("terminal lookup");
    assert_eq!(reopened.operation, cancelled.operation);
    assert_eq!(reopened.root_phase, "active");
    assert_eq!(reopened.active_epoch, 1);
    Ok(())
}

#[test]
fn root_retirement_retains_checkpoint_without_signed_publication_proof()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, _) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(initialized)?;
    let catalog = services.open_maintenance_catalog().expect("catalog");
    let basis = catalog.pin()?;
    let (_, governance) = basis.governance_object()?;
    let records = catalog.governance_audit_records()?;
    let frontier = records.last().ok_or("audit frontier")?;
    let (task, binding) = positron_kernel::Catalog::governance_audit_checkpoint_task(
        frontier,
        governance.integrity_key_fingerprint(),
    )?;
    let coordinator = services.instance.maintenance_coordinator();
    let wrong_binding = positron_kernel::GovernanceAuditCheckpointBinding::new(
        binding.position(),
        [0xef; 32],
        binding.integrity_key_fingerprint(),
    )
    .expect("binding");
    let generation = catalog.pin()?.number();
    assert!(matches!(
        coordinator.submit_governance_audit_checkpoint_and_persist(
            &catalog,
            task.clone(),
            wrong_binding,
            17,
        ),
        Err(positron_kernel::MaintenanceFailure::InvalidInput)
    ));
    assert_eq!(catalog.pin()?.number(), generation);
    coordinator
        .submit_governance_audit_checkpoint_and_persist(&catalog, task.clone(), binding, 17)
        .expect("submit checkpoint");
    let execution = coordinator
        .start_task_with_reservation_and_persist(
            &catalog,
            &services.instance._authority,
            18,
            false,
            task.identity(),
        )
        .expect("dispatch")
        .ok_or("checkpoint execution")?;
    // A terminal descriptor alone cannot stand in for its signed artifact.
    execution
        .complete_and_persist(coordinator, &catalog, true)
        .expect("terminal descriptor");
    drop(execution);
    let session =
        positron_kernel::RootRewrapSession::admit_provider(&services.instance._authority)?;
    assert_eq!(
        coordinator
            .reclaim_terminal_records_for_root_retirement(&session, &catalog)
            .expect("guarded reclamation"),
        0
    );
    assert_eq!(
        coordinator
            .status(task.identity())
            .expect("retained checkpoint")
            .phase(),
        positron_kernel::MaintenanceTaskPhase::Succeeded
    );
    assert!(
        coordinator
            .guard_root_retirement_references(&session, &catalog, &catalog.pin()?)
            .is_err()
    );
    Ok(())
}
