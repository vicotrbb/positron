use super::*;

#[test]
fn running_provider_migration_accepts_one_replayable_preparation()
-> Result<(), Box<dyn std::error::Error>> {
    run_lifecycle(false)
}

#[test]
fn retained_work_refuses_online_retirement_without_losing_committed_route()
-> Result<(), Box<dyn std::error::Error>> {
    run_lifecycle(true)
}

fn run_lifecycle(retained_work: bool) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let configuration = fixture.migration_configuration()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        positron_governance::PresentedCredential::parse(&administrator)?,
        positron_governance::RequestedIntent::SystemAdministration,
        positron_governance::CompatibilityHints::none(),
    )?;
    let requesting_principal = actor.principal_id();
    let services = ServiceHandle::new(initialized)?;
    let status = services
        .manage_provider_migration(&administrator, br#"{"action":"status"}"#)
        .expect("status");
    let source_provider = status.active_provider.clone();
    assert_eq!(status.source_provider, source_provider);
    assert!(status.target_provider.is_none());
    let preparation = positron_api::provider_migration::ProviderMigrationRequest {
        action: "prepare".into(),
        expected_catalog_generation: Some(status.catalog_generation),
        idempotency_key: Some("12121212-1212-4212-8212-121212121212".into()),
        configuration_reference: Some(configuration.to_str().ok_or("configuration path")?.into()),
        operation_id: None,
    }
    .encode()?;
    let first = services
        .manage_provider_migration(&administrator, &preparation)
        .expect("accepted preparation");
    let replay = services
        .manage_provider_migration(&administrator, &preparation)
        .expect("exact retry");
    assert_eq!(first.operation, replay.operation);
    assert_eq!(first.catalog_generation, replay.catalog_generation);
    assert_eq!(
        first
            .operation
            .as_ref()
            .map(|operation| operation.status.as_str()),
        Some("pending")
    );
    assert!(crate::services::maintenance::wake_runtime_maintenance(
        &services, None
    )?);
    let lookup = positron_api::provider_migration::ProviderMigrationRequest {
        action: "status".into(),
        expected_catalog_generation: None,
        idempotency_key: None,
        configuration_reference: None,
        operation_id: first
            .operation
            .as_ref()
            .map(|operation| operation.id.clone()),
    }
    .encode()?;
    let completed = services
        .manage_provider_migration(&administrator, &lookup)
        .expect("completed preparation");
    assert_eq!(completed.root_phase, "prepared");
    assert_eq!(completed.source_provider, source_provider);
    assert!(
        completed
            .target_provider
            .as_ref()
            .is_some_and(|target| target != &source_provider)
    );
    assert_eq!(
        completed
            .operation
            .as_ref()
            .map(|operation| operation.status.as_str()),
        Some("succeeded")
    );
    let mut generation = completed.catalog_generation;
    for (index, action) in ["cancel", "resume", "activate"].into_iter().enumerate() {
        generation = services
            .manage_provider_migration(&administrator, br#"{"action":"status"}"#)
            .expect("current generation")
            .catalog_generation
            .max(generation);
        let request = positron_api::provider_migration::ProviderMigrationRequest {
            action: action.into(),
            expected_catalog_generation: Some(generation),
            idempotency_key: Some(format!("13131313-1313-4313-8313-{:012}", index + 1)),
            configuration_reference: (action == "activate")
                .then(|| configuration.to_string_lossy().into_owned()),
            operation_id: None,
        }
        .encode()?;
        let accepted = services
            .manage_provider_migration(&administrator, &request)
            .expect("accepted phase");
        let lookup = positron_api::provider_migration::ProviderMigrationRequest {
            action: "status".into(),
            expected_catalog_generation: None,
            idempotency_key: None,
            configuration_reference: None,
            operation_id: accepted.operation.map(|operation| operation.id),
        }
        .encode()?;
        let mut result = services
            .manage_provider_migration(&administrator, &lookup)
            .expect("accepted phase lookup");
        for _ in 0..32 {
            if result
                .operation
                .as_ref()
                .is_some_and(|operation| operation.status == "succeeded")
            {
                break;
            }
            crate::services::maintenance::wake_runtime_maintenance(&services, None)?;
            result = services
                .manage_provider_migration(&administrator, &lookup)
                .expect("phase lookup");
        }
        assert_eq!(
            result
                .operation
                .as_ref()
                .map(|operation| operation.status.as_str()),
            Some("succeeded")
        );
        assert_eq!(
            result.root_phase,
            match action {
                "cancel" => "cancelled",
                "resume" => "prepared",
                _ => "verifying",
            }
        );
        generation = result.catalog_generation;
    }
    let status = services
        .manage_provider_migration(&administrator, br#"{"action":"status"}"#)
        .expect("cutover status");
    assert_eq!(status.active_epoch, 2);
    assert_eq!(status.predecessor_epoch, Some(1));
    if retained_work {
        services.ingest_otlp_logs(&ingest, request("retained-cutover-route").encode_to_vec())?;
        let catalog = services
            .open_maintenance_catalog()
            .expect("retained task catalog");
        let task = positron_kernel::MaintenanceTask::with_contract(
            positron_kernel::MaintenanceTaskId::new([0xd4; 16]).expect("task ID"),
            positron_kernel::MaintenanceTaskClass::Migration,
            positron_kernel::MaintenanceScope::system(),
            positron_kernel::MaintenanceTrigger::Event,
            positron_kernel::MaintenancePreconditions::new(catalog.pin()?.number(), 1)
                .expect("preconditions"),
            Vec::new(),
            Vec::new(),
            positron_kernel::ResourceAmounts::new([1; 11]),
        )
        .expect("opaque migration task");
        services
            .instance
            .maintenance_coordinator()
            .submit_and_persist(&catalog, task, 1)
            .expect("retained task");
    }
    let unlock = age::x25519::Identity::generate();
    let recipients = positron_kernel::RecoveryRecipients::parse(&[unlock.to_public().to_string()])?;
    let bundle = fixture
        .recovery_export_directory()?
        .join("online-cutover.age");
    services
        .instance
        .create_recovery_bundle(&bundle, &recipients)?;
    services
        .instance
        .verify_recovery_bundle(&bundle, positron_kernel::RecoveryUnlock::Identity(&unlock))?;
    for (index, action) in ["verify", "retire"].into_iter().enumerate() {
        let current = services
            .manage_provider_migration(&administrator, br#"{"action":"status"}"#)
            .expect("current status");
        let accepted = services
            .manage_provider_migration(
                &administrator,
                &ProviderMigrationRequest {
                    action: action.into(),
                    expected_catalog_generation: Some(current.catalog_generation),
                    idempotency_key: Some(format!("14141414-1414-4414-8414-{:012}", index + 1)),
                    configuration_reference: Some(configuration.to_string_lossy().into_owned()),
                    operation_id: None,
                }
                .encode()?,
            )
            .expect("accepted recovery phase");
        let lookup = ProviderMigrationRequest {
            action: "status".into(),
            expected_catalog_generation: None,
            idempotency_key: None,
            configuration_reference: None,
            operation_id: accepted.operation.map(|operation| operation.id),
        }
        .encode()?;
        let mut completed = services
            .manage_provider_migration(&administrator, &lookup)
            .expect("phase lookup");
        for _ in 0..32 {
            if completed.operation.as_ref().is_some_and(|operation| {
                matches!(operation.status.as_str(), "succeeded" | "failed")
            }) {
                break;
            }
            crate::services::maintenance::wake_runtime_maintenance(&services, None)
                .unwrap_or_else(|failure| panic!("{action} dispatch: {failure:?}"));
            completed = services
                .manage_provider_migration(&administrator, &lookup)
                .expect("phase lookup");
        }
        assert_eq!(
            completed
                .operation
                .as_ref()
                .map(|operation| operation.status.as_str()),
            Some(if retained_work { "failed" } else { "succeeded" })
        );
        if action == "retire" && !retained_work {
            assert_eq!(completed.predecessor_epoch, None);
            assert_eq!(completed.active_epoch, 2);
            assert_eq!(completed.source_provider, source_provider);
            assert_eq!(
                completed.target_provider.as_ref(),
                Some(&completed.active_provider)
            );
            assert_eq!(
                services
                    .manage_provider_migration(&administrator, &lookup)
                    .expect("phase lookup")
                    .operation,
                completed.operation
            );
        }
    }
    if retained_work {
        assert_eq!(
            services
                .instance
                .local_key_rotation_status()?
                .predecessor_epoch(),
            Some(1)
        );
        services.ingest_otlp_logs(&ingest, request("route-after-refusal").encode_to_vec())?;
    }
    let catalog = services.open_maintenance_catalog().expect("audit catalog");
    let mut migration_audits = 0;
    for record in catalog.governance_audit_records()? {
        let entry = positron_governance::GovernanceAuditEntry::decode(&record)?;
        if let Some(rotation) = entry.as_catalog_root_rotation()
            && rotation.operation_id().is_some()
        {
            assert_eq!(rotation.requesting_principal(), Some(requesting_principal));
            migration_audits += 1;
        }
    }
    assert!(migration_audits >= 6);
    Ok(())
}
