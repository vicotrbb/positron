//! Replacement fixture workers enter through normal service recovery.
use super::*;

#[test]
fn root_phase_recovers_a_scrub_left_running_by_the_previous_fixture_worker()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let fixture = Fixture::new()?;
    let configuration = fixture.migration_configuration()?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let mut services = ServiceHandle::new(Arc::clone(&initialized))?;
    let scope = SegmentScope::new(initialized.tenant, SignalKind::Logs, initialized.logs_shard);
    let scrub = MaintenanceTaskId::new([0xda; 16]).map_err(|_| "scrub identity")?;
    {
        let catalog = open_catalog(&initialized)?;
        ActiveSegmentLedger::open(
            &initialized._authority,
            &catalog,
            scope,
            initialized.tenant_segment_key_for_test(scope)?,
        )?
        .seal()?;
        let basis = catalog.pin()?;
        let task = MaintenanceTask::integrity_scrub(
            scrub,
            MaintenanceScope::segment(scope.tenant_id(), scope.signal_kind(), scope.shard_id()),
            MaintenanceTrigger::Event,
            MaintenancePreconditions::new(basis.number(), 1).map_err(|_| "scrub basis")?,
            basis.integrity_scope_source_identity(scope)?,
            0,
        )
        .map_err(|_| "scrub task")?;
        initialized
            .maintenance_coordinator()
            .submit_and_persist(&catalog, task, 0)
            .map_err(|failure| format!("submit scrub: {failure:?}"))?;
    }
    let cancellation = crate::TaskCancellation::new();
    cancellation.cancel_after_polls(6);
    services.run_maintenance_worker(&cancellation)?;
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .status(scrub)
            .map_err(|failure| format!("scrub status: {failure:?}"))?
            .phase(),
        MaintenanceTaskPhase::Running,
        "drain retains the durable owner until service recovery"
    );
    let generation = services
        .manage_provider_migration(&administrator, br#"{"action":"status"}"#)
        .map_err(|failure| format!("root status: {failure:?}"))?
        .catalog_generation;
    let accepted = services
        .manage_provider_migration(
            &administrator,
            &positron_api::provider_migration::ProviderMigrationRequest {
                action: "prepare".into(),
                expected_catalog_generation: Some(generation),
                idempotency_key: Some("dadadada-dada-4ada-8ada-dadadadadada".into()),
                configuration_reference: Some(configuration.to_string_lossy().into_owned()),
                operation_id: None,
            }
            .encode()?,
        )
        .map_err(|failure| format!("prepare: {failure:?}"))?;
    let operation = accepted.operation.ok_or("accepted root operation")?;
    assert_eq!(operation.status, "pending");
    assert_eq!(operation.irreversible_boundary, "not_crossed");
    let migration = MaintenanceTaskId::new(
        crate::services::maintenance_verification::decode_fixed_hex(&operation.id)
            .ok_or("migration identity")?,
    )
    .map_err(|failure| format!("migration identity: {failure:?}"))?;
    let waiting = initialized
        .maintenance_coordinator()
        .status(migration)
        .map_err(|failure| format!("migration status: {failure:?}"))?;
    assert_eq!(waiting.phase(), MaintenanceTaskPhase::Queued);
    assert_eq!(waiting.conflict_owner(), Some(scrub));
    let completed = finish_root(&mut services, &administrator, &operation.id)?;
    assert_eq!(
        completed
            .operation
            .as_ref()
            .map(|operation| operation.status.as_str()),
        Some("succeeded")
    );
    let drained_scrub = initialized
        .maintenance_coordinator()
        .status(scrub)
        .map_err(|failure| format!("drained scrub status: {failure:?}"))?;
    // The joined replacement worker may have admitted this scrub again after
    // completing the root operation. Inspect its state after service recovery.
    services = ServiceHandle::new(Arc::clone(&initialized))?;
    let recovered_scrub = services
        .instance
        .maintenance_coordinator()
        .status(scrub)
        .map_err(|failure| format!("recovered scrub status: {failure:?}"))?;
    assert!(
        matches!(
            recovered_scrub.phase(),
            MaintenanceTaskPhase::Queued | MaintenanceTaskPhase::Succeeded
        ),
        "original scrub did not recover: before={drained_scrub:?}; after={recovered_scrub:?}"
    );
    Ok(())
}
