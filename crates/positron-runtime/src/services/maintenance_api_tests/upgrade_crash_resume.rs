//! A real configured source cannot hand off Drain before its trusted time catches up.
use super::*;
use positron_governance::{DurableOperationAdministration as Administration, UpgradeStage};
use std::time::Instant;

#[test]
fn configured_crash_before_drain_waits_for_trusted_time_then_finishes_real_drain()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let prepared = super::upgrade_end_to_end::crash_source_before_drain()?;
    verify_cold_recovery(&prepared)
}

#[inline(never)]
fn verify_cold_recovery(
    prepared: &super::upgrade_end_to_end::DrainedFixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let instance = crate::InstanceBootstrap::reopen_configured(
        &prepared.fixture.paths()?,
        &prepared.configuration,
    )?;
    let catalog = open_catalog(&instance)?;
    let before = catalog.pin()?.identity();
    let before_number = catalog.pin()?.number();
    let operation = Administration::inspect(&catalog, prepared.id)?.ok_or("crashed intent")?;
    assert_eq!(operation.upgrade_stage(), Some(UpgradeStage::Draining));
    assert!(
        instance.retention_time.governance_now_seconds()? < operation.updated_at_unix_seconds(),
        "controlled future metadata must actually be ahead of trusted time"
    );
    drop(catalog);
    assert!(instance.graceful_shutdown_record()?.is_none());
    drop(instance);
    let deadline = Instant::now() + Duration::from_secs(30);
    let process = cold_source(prepared)?;
    assert_eq!(process.health().phase(), crate::ProcessPhase::Fenced);
    assert!(process.services().is_none());
    assert!(
        process
            .bound_endpoints()
            .iter()
            .all(|endpoint| !endpoint.role().is_data())
    );
    assert!(
        matches!(
            process.resume_configured_upgrade_drain(&prepared.configuration),
            Err(crate::UpgradeFailure::CapacityUnavailable)
        ),
        "trusted time lag must not hand off a Drain token"
    );
    assert_eq!(
        process.crash_inspection().catalog_generation(),
        Some(before_number)
    );
    assert_eq!(process.pending_upgrade_operation()?, Some(operation));
    assert_eq!(process.health().phase(), crate::ProcessPhase::Fenced);
    match prepared.fixture.paths()?.retain_volume_for_test() {
        Err(error) => assert_eq!(
            error.code(),
            crate::BootstrapFailureCode::StorageUnavailable
        ),
        Ok(_) => return Err("refused handoff released the Process volume owner".into()),
    }
    drop(process);
    let inspected = crate::InstanceBootstrap::reopen_configured(
        &prepared.fixture.paths()?,
        &prepared.configuration,
    )?;
    let catalog = open_catalog(&inspected)?;
    assert_eq!(
        catalog.pin()?.identity(),
        before,
        "refused handoff cannot mutate Catalog"
    );
    assert_eq!(
        Administration::inspect(&catalog, prepared.id)?,
        Some(operation)
    );
    drop(catalog);
    assert!(inspected.graceful_shutdown_record()?.is_none());
    drop(inspected);
    let process = cold_source(prepared)?;
    let accepted = loop {
        match process.resume_configured_upgrade_drain(&prepared.configuration) {
            Ok(Some(token)) => break token,
            Err(crate::UpgradeFailure::CapacityUnavailable) if Instant::now() < deadline => {
                assert_eq!(process.pending_upgrade_operation()?, Some(operation));
                std::thread::sleep(Duration::from_millis(50));
            },
            other => return Err(format!("configured Drain recovery {other:?}").into()),
        }
    };
    assert_eq!(accepted.operation().operation_id(), prepared.id);
    let id = process
        .begin_upgrade(accepted)
        .map_err(|error| format!("begin real Drain {error:?}"))?
        .finish(ShutdownTrigger::FirstSignal)
        .map_err(|error| format!("finish real Drain {error:?}"))?;
    assert_eq!(id, prepared.id);
    let instance = crate::InstanceBootstrap::reopen_configured(
        &prepared.fixture.paths()?,
        &prepared.configuration,
    )?;
    let catalog = open_catalog(&instance)?;
    let final_catalog = catalog.pin()?.identity();
    let final_operation = Administration::inspect(&catalog, id)?.ok_or("final drained intent")?;
    assert_ne!(final_catalog, before);
    drop(catalog);
    let record = instance
        .graceful_shutdown_record()?
        .ok_or("real final Drain marker")?;
    drop(instance);
    let session = loop {
        match crate::OfflineUpgradeSession::begin(
            &prepared.fixture.paths()?,
            &prepared.configuration,
            id,
        ) {
            Ok(session) => break session,
            Err(crate::UpgradeFailure::SnapshotUnavailable) if Instant::now() < deadline => {
                let inspected = crate::InstanceBootstrap::reopen_configured(
                    &prepared.fixture.paths()?,
                    &prepared.configuration,
                )
                .map_err(|error| format!("offline retry inspection {error:?}"))?;
                let catalog = open_catalog(&inspected)?;
                assert_eq!(
                    catalog.pin()?.identity(),
                    final_catalog,
                    "offline admission wait must preserve final Catalog"
                );
                assert_eq!(
                    Administration::inspect(&catalog, id)?,
                    Some(final_operation)
                );
                drop(catalog);
                drop(inspected);
                std::thread::sleep(Duration::from_millis(50));
            },
            Err(error) => {
                return Err(format!("offline admission after real Drain {error:?}").into());
            },
        }
    };
    let operation = session.status()?;
    assert_eq!(operation.operation_id(), prepared.id);
    let evidence = operation
        .upgrade_drain_evidence()
        .ok_or("bound Drain evidence")?;
    assert_eq!(evidence.marker_identity(), record.marker_identity());
    assert_eq!(evidence.transaction(), record.transaction());
    Ok(())
}

#[inline(never)]
fn cold_source(
    prepared: &super::upgrade_end_to_end::DrainedFixture,
) -> Result<crate::RunningProcess, Box<dyn std::error::Error>> {
    let listeners = crate::process_lifecycle::ObservingListeners::default();
    let tasks = crate::process_lifecycle::ObservingTasks::default();
    Ok(ApplicationRuntime::start(
        ServeConfiguration::new(prepared.fixture.paths()?, InitializationMode::ExistingOnly)
            .with_effective_configuration(Arc::clone(&prepared.configuration)),
        HostInputs::new(&listeners, &tasks),
    )?)
}
