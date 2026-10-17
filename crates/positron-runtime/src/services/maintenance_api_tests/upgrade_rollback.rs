//! Explicit same-format source selection attests real bytes before restart.
use super::*;
use positron_governance::{
    AdministrativeIdempotencyKey, DurableOperationAdministration as Administration,
    DurableOperationStatus, UpgradePublicationOutcome, UpgradeStage,
};

#[test]
fn failed_target_rolls_back_to_the_measured_installed_source_and_preserves_query()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let drained = super::upgrade_end_to_end::drain_installed_source()?;
    select_source(&drained)?;
    restart_source(&drained)
}

#[inline(never)]
fn select_source(
    drained: &super::upgrade_end_to_end::DrainedFixture,
) -> Result<(), Box<dyn std::error::Error>> {
    assert!(
        drained.configuration.installed_release().is_some(),
        "installed source fixture"
    );
    let mut session = super::upgrade_end_to_end::snapshot_offline(drained)?;
    let snapshot = session.rollback_snapshot()?.ok_or("verified snapshot")?;
    assert_eq!(
        session.publish(&drained.target)?.upgrade_stage(),
        Some(UpgradeStage::AwaitingRestart)
    );
    let failed = session
        .fail()
        .map_err(|error| format!("fail published target {error:?}"))?;
    assert_eq!(failed.status(), DurableOperationStatus::Failed);
    assert!(failed.upgrade_rollback_available());
    let key = AdministrativeIdempotencyKey::new([0xf3; 16])?;
    assert_eq!(
        session.rollback(
            &drained.target,
            &std::env::current_exe()?,
            key,
            failed.revision(),
        ),
        Err(crate::UpgradeFailure::ArtifactMismatch)
    );
    assert_eq!(session.status()?, failed);
    // The installed current manifest remains the original source. No synthetic
    // version or executable override participates in source qualification.
    let selected = session
        .rollback_installed(&drained.configuration, key, failed.revision())
        .map_err(|error| format!("select installed source {error:?}"))?;
    assert_eq!(selected.status(), DurableOperationStatus::Failed);
    assert_eq!(selected.upgrade_rollback_key(), Some(key));
    assert_eq!(
        session.rollback_installed(&drained.configuration, key, failed.revision())?,
        selected,
        "the exact keyed source selection replays"
    );
    assert_eq!(session.rollback_snapshot()?, Some(snapshot));
    Ok(())
}

#[inline(never)]
fn restart_source(
    drained: &super::upgrade_end_to_end::DrainedFixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let listeners = crate::process_lifecycle::ObservingListeners::default();
    let tasks = crate::process_lifecycle::ObservingTasks::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(drained.fixture.paths()?, InitializationMode::ExistingOnly)
            .with_effective_configuration(Arc::clone(&drained.configuration)),
        HostInputs::new(&listeners, &tasks),
    )?;
    assert_eq!(process.health().phase(), crate::ProcessPhase::Serving);
    let services = process.services().ok_or("source services")?;
    assert_eq!(
        services.query_log_bodies(
            &drained.query,
            "logs | range query_time 0 100 | limit 16",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?,
        )?,
        ["upgrade-lifecycle-preserved"]
    );
    let catalog = open_catalog(&services.instance)?;
    let publication = Administration::current_upgrade_publication(&catalog)?
        .ok_or("audited source publication")?;
    assert_eq!(publication.operation_id(), drained.id);
    assert_eq!(
        publication.outcome(),
        UpgradePublicationOutcome::SourceRollback
    );
    assert_eq!(publication.release(), publication.parameters().source());
    assert_eq!(
        Administration::inspect(&catalog, drained.id)?
            .ok_or("failed target history")?
            .status(),
        DurableOperationStatus::Failed
    );
    drop(catalog);
    drop(services);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful
    );
    Ok(())
}
