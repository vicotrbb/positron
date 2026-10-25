//! A foreign registration cannot inherit a genuine upgrade snapshot's lineage.
use super::*;
use crate::{InitializedInstance, InstanceBootstrap, OfflineUpgradeSession, UpgradeFailure};
use positron_governance::{
    BackupVerificationParameters, DurableOperationAdministration as Administration,
    DurableOperationRequest, DurableOperationStatus,
};

#[test]
fn offline_upgrade_rejects_verification_with_only_a_different_registration()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let drained = super::upgrade_end_to_end::drain_source(false)?;
    let paths = drained.fixture.paths()?;
    let configuration = &drained.configuration;
    let id = drained.id;
    drop(begin(&drained)?);
    let snapshot = complete_snapshot(&drained)?;
    let valid = OfflineUpgradeSession::inspect_progress(&paths, configuration, id)?;
    assert_eq!(
        valid.snapshot.ok_or("snapshot progress")?.status,
        DurableOperationStatus::Succeeded
    );
    assert!(valid.verification.is_none());
    let (foreign, unchanged) = preclaim_verification(&drained, snapshot)?;
    assert_eq!(
        OfflineUpgradeSession::inspect_progress(&paths, configuration, id),
        Err(UpgradeFailure::InvalidRequest)
    );
    verify_retained(&drained, snapshot, foreign, Some(unchanged))?;
    let mut session = begin(&drained)?;
    let parent = session.status()?;
    assert_eq!(
        session.advance(std::time::Instant::now() + Duration::from_secs(5)),
        Err(UpgradeFailure::InvalidRequest)
    );
    assert_eq!(session.status()?, parent);
    drop(session);
    verify_retained(&drained, snapshot, foreign, None)?;
    Ok(())
}

#[inline(never)]
fn complete_snapshot(
    drained: &super::upgrade_end_to_end::DrainedFixture,
) -> Result<positron_governance::DurableOperation, Box<dyn std::error::Error>> {
    let paths = drained.fixture.paths()?;
    let configuration = &drained.configuration;
    let id = drained.id;
    let instance = Arc::new(recovered(&paths, configuration, id)?);
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    let catalog = open_catalog(&instance)?;
    let parent = Administration::inspect(&catalog, id)?.ok_or("parent")?;
    let parameters = parent.upgrade_parameters().ok_or("parameters")?;
    let actor = Administration::resume_upgrade_actor(
        &catalog,
        id,
        instance.retention_time.security_time_seconds()?,
    )?;
    let generation = catalog.pin()?.number();
    drop(catalog);
    let snapshot = services.accept_upgrade_snapshot(
        actor,
        parameters.backup(),
        Administration::upgrade_snapshot_key(id)?,
        generation,
    )?;
    let snapshot = services.drive_upgrade_backup_operation(
        snapshot.operation_id(),
        std::time::Instant::now() + Duration::from_secs(60),
    )?;
    assert_eq!(snapshot.status(), DurableOperationStatus::Succeeded);
    Ok(snapshot)
}

#[inline(never)]
fn preclaim_verification(
    drained: &super::upgrade_end_to_end::DrainedFixture,
    snapshot: positron_governance::DurableOperation,
) -> Result<
    (
        positron_governance::DurableOperation,
        positron_kernel::CatalogGenerationId,
    ),
    Box<dyn std::error::Error>,
> {
    let instance = Arc::new(recovered(
        &drained.fixture.paths()?,
        &drained.configuration,
        drained.id,
    )?);
    let catalog = open_catalog(&instance)?;
    let parent = Administration::inspect(&catalog, drained.id)?.ok_or("parent")?;
    let parameters = parent.upgrade_parameters().ok_or("parameters")?;
    let actor = Administration::resume_upgrade_actor(
        &catalog,
        drained.id,
        instance.retention_time.security_time_seconds()?,
    )?;
    drop(catalog);
    let receipt = snapshot
        .backup_receipt()
        .ok_or("genuine completed snapshot receipt")?;
    let wrong_registration = [0x91; 32];
    assert_ne!(
        wrong_registration,
        parameters.backup().registration_identity()
    );
    let verification = BackupVerificationParameters::new(
        parameters.backup().repository(),
        wrong_registration,
        snapshot.operation_id().to_bytes(),
        receipt.manifest(),
    )?;
    let catalog = open_catalog(&instance)?;
    let basis = catalog.pin()?;
    let (registration, _) = positron_backup::BackupRepositoryRegistration::find(
        &basis,
        instance.instance.to_bytes(),
        parameters.backup().repository().repository_id(),
    )?
    .ok_or("current registration")?;
    let request = DurableOperationRequest::backup_verification(
        actor.principal_id(),
        Administration::upgrade_snapshot_verification_key(drained.id)?,
        instance.instance.to_bytes(),
        basis.number(),
        instance.retention_time.governance_now_seconds()?,
        verification.intent_digest(),
    )?;
    let foreign = Administration::accept_backup_verification_registered(
        &catalog,
        actor,
        request,
        verification,
        registration,
    )?;
    let unchanged = catalog.pin()?.identity();
    Ok((foreign, unchanged))
}

#[inline(never)]
fn begin(
    drained: &super::upgrade_end_to_end::DrainedFixture,
) -> Result<OfflineUpgradeSession, Box<dyn std::error::Error>> {
    Ok(OfflineUpgradeSession::begin_recovered(
        recovered(
            &drained.fixture.paths()?,
            &drained.configuration,
            drained.id,
        )?,
        &drained.configuration,
        drained.id,
    )?)
}

#[inline(never)]
fn verify_retained(
    drained: &super::upgrade_end_to_end::DrainedFixture,
    snapshot: positron_governance::DurableOperation,
    foreign: positron_governance::DurableOperation,
    generation: Option<positron_kernel::CatalogGenerationId>,
) -> Result<(), Box<dyn std::error::Error>> {
    let instance = recovered(
        &drained.fixture.paths()?,
        &drained.configuration,
        drained.id,
    )?;
    let catalog = open_catalog(&instance)?;
    if let Some(generation) = generation {
        assert_eq!(catalog.pin()?.identity(), generation);
    }
    assert_eq!(
        Administration::inspect(&catalog, snapshot.operation_id())?,
        Some(snapshot)
    );
    assert_eq!(
        Administration::inspect(&catalog, foreign.operation_id())?,
        Some(foreign)
    );
    Ok(())
}

#[inline(never)]
fn recovered(
    paths: &crate::BootstrapPaths,
    configuration: &positron_config::EffectiveConfiguration,
    id: positron_governance::OperationId,
) -> Result<InitializedInstance, Box<dyn std::error::Error>> {
    let mut instance = InstanceBootstrap::reopen_configured(paths, configuration)?;
    let (clock, elapsed) = RetentionTimeAuthority::establish_with_manual_elapsed(
        instance.retention_time.status().safe_anchor(),
    );
    let catalog = open_catalog(&instance)?;
    clock.recover_catalog_anchor(&catalog.pin()?)?;
    let parent = Administration::inspect(&catalog, id)?.ok_or("parent")?;
    let gap = parent
        .updated_at_unix_seconds()
        .saturating_sub(clock.governance_now_seconds()?);
    elapsed.advance(
        gap.checked_add(1)
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .ok_or("trusted elapsed range")?,
    )?;
    drop(catalog);
    instance.install_retention_time_for_test(clock)?;
    Ok(instance)
}
