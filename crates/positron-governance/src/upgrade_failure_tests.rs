//! Failure retains the authoritative prepublication/rollback distinction.
use super::*;

#[test]
fn upgrade_failure_retains_the_verified_recovery_receipt_after_publication()
-> Result<(), Box<dyn Error>> {
    exercise_failure(true)
}
#[test]
fn failed_upgrade_publication_stays_blocked_after_operation_lookup_expires()
-> Result<(), Box<dyn Error>> {
    exercise_failure(false)
}
fn exercise_failure(rollback_source: bool) -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let catalog = Catalog::open(
        &fixture.authority,
        fixture.instance,
        fixture.keys.catalog_secret(fixture.instance)?,
    )?;
    let actor = fixture.actor;
    let parameters = fixture.parameters;
    let request = DurableOperationRequest::upgrade(
        actor.principal_id(),
        AdministrativeIdempotencyKey::new([61; 16])?,
        fixture.instance.to_bytes(),
        catalog.pin()?.number(),
        18,
        parameters.intent_digest(),
    )?;
    let pending = DurableOperationAdministration::accept_upgrade(
        &catalog,
        actor,
        request,
        parameters,
        fixture.registration_row,
    )?;
    let id = pending.operation_id();
    DurableOperationAdministration::begin(&catalog, actor, id, 19)?;
    let failed = DurableOperationAdministration::fail_upgrade(&catalog, actor, id, 20)?;
    assert_eq!(
        failed.irreversible_boundary(),
        DurableOperationBoundary::NotCrossed
    );
    assert!(!failed.upgrade_rollback_available());
    assert!(failed.upgrade_snapshot_evidence().is_none());
    let request = DurableOperationRequest::upgrade(
        actor.principal_id(),
        AdministrativeIdempotencyKey::new([62; 16])?,
        fixture.instance.to_bytes(),
        catalog.pin()?.number(),
        21,
        parameters.intent_digest(),
    )?;
    let pending = DurableOperationAdministration::accept_upgrade(
        &catalog,
        actor,
        request,
        parameters,
        fixture.registration_row,
    )?;
    let id = pending.operation_id();
    DurableOperationAdministration::begin(&catalog, actor, id, 22)?;
    DurableOperationAdministration::advance_upgrade(
        &catalog,
        actor,
        id,
        UpgradeStage::Draining,
        23,
    )?;
    let basis = catalog.pin()?;
    let drain = UpgradeDrainEvidence::new(
        basis.identity().to_bytes(),
        basis.number(),
        fixture.marker_id,
        [63; 16],
    )?;
    DurableOperationAdministration::record_upgrade_drain(&catalog, actor, id, drain, 24)?;
    let backup = parameters.backup();
    let (backup_id, verification_id, receipt) = verified_snapshot(
        &catalog,
        actor,
        fixture.instance,
        backup,
        backup.repository(),
        fixture.registration_id,
        id,
    )?;
    DurableOperationAdministration::record_upgrade_snapshot(
        &catalog,
        actor,
        id,
        backup_id,
        verification_id,
        34,
    )?;
    DurableOperationAdministration::advance_upgrade(
        &catalog,
        actor,
        id,
        UpgradeStage::Publishing,
        35,
    )?;
    let restart = DurableOperationAdministration::advance_upgrade(
        &catalog,
        actor,
        id,
        UpgradeStage::AwaitingRestart,
        36,
    )?;
    assert!(restart.upgrade_rollback_available());
    let failed = DurableOperationAdministration::fail_upgrade(&catalog, actor, id, 37)?;
    assert_eq!(failed.status(), DurableOperationStatus::Failed);
    assert!(failed.upgrade_rollback_available());
    assert!(
        DurableOperationAdministration::current_upgrade_publication(&catalog)?
            .ok_or("publication")?
            .failed()
    );
    assert_eq!(
        failed
            .upgrade_snapshot_evidence()
            .ok_or("snapshot")?
            .receipt(),
        receipt
    );
    assert_eq!(
        failed.irreversible_boundary(),
        DurableOperationBoundary::CatalogGenerationPublished
    );
    drop(catalog);
    let catalog = Catalog::open(
        &fixture.authority,
        fixture.instance,
        fixture.keys.catalog_secret(fixture.instance)?,
    )?;
    assert_eq!(
        DurableOperationAdministration::inspect(&catalog, id)?,
        Some(failed)
    );
    assert_eq!(
        DurableOperationAdministration::fail_upgrade(&catalog, actor, id, 38)?,
        failed
    );
    if !rollback_source {
        let expiration = DurableOperationRequest::catalog_format_migration(
            actor.principal_id(),
            AdministrativeIdempotencyKey::new([66; 16])?,
            fixture.instance.to_bytes(),
            catalog.pin()?.number(),
            2_592_040,
        )?;
        DurableOperationAdministration::accept_catalog_format_migration(
            &catalog, actor, expiration,
        )?;
        assert!(DurableOperationAdministration::inspect(&catalog, id)?.is_none());
        let publication = DurableOperationAdministration::current_upgrade_publication(&catalog)?
            .ok_or("publication")?;
        assert!(publication.failed());
        assert!(publication.verification_report().is_none());
        assert!(!publication.is_rollback());
        return Ok(());
    }
    let key = AdministrativeIdempotencyKey::new([64; 16])?;
    let rollback = DurableOperationAdministration::rollback_upgrade(
        &catalog,
        actor,
        id,
        key,
        failed.revision(),
        39,
    )?;
    assert_eq!(rollback.status(), DurableOperationStatus::Failed);
    assert!(!rollback.upgrade_rollback_available());
    let publication = DurableOperationAdministration::current_upgrade_publication(&catalog)?
        .ok_or("publication")?;
    assert!(publication.is_rollback());
    assert_eq!(publication.release(), parameters.source());
    assert_eq!(publication.snapshot().receipt(), receipt);
    assert_eq!(
        DurableOperationAdministration::rollback_upgrade(
            &catalog,
            actor,
            id,
            key,
            failed.revision(),
            40
        )?,
        rollback
    );
    assert_eq!(
        DurableOperationAdministration::rollback_upgrade(
            &catalog,
            actor,
            id,
            AdministrativeIdempotencyKey::new([65; 16])?,
            rollback.revision(),
            40
        ),
        Err(DurableOperationFailure::IdempotencyConflict)
    );
    assert!(DurableOperationAdministration::next_upgrade_operation(&catalog, None)?.is_none());
    Ok(())
}
