use super::*;

#[test]
fn upgrade_requires_verified_snapshot_and_recovers_publication_before_restart()
-> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let Fixture {
        authority,
        keys,
        instance,
        actor,
        parameters,
        registration_id,
        ..
    } = &fixture;
    let catalog = Catalog::open(authority, *instance, keys.catalog_secret(*instance)?)?;
    let (instance, actor, parameters, registration_id) =
        (*instance, *actor, *parameters, *registration_id);
    let backup = parameters.backup();
    let repository = backup.repository();
    let request = DurableOperationRequest::upgrade(
        actor.principal_id(),
        AdministrativeIdempotencyKey::new([13; 16])?,
        instance.to_bytes(),
        catalog.pin()?.number(),
        22,
        parameters.intent_digest(),
    )?;
    let accepted = DurableOperationAdministration::accept_upgrade(
        &catalog,
        actor,
        request,
        parameters,
        fixture.registration_row,
    )?;
    let id = accepted.operation_id();
    DurableOperationAdministration::begin(&catalog, actor, id, 23)?;
    let before = catalog.pin()?.number();
    assert_eq!(
        DurableOperationAdministration::mark_draining(&catalog, actor, id, 24),
        Err(DurableOperationFailure::InvalidState)
    );
    assert_eq!(catalog.pin()?.number(), before);
    DurableOperationAdministration::advance_upgrade(
        &catalog,
        actor,
        id,
        UpgradeStage::Draining,
        24,
    )?;
    let basis = catalog.pin()?;
    let missing = UpgradeDrainEvidence::new(
        basis.identity().to_bytes(),
        basis.number(),
        [99; 32],
        [98; 16],
    )?;
    assert_eq!(
        DurableOperationAdministration::record_upgrade_drain(&catalog, actor, id, missing, 25),
        Err(DurableOperationFailure::InvalidState)
    );
    let drain = UpgradeDrainEvidence::new(
        basis.identity().to_bytes(),
        basis.number(),
        fixture.marker_id,
        [98; 16],
    )?;
    let captured =
        DurableOperationAdministration::record_upgrade_drain(&catalog, actor, id, drain, 25)?;
    assert_eq!(captured.upgrade_stage(), Some(UpgradeStage::Snapshot));
    assert_eq!(
        DurableOperationAdministration::record_upgrade_drain(&catalog, actor, id, drain, 26)?,
        captured
    );
    assert_eq!(
        DurableOperationAdministration::advance_upgrade(
            &catalog,
            actor,
            id,
            UpgradeStage::Publishing,
            26
        ),
        Err(DurableOperationFailure::InvalidState)
    );
    assert_eq!(
        DurableOperationAdministration::record_upgrade_snapshot(&catalog, actor, id, id, id, 26),
        Err(DurableOperationFailure::InvalidState)
    );
    let (backup_id, verification_id, receipt) = verified_snapshot(
        &catalog,
        actor,
        instance,
        backup,
        repository,
        registration_id,
        id,
    )?;
    let evidence = DurableOperationAdministration::record_upgrade_snapshot(
        &catalog,
        actor,
        id,
        backup_id,
        verification_id,
        34,
    )?;
    assert_eq!(
        evidence
            .upgrade_snapshot_evidence()
            .ok_or("snapshot")?
            .receipt(),
        receipt
    );
    let publishing = DurableOperationAdministration::advance_upgrade(
        &catalog,
        actor,
        id,
        UpgradeStage::Publishing,
        35,
    )?;
    let basis = catalog.pin()?;
    let audits = catalog.governance_audit_records()?.len();
    let fault = positron_kernel::with_catalog_publication_fault_after(
        positron_kernel::CatalogPublicationFault::SynchronizeCommit,
        0,
        || {
            DurableOperationAdministration::advance_upgrade(
                &catalog,
                actor,
                id,
                UpgradeStage::AwaitingRestart,
                36,
            )
        },
    );
    assert_eq!(fault, Err(DurableOperationFailure::PersistenceUnavailable));
    assert!(DurableOperationAdministration::current_upgrade_publication(&catalog)?.is_none());
    assert_eq!(catalog.pin()?.number(), basis.number());
    assert_eq!(catalog.governance_audit_records()?.len(), audits);
    assert_eq!(
        DurableOperationAdministration::inspect(&catalog, id)?,
        Some(publishing)
    );
    drop(catalog);
    let catalog = Catalog::open(authority, instance, keys.catalog_secret(instance)?)?;
    let restart = DurableOperationAdministration::advance_upgrade(
        &catalog,
        actor,
        id,
        UpgradeStage::AwaitingRestart,
        37,
    )?;
    assert_eq!(
        restart.irreversible_boundary(),
        DurableOperationBoundary::CatalogGenerationPublished
    );
    let publication = DurableOperationAdministration::current_upgrade_publication(&catalog)?
        .ok_or("publication")?;
    assert_eq!(publication.operation_id(), id);
    assert_eq!(publication.parameters(), parameters);
    assert_eq!(publication.snapshot().receipt(), receipt);
    assert_eq!(
        DurableOperationAdministration::cancel_upgrade(
            &catalog,
            actor,
            id,
            AdministrativeIdempotencyKey::new([16; 16])?,
            restart.revision(),
            38
        ),
        Err(DurableOperationFailure::CancellationUnavailable)
    );
    let proof = verification_report(
        &catalog,
        keys,
        id,
        positron_kernel::upgrade_verification::UpgradeQueryVerification::Executed {
            tenant: tenant(1)?.to_bytes(),
        },
    )?;
    assert_eq!(
        DurableOperationAdministration::succeed_upgrade(&catalog, actor, id, &proof, 38),
        Err(DurableOperationFailure::InvalidState)
    );
    DurableOperationAdministration::advance_upgrade(
        &catalog,
        actor,
        id,
        UpgradeStage::Verifying,
        38,
    )?;
    let proof = verification_report(
        &catalog,
        keys,
        id,
        positron_kernel::upgrade_verification::UpgradeQueryVerification::Executed {
            tenant: tenant(1)?.to_bytes(),
        },
    )?;
    snapshot_support::assert_report_binding(&catalog, keys, id, &proof)?;
    let before = catalog.pin()?.identity();
    let failed = positron_kernel::with_catalog_publication_fault_after(
        positron_kernel::CatalogPublicationFault::SynchronizeCommit,
        0,
        || DurableOperationAdministration::succeed_upgrade(&catalog, actor, id, &proof, 39),
    );
    assert_eq!(failed, Err(DurableOperationFailure::PersistenceUnavailable));
    assert_eq!(catalog.pin()?.identity(), before);
    drop(catalog);
    let catalog = Catalog::open(authority, instance, keys.catalog_secret(instance)?)?;
    let complete =
        DurableOperationAdministration::resume_upgrade_verification(&catalog, actor, id)?
            .ok_or("prepared verification")?;
    let publication = DurableOperationAdministration::current_upgrade_publication(&catalog)?
        .ok_or("publication")?;
    assert_eq!(
        publication.verification_report(),
        complete.upgrade_verification_report()
    );
    assert!(publication.verification_report().is_some());
    drop(catalog);
    let catalog = Catalog::open(authority, instance, keys.catalog_secret(instance)?)?;
    assert_eq!(
        DurableOperationAdministration::inspect(&catalog, id)?,
        Some(complete)
    );
    assert_eq!(complete.status(), DurableOperationStatus::Succeeded);
    assert_eq!(
        complete.upgrade_snapshot_evidence(),
        evidence.upgrade_snapshot_evidence()
    );
    let after_expiry = 40 + 2_592_000;
    let expiration_trigger = DurableOperationRequest::catalog_format_migration(
        actor.principal_id(),
        AdministrativeIdempotencyKey::new([95; 16])?,
        instance.to_bytes(),
        catalog.pin()?.number(),
        after_expiry,
    )?;
    DurableOperationAdministration::accept_catalog_format_migration(
        &catalog,
        actor,
        expiration_trigger,
    )?;
    assert!(DurableOperationAdministration::inspect(&catalog, id)?.is_none());
    assert_eq!(
        DurableOperationAdministration::current_upgrade_publication(&catalog)?,
        Some(publication)
    );
    snapshot_support::assert_report_reference_required(
        &catalog,
        publication.verification_report().ok_or("report")?,
    )?;
    Ok(())
}
