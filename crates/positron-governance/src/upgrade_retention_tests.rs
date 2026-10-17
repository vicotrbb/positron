//! Active Upgrade owns its unfinished snapshot prerequisites across lookup expiry.
use super::*;

#[test]
fn active_upgrade_retains_completed_children_until_snapshot_evidence_is_attached()
-> Result<(), Box<dyn Error>> {
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
        AdministrativeIdempotencyKey::new([101; 16])?,
        fixture.instance.to_bytes(),
        catalog.pin()?.number(),
        22,
        parameters.intent_digest(),
    )?;
    let parent = DurableOperationAdministration::accept_upgrade(
        &catalog,
        actor,
        request,
        parameters,
        fixture.registration_row,
    )?;
    let id = parent.operation_id();
    DurableOperationAdministration::begin(&catalog, actor, id, 23)?;
    DurableOperationAdministration::advance_upgrade(
        &catalog,
        actor,
        id,
        UpgradeStage::Draining,
        24,
    )?;
    let basis = catalog.pin()?;
    let drain = UpgradeDrainEvidence::new(
        basis.identity().to_bytes(),
        basis.number(),
        fixture.marker_id,
        [98; 16],
    )?;
    DurableOperationAdministration::record_upgrade_drain(&catalog, actor, id, drain, 25)?;
    let (backup, verification, receipt) = verified_snapshot(
        &catalog,
        actor,
        fixture.instance,
        parameters.backup(),
        parameters.backup().repository(),
        fixture.registration_id,
        id,
    )?;
    let expiry = DurableOperationAdministration::inspect(&catalog, verification)?
        .ok_or("verification")?
        .earliest_lookup_expiry_unix_seconds()
        .ok_or("expiry")?;
    retain(&catalog, actor, fixture.instance, expiry + 1, 102)?;
    assert!(
        DurableOperationAdministration::inspect(&catalog, backup)?.is_some(),
        "active Upgrade lost its completed snapshot before attaching its receipt"
    );
    assert!(
        DurableOperationAdministration::inspect(&catalog, verification)?.is_some(),
        "active Upgrade lost its completed independent verification"
    );
    drop(catalog);
    let catalog = Catalog::open(
        &fixture.authority,
        fixture.instance,
        fixture.keys.catalog_secret(fixture.instance)?,
    )?;
    let recorded = DurableOperationAdministration::record_upgrade_snapshot(
        &catalog,
        actor,
        id,
        backup,
        verification,
        expiry + 2,
    )?;
    assert_eq!(
        recorded
            .upgrade_snapshot_evidence()
            .ok_or("snapshot")?
            .receipt(),
        receipt
    );
    retain(&catalog, actor, fixture.instance, expiry + 3, 103)?;
    assert!(DurableOperationAdministration::inspect(&catalog, backup)?.is_none());
    assert!(DurableOperationAdministration::inspect(&catalog, verification)?.is_none());
    assert_eq!(
        DurableOperationAdministration::inspect(&catalog, id)?
            .ok_or("parent")?
            .upgrade_snapshot_evidence(),
        recorded.upgrade_snapshot_evidence()
    );
    Ok(())
}
fn retain(
    catalog: &Catalog<'_>,
    actor: AuthorizedContext,
    instance: positron_kernel::InstanceId,
    now: u64,
    key: u8,
) -> Result<(), Box<dyn Error>> {
    let parameters = RepositoryOperationParameters::local(
        RepositoryAction::Verify,
        "/backup",
        [72; 16],
        [73; 32],
        [74; 32],
    )?;
    let request = DurableOperationRequest::repository(
        actor.principal_id(),
        AdministrativeIdempotencyKey::new([key; 16])?,
        instance.to_bytes(),
        catalog.pin()?.number(),
        now,
        parameters.intent_digest(),
    )?;
    DurableOperationAdministration::accept_repository(catalog, actor, request, parameters)?;
    Ok(())
}
