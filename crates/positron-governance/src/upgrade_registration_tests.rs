use super::*;

#[test]
fn upgrade_accepts_current_registration_row_with_a_distinct_stable_binding()
-> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let catalog = Catalog::open(
        &fixture.authority,
        fixture.instance,
        fixture.keys.catalog_secret(fixture.instance)?,
    )?;
    let old = fixture.parameters;
    let backup = BackupSnapshotParameters::new(
        old.backup().repository(),
        old.backup().retention_seconds(),
        [0x91; 32],
    )?;
    let parameters = UpgradeParameters::new(
        old.source(),
        old.target(),
        old.format_epoch(),
        old.configuration_digest(),
        backup,
    )?;
    let request = DurableOperationRequest::upgrade(
        fixture.actor.principal_id(),
        AdministrativeIdempotencyKey::new([0x92; 16])?,
        fixture.instance.to_bytes(),
        catalog.pin()?.number(),
        18,
        parameters.intent_digest(),
    )?;
    let missing = CatalogObject::new(b"absent registration row".to_vec())?.identity();
    let basis = catalog.pin()?.identity();
    assert_eq!(
        DurableOperationAdministration::accept_upgrade(
            &catalog,
            fixture.actor,
            request,
            parameters,
            missing
        ),
        Err(DurableOperationFailure::InvalidInput)
    );
    assert_eq!(catalog.pin()?.identity(), basis);
    let accepted = DurableOperationAdministration::accept_upgrade(
        &catalog,
        fixture.actor,
        request,
        parameters,
        fixture.registration_row,
    )?;
    assert_eq!(accepted.upgrade_parameters(), Some(parameters));
    // A moved registry anchor changes the row address, not accepted intent.
    let basis = catalog.pin()?;
    let objects = basis
        .object_identities()
        .filter(|id| *id != fixture.registration_row)
        .map(|id| {
            CatalogObject::new(basis.object(id)?.ok_or("object")?.to_vec()).map_err(Into::into)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0x93; 16])?,
            positron_kernel::FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    assert_eq!(
        DurableOperationAdministration::accept_upgrade(
            &catalog,
            fixture.actor,
            request,
            parameters,
            fixture.registration_row
        )?,
        accepted
    );
    assert_eq!(
        DurableOperationAdministration::replay_upgrade(&catalog, fixture.actor, request)?,
        accepted
    );
    let changed = DurableOperationRequest::upgrade(
        fixture.actor.principal_id(),
        request.idempotency_key(),
        fixture.instance.to_bytes(),
        request.accepted_generation(),
        18,
        [0x94; 32],
    )?;
    assert_eq!(
        DurableOperationAdministration::replay_upgrade(&catalog, fixture.actor, changed),
        Err(DurableOperationFailure::IdempotencyConflict)
    );
    Ok(())
}
