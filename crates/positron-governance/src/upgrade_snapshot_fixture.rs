//! Public Backup and verification seam used by Upgrade lifecycle tests.
use super::*;
pub(super) fn verified_snapshot(
    catalog: &Catalog<'_>,
    actor: AuthorizedContext,
    instance: positron_kernel::InstanceId,
    backup: BackupSnapshotParameters,
    repository: RepositoryOperationParameters,
    registration_id: [u8; 32],
    id: OperationId,
) -> Result<(OperationId, OperationId, BackupOperationReceipt), Box<dyn Error>> {
    let request = DurableOperationRequest::backup_snapshot(
        actor.principal_id(),
        DurableOperationAdministration::upgrade_snapshot_key(id)?,
        instance.to_bytes(),
        catalog.pin()?.number(),
        26,
        backup.intent_digest(),
    )?;
    let accepted = DurableOperationAdministration::accept_backup(
        catalog,
        actor,
        request,
        backup,
        registration_id,
        CatalogObject::new(b"upgrade repository".to_vec())?,
    )?;
    let backup_id = accepted.operation_id();
    DurableOperationAdministration::begin(catalog, actor, backup_id, 27)?;
    DurableOperationAdministration::advance_backup(
        catalog,
        actor,
        backup_id,
        BackupOperationStage::Publishing,
        28,
    )?;
    let source = catalog.pin()?;
    let receipt = BackupOperationReceipt::new(
        [20; 32],
        [21; 32],
        source.number(),
        source.identity().to_bytes(),
        8192,
        0,
        3600,
    )?;
    let previous = source
        .object_identities()
        .find(|id| id.to_bytes() == registration_id)
        .ok_or("registration")?;
    let successor = CatalogObject::new(b"anchored upgrade repository".to_vec())?;
    let registration = successor.identity();
    DurableOperationAdministration::succeed_backup_with_registration(
        catalog, actor, backup_id, receipt, previous, successor, 29,
    )?;
    let verify = BackupVerificationParameters::new(
        repository,
        registration.to_bytes(),
        [22; 16],
        receipt.manifest(),
    )?;
    let request = DurableOperationRequest::backup_verification(
        actor.principal_id(),
        DurableOperationAdministration::upgrade_snapshot_verification_key(id)?,
        instance.to_bytes(),
        catalog.pin()?.number(),
        30,
        verify.intent_digest(),
    )?;
    let accepted = DurableOperationAdministration::accept_backup_verification_registered(
        catalog,
        actor,
        request,
        verify,
        registration,
    )?;
    let verification_id = accepted.operation_id();
    assert_eq!(
        DurableOperationAdministration::record_upgrade_snapshot(
            catalog,
            actor,
            id,
            backup_id,
            verification_id,
            31
        ),
        Err(DurableOperationFailure::InvalidState)
    );
    DurableOperationAdministration::begin(catalog, actor, verification_id, 31)?;
    DurableOperationAdministration::advance_backup_verification(
        catalog,
        actor,
        verification_id,
        true,
        32,
    )?;
    DurableOperationAdministration::succeed_backup_verification(
        catalog,
        actor,
        verification_id,
        CatalogObject::new(b"verified snapshot report".to_vec())?,
        33,
    )?;
    Ok((backup_id, verification_id, receipt))
}

/// Tests the Governance signature boundary; Runtime separately produces this
/// report only after real startup integrity and native query execution.
pub(super) fn verification_report(
    catalog: &Catalog<'_>,
    keys: &BootstrapKeyCustody,
    id: OperationId,
    query: positron_kernel::upgrade_verification::UpgradeQueryVerification,
) -> Result<positron_kernel::upgrade_verification::UpgradeVerificationReport, Box<dyn Error>> {
    let basis = catalog.pin()?;
    let publication = DurableOperationAdministration::current_upgrade_publication(catalog)?
        .ok_or("publication")?;
    let (_, governance) = basis.governance_object()?;
    let input = positron_kernel::upgrade_verification::UpgradeVerificationInput::new(
        governance.instance(),
        id.to_bytes(),
        publication.object_identity()?,
        basis.identity().to_bytes(),
        basis.number(),
        query,
    )?;
    sign_report(catalog, keys, input)
}
pub(super) fn sign_report(
    catalog: &Catalog<'_>,
    keys: &BootstrapKeyCustody,
    input: positron_kernel::upgrade_verification::UpgradeVerificationInput,
) -> Result<positron_kernel::upgrade_verification::UpgradeVerificationReport, Box<dyn Error>> {
    let basis = catalog.pin()?;
    let (_, governance) = basis.governance_object()?;
    let signer = keys.upgrade_verification_signer(
        positron_kernel::InstanceId::new(governance.instance())?,
        governance.protected_integrity_key(),
    )?;
    Ok(positron_kernel::upgrade_verification::UpgradeVerificationReport::sign(input, &signer)?)
}

pub(super) fn assert_report_binding(
    catalog: &Catalog<'_>,
    keys: &BootstrapKeyCustody,
    id: OperationId,
    proof: &positron_kernel::upgrade_verification::UpgradeVerificationReport,
) -> Result<(), Box<dyn Error>> {
    let input = proof.input();
    let actor = DurableOperationAdministration::resume_upgrade_actor(catalog, id, 39)?;
    for (changed,expected) in [
        (positron_kernel::upgrade_verification::UpgradeVerificationInput::new(input.instance(),[96;16],input.publication(),input.catalog_identity(),input.catalog_generation(),input.query())?,DurableOperationFailure::InvalidInput),
        (positron_kernel::upgrade_verification::UpgradeVerificationInput::new(input.instance(),id.to_bytes(),[97;32],input.catalog_identity(),input.catalog_generation(),input.query())?,DurableOperationFailure::InvalidInput),
        (positron_kernel::upgrade_verification::UpgradeVerificationInput::new(input.instance(),id.to_bytes(),input.publication(),input.catalog_identity(),input.catalog_generation()+1,input.query())?,DurableOperationFailure::StaleGeneration),
        (positron_kernel::upgrade_verification::UpgradeVerificationInput::new(input.instance(),id.to_bytes(),input.publication(),input.catalog_identity(),input.catalog_generation(),positron_kernel::upgrade_verification::UpgradeQueryVerification::NotApplicableNoQueryableTenant)?,DurableOperationFailure::InvalidInput),
    ] {
        let rejected=sign_report(catalog,keys,changed)?;
        assert_eq!(DurableOperationAdministration::succeed_upgrade(catalog,actor,id,&rejected,39),Err(expected));
        assert_eq!(catalog.pin()?.identity().to_bytes(),input.catalog_identity());
    }
    let mut tampered = proof.bytes().to_vec();
    *tampered.last_mut().ok_or("signature")? ^= 1;
    let tampered =
        positron_kernel::upgrade_verification::UpgradeVerificationReport::from_bytes(&tampered)?;
    assert_eq!(
        DurableOperationAdministration::succeed_upgrade(catalog, actor, id, &tampered, 39),
        Err(DurableOperationFailure::InvalidInput)
    );
    assert_eq!(
        catalog.pin()?.identity().to_bytes(),
        input.catalog_identity()
    );
    Ok(())
}
pub(super) fn assert_report_reference_required(
    catalog: &Catalog<'_>,
    report: [u8; 32],
) -> Result<(), Box<dyn Error>> {
    let basis = catalog.pin()?;
    let mut objects = Vec::new();
    for id in basis.object_identities() {
        if id.to_bytes() != report {
            objects.push(CatalogObject::new(
                basis.object(id)?.ok_or("object")?.to_vec(),
            )?);
        }
    }
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([99; 16])?,
            basis.format_epoch().ok_or("epoch")?,
            objects,
        )?,
        None,
    )?;
    assert_eq!(
        DurableOperationAdministration::current_upgrade_publication(catalog),
        Err(DurableOperationFailure::PersistenceUnavailable)
    );
    Ok(())
}
