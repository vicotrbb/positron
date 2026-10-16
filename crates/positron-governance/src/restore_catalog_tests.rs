use super::*;
#[test]
fn restore_rehydrates_only_exact_authenticated_snapshot_tenant_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let root = PagedCatalogRoot::new()?;
    let instance = positron_kernel::InstanceId::new([0xe1; 16])?;
    let default_tenant = tenant(1)?;
    let authority = fixture_authority(
        PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?,
        default_tenant,
    )?;
    let keys = BootstrapKeyCustody::initialize(&root.secrets())?;
    let catalog = Catalog::open(&authority, instance, keys.catalog_secret(instance)?)?;
    let administrator = PrincipalId::from_bytes([0xe2; 16])?;
    let secret = [0xe3; 32];
    let salt = [0xe4; 32];
    let hash = keys.salted_secret_hash(&salt, &secret)?;
    let initial = crate::InitialGovernanceIntent::create_tenant(crate::InitialTenantIntent::new(
        instance.to_bytes(),
        default_tenant,
        TenantSlug::parse_canonical("default")?,
        "Default tenant",
        administrator,
        salt,
        hash,
        PrincipalId::from_bytes([0xe5; 16])?,
        [0xe6; 32],
        [0xe7; 32],
        PrincipalId::from_bytes([0xe8; 16])?,
        [0xe9; 32],
        [0xea; 32],
        [0xeb; 32],
        [0xec; 32],
        vec![0xed; 48],
        keys.tenant_key_envelope(instance, default_tenant)?,
        2_592_000,
        1,
        1,
        [16; 11],
        crate::InitialAuditContext::new(17, [0xee; 16], true)?,
    )?)?;
    let (governance, audit) = initial.into_parts();
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([0xef; 16])?,
            positron_kernel::FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(governance)?],
        )?,
        Some(AuditIntent::new(audit)?),
    )?;
    let basis = catalog.pin()?;
    let original = basis.governance_object()?.1.tenant_key_envelope().to_vec();
    let (epoch, fingerprint) =
        keys.backup_tenant_key_identity(instance, default_tenant, &original)?;
    let sanitized = TenantAdministration::backup_catalog_objects(
        &basis,
        &[(default_tenant, epoch, fingerprint)],
    )?;
    let objects = sanitized
        .iter()
        .map(|object| CatalogObject::new(object.canonical_bytes().to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xf0; 16])?,
            positron_kernel::FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    let snapshot = catalog.pin()?;
    assert!(TenantAdministration::restore_catalog_objects(&snapshot, &keys, &[]).is_err());
    let mut corrupt = original.clone();
    *corrupt.last_mut().ok_or("envelope")? ^= 1;
    assert!(
        TenantAdministration::restore_catalog_objects(
            &snapshot,
            &keys,
            &[(default_tenant, corrupt)]
        )
        .is_err()
    );
    assert!(
        TenantAdministration::restore_catalog_objects(
            &snapshot,
            &keys,
            &[
                (default_tenant, original.clone()),
                (default_tenant, original.clone())
            ]
        )
        .is_err()
    );
    let restored = TenantAdministration::restore_catalog_objects(
        &snapshot,
        &keys,
        &[(default_tenant, original.clone())],
    )?;
    catalog.commit(
        snapshot.identity(),
        CatalogProposal::new(
            TransactionId::new([0xf1; 16])?,
            positron_kernel::FormatEpoch::CATALOG_V1,
            restored,
        )?,
        None,
    )?;
    let restored = catalog.pin()?;
    assert_eq!(
        restored.governance_object()?.1.tenant_key_envelope(),
        original
    );
    assert_eq!(
        restored.governance_object()?.0,
        basis.governance_object()?.0
    );
    assert_eq!(
        keys.backup_tenant_key_identity(
            instance,
            default_tenant,
            restored.governance_object()?.1.tenant_key_envelope()
        )?,
        (epoch, fingerprint)
    );
    Ok(())
}

#[test]
fn restore_operation_binds_target_configuration_and_independent_recovery()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::*;
    let repository = RepositoryOperationParameters::local(
        RepositoryAction::Verify,
        "/backup",
        [1; 16],
        [2; 32],
        [3; 32],
    )?;
    let source = BackupVerificationParameters::new(repository, [4; 32], [5; 16], [6; 32])?;
    let parameters = BackupRestoreParameters::new(source, [7; 32], [8; 32], [9; 32])?;
    let request = DurableOperationRequest::backup_restore(
        PrincipalId::from_bytes([10; 16])?,
        AdministrativeIdempotencyKey::new([11; 16])?,
        [12; 16],
        1,
        13,
        parameters.intent_digest(),
    )?;
    assert_eq!(request.kind(), DurableOperationKind::BackupRestore);
    assert_eq!(
        request.kind().declared_irreversible_boundary(),
        DurableOperationBoundary::CatalogGenerationPublished
    );
    for changed in [
        BackupRestoreParameters::new(source, [17; 32], [8; 32], [9; 32])?,
        BackupRestoreParameters::new(source, [7; 32], [18; 32], [9; 32])?,
        BackupRestoreParameters::new(source, [7; 32], [8; 32], [19; 32])?,
    ] {
        assert_ne!(parameters.intent_digest(), changed.intent_digest());
    }
    assert!(BackupRestoreParameters::new(source, [0; 32], [8; 32], [9; 32]).is_err());
    assert!(BackupRestoreParameters::new(source, [7; 32], [0; 32], [9; 32]).is_err());
    assert!(BackupRestoreParameters::new(source, [7; 32], [8; 32], [0; 32]).is_err());
    Ok(())
}

#[test]
fn restore_operation_reopens_exact_intent_and_rejects_cancellation_after_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let root = PagedCatalogRoot::new()?;
    let instance = positron_kernel::InstanceId::new([0xe1; 16])?;
    let default_tenant = tenant(1)?;
    let authority = fixture_authority(
        PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?,
        default_tenant,
    )?;
    let keys = BootstrapKeyCustody::initialize(&root.secrets())?;
    let catalog = Catalog::open(&authority, instance, keys.catalog_secret(instance)?)?;
    let administrator = PrincipalId::from_bytes([0xe2; 16])?;
    let secret = [0xe3; 32];
    let salt = [0xe4; 32];
    let hash = keys.salted_secret_hash(&salt, &secret)?;
    let initial = crate::InitialGovernanceIntent::create_tenant(crate::InitialTenantIntent::new(
        instance.to_bytes(),
        default_tenant,
        TenantSlug::parse_canonical("default")?,
        "Default tenant",
        administrator,
        salt,
        hash,
        PrincipalId::from_bytes([0xe5; 16])?,
        [0xe6; 32],
        [0xe7; 32],
        PrincipalId::from_bytes([0xe8; 16])?,
        [0xe9; 32],
        [0xea; 32],
        [0xeb; 32],
        [0xec; 32],
        vec![0xed; 48],
        keys.tenant_key_envelope(instance, default_tenant)?,
        2_592_000,
        1,
        1,
        [16; 11],
        crate::InitialAuditContext::new(17, [0xee; 16], true)?,
    )?)?;
    let (governance, audit) = initial.into_parts();
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([0xef; 16])?,
            positron_kernel::FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(governance)?],
        )?,
        Some(AuditIntent::new(audit)?),
    )?;
    use crate::*;
    let actor = Identity::open(&catalog.pin()?)?.attribute(
        &keys,
        PresentedCredential::parse(&format!("pos_{}", "e3".repeat(32)))?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let registration = catalog.pin()?.governance_object()?.0;
    let source = BackupVerificationParameters::new(
        RepositoryOperationParameters::local(
            RepositoryAction::Verify,
            "/backup",
            [1; 16],
            [2; 32],
            [3; 32],
        )?,
        registration.to_bytes(),
        [5; 16],
        [6; 32],
    )?;
    let parameters = BackupRestoreParameters::new(source, [7; 32], [8; 32], [9; 32])?;
    let request = DurableOperationRequest::backup_restore(
        actor.principal_id(),
        AdministrativeIdempotencyKey::new([11; 16])?,
        instance.to_bytes(),
        catalog.pin()?.number(),
        20,
        parameters.intent_digest(),
    )?;
    let accepted = DurableOperationAdministration::accept_backup_restore_registered(
        &catalog,
        actor,
        request,
        parameters,
        registration,
    )?;
    assert_eq!(accepted.status(), DurableOperationStatus::Pending);
    assert_eq!(accepted.backup_restore_parameters(), Some(parameters));
    assert_eq!(
        DurableOperationAdministration::accept_backup_restore_registered(
            &catalog,
            actor,
            request,
            parameters,
            registration
        )?,
        accepted
    );
    DurableOperationAdministration::begin(&catalog, actor, accepted.operation_id(), 21)?;
    let running = DurableOperationAdministration::advance_backup_restore(
        &catalog,
        actor,
        accepted.operation_id(),
        BackupRestoreStage::Transferring,
        22,
    )?;
    assert_eq!(running.status(), DurableOperationStatus::Running);
    drop(catalog);
    let catalog = Catalog::open(&authority, instance, keys.catalog_secret(instance)?)?;
    assert_eq!(
        DurableOperationAdministration::inspect_authorized(
            &catalog,
            actor,
            accepted.operation_id()
        )?
        .ok_or("restored operation")?
        .backup_restore_parameters(),
        Some(parameters)
    );
    DurableOperationAdministration::advance_backup_restore(
        &catalog,
        actor,
        accepted.operation_id(),
        BackupRestoreStage::Verifying,
        23,
    )?;
    let publishing = DurableOperationAdministration::advance_backup_restore(
        &catalog,
        actor,
        accepted.operation_id(),
        BackupRestoreStage::Publishing,
        24,
    )?;
    assert!(
        DurableOperationAdministration::cancel_backup_restore(
            &catalog,
            actor,
            accepted.operation_id(),
            AdministrativeIdempotencyKey::new([12; 16])?,
            publishing.revision(),
            25
        )
        .is_err()
    );
    let report = CatalogObject::new(b"POSBRR01verified restore receipt fixture".to_vec())?;
    let digest = report.identity().to_bytes();
    let completed = DurableOperationAdministration::succeed_backup_restore(
        &catalog,
        actor,
        accepted.operation_id(),
        report,
        26,
    )?;
    assert_eq!(completed.status(), DurableOperationStatus::Succeeded);
    assert_eq!(completed.backup_restore_report(), Some(digest));
    let request = DurableOperationRequest::backup_restore(
        actor.principal_id(),
        AdministrativeIdempotencyKey::new([13; 16])?,
        instance.to_bytes(),
        catalog.pin()?.number(),
        27,
        parameters.intent_digest(),
    )?;
    let pending = DurableOperationAdministration::accept_backup_restore_registered(
        &catalog,
        actor,
        request,
        parameters,
        registration,
    )?;
    let changed = BackupRestoreParameters::new(source, [17; 32], [8; 32], [9; 32])?;
    let conflict = DurableOperationRequest::backup_restore(
        actor.principal_id(),
        request.idempotency_key(),
        instance.to_bytes(),
        request.accepted_generation(),
        27,
        changed.intent_digest(),
    )?;
    assert!(
        DurableOperationAdministration::accept_backup_restore_registered(
            &catalog,
            actor,
            conflict,
            changed,
            registration
        )
        .is_err()
    );
    DurableOperationAdministration::begin(&catalog, actor, pending.operation_id(), 28)?;
    let transferring = DurableOperationAdministration::advance_backup_restore(
        &catalog,
        actor,
        pending.operation_id(),
        BackupRestoreStage::Transferring,
        29,
    )?;
    let cancellation = AdministrativeIdempotencyKey::new([14; 16])?;
    assert!(
        DurableOperationAdministration::cancel_backup_restore(
            &catalog,
            actor,
            pending.operation_id(),
            cancellation,
            pending.revision(),
            30
        )
        .is_err()
    );
    let cancelled = DurableOperationAdministration::cancel_backup_restore(
        &catalog,
        actor,
        pending.operation_id(),
        cancellation,
        transferring.revision(),
        30,
    )?;
    assert_eq!(cancelled.status(), DurableOperationStatus::Cancelled);
    assert_eq!(
        DurableOperationAdministration::accept_backup_restore_registered(
            &catalog,
            actor,
            request,
            parameters,
            registration
        )?,
        cancelled
    );
    assert_eq!(
        DurableOperationAdministration::cancel_backup_restore(
            &catalog,
            actor,
            pending.operation_id(),
            cancellation,
            transferring.revision(),
            31
        )?,
        cancelled
    );

    Ok(())
}
