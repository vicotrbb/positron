use super::*;
use crate::*;
#[test]
fn backup_acceptance_progress_cancellation_and_publication_are_durable()
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
    let actor = crate::Identity::open(&catalog.pin()?)?.attribute(
        &keys,
        crate::PresentedCredential::parse(&format!("pos_{}", "e3".repeat(32)))?,
        crate::RequestedIntent::SystemAdministration,
        crate::CompatibilityHints::none(),
    )?;
    let repository = RepositoryOperationParameters::local(
        RepositoryAction::Verify,
        "/protected/repository",
        [0xf5; 16],
        [0xf6; 32],
        [0xf7; 32],
    )?;
    let registration = CatalogObject::new(b"bound backup repository fixture".to_vec())?;
    let parameters =
        BackupSnapshotParameters::new(repository, 3600, registration.identity().to_bytes())?;
    let request = DurableOperationRequest::backup_snapshot(
        actor.principal_id(),
        AdministrativeIdempotencyKey::new([0xf8; 16])?,
        instance.to_bytes(),
        catalog.pin()?.number(),
        18,
        parameters.intent_digest(),
    )?;
    let accepted = DurableOperationAdministration::accept_backup(
        &catalog,
        actor,
        request,
        parameters,
        registration,
    )?;
    assert_eq!(accepted.kind(), DurableOperationKind::BackupSnapshot);
    assert_eq!(accepted.backup_parameters(), Some(parameters));
    let replay = DurableOperationAdministration::accept_backup(
        &catalog,
        actor,
        request,
        parameters,
        CatalogObject::new(b"bound backup repository fixture".to_vec())?,
    )?;
    assert_eq!(accepted, replay);
    let id = accepted.operation_id();
    DurableOperationAdministration::begin(&catalog, actor, id, 19)?;
    let transferring = DurableOperationAdministration::advance_backup(
        &catalog,
        actor,
        id,
        BackupOperationStage::Transferring,
        20,
    )?;
    assert_eq!(transferring.phase(), DurableOperationPhase::BackupTransfer);
    assert_ne!(catalog.pin()?.number(), transferring.revision());
    assert_eq!(
        DurableOperationAdministration::cancel_backup(
            &catalog,
            actor,
            id,
            AdministrativeIdempotencyKey::new([0xf9; 16])?,
            transferring.revision() - 1,
            21
        ),
        Err(DurableOperationFailure::StaleGeneration)
    );
    let cancelled = DurableOperationAdministration::cancel_backup(
        &catalog,
        actor,
        id,
        AdministrativeIdempotencyKey::new([0xf9; 16])?,
        transferring.revision(),
        21,
    )?;
    assert_eq!(cancelled.status(), DurableOperationStatus::Running);
    assert_eq!(cancelled.phase(), DurableOperationPhase::BackupCancellation);
    assert!(cancelled.completed_at_unix_seconds().is_none());
    let requested_audit = catalog
        .governance_audit_records()?
        .into_iter()
        .last()
        .ok_or("requested audit")?;
    let GovernanceAuditEntry::DurableOperation(requested_audit) =
        GovernanceAuditEntry::decode(&requested_audit)?
    else {
        return Err("requested audit owner".into());
    };
    assert_eq!(requested_audit.outcome(), DurableOperationStatus::Running);
    assert!(requested_audit.cancellation_request_id().is_some());
    let cancelled =
        DurableOperationAdministration::complete_backup_cancellation(&catalog, actor, id, 21)?;
    assert_eq!(cancelled.status(), DurableOperationStatus::Cancelled);
    assert_eq!(
        DurableOperationAdministration::cancel_backup(
            &catalog,
            actor,
            id,
            AdministrativeIdempotencyKey::new([0xf9; 16])?,
            transferring.revision(),
            22
        )?,
        cancelled
    );
    let request2 = DurableOperationRequest::backup_snapshot(
        actor.principal_id(),
        AdministrativeIdempotencyKey::new([0xfa; 16])?,
        instance.to_bytes(),
        catalog.pin()?.number(),
        22,
        parameters.intent_digest(),
    )?;
    let accepted2 = DurableOperationAdministration::accept_backup(
        &catalog,
        actor,
        request2,
        parameters,
        CatalogObject::new(b"bound backup repository fixture".to_vec())?,
    )?;
    let id2 = accepted2.operation_id();
    DurableOperationAdministration::begin(&catalog, actor, id2, 23)?;
    DurableOperationAdministration::advance_backup(
        &catalog,
        actor,
        id2,
        BackupOperationStage::Publishing,
        24,
    )?;
    assert_eq!(
        DurableOperationAdministration::cancel_backup(
            &catalog,
            actor,
            id2,
            AdministrativeIdempotencyKey::new([0xfb; 16])?,
            catalog.pin()?.number(),
            25
        ),
        Err(DurableOperationFailure::CancellationUnavailable)
    );
    let receipt =
        BackupOperationReceipt::new([0xfc; 32], [0xfe; 32], 17, [0xfd; 32], 8192, 4096, 3600)?;
    let previous = CatalogObject::new(b"bound backup repository fixture".to_vec())?.identity();
    let successor = CatalogObject::new(b"anchored backup repository fixture".to_vec())?;
    let successor_id = successor.identity();
    let before = catalog.pin()?.number();
    let audits_before = catalog.governance_audit_records()?.len();
    let fault = positron_kernel::with_catalog_publication_fault_after(
        positron_kernel::CatalogPublicationFault::SynchronizeCommit,
        0,
        || {
            DurableOperationAdministration::succeed_backup_with_registration(
                &catalog,
                actor,
                id2,
                receipt,
                previous,
                CatalogObject::new(b"anchored backup repository fixture".to_vec())
                    .expect("registration"),
                26,
            )
        },
    );
    assert_eq!(fault, Err(DurableOperationFailure::PersistenceUnavailable));
    assert_eq!(catalog.pin()?.number(), before);
    assert_eq!(catalog.governance_audit_records()?.len(), audits_before);
    assert!(catalog.pin()?.object(previous)?.is_some());
    assert!(catalog.pin()?.object(successor_id)?.is_none());
    assert!(
        DurableOperationAdministration::inspect(&catalog, id2)?
            .ok_or("operation")?
            .backup_receipt()
            .is_none()
    );
    drop(catalog);
    let catalog = Catalog::open(&authority, instance, keys.catalog_secret(instance)?)?;
    assert_eq!(catalog.pin()?.number(), before);
    assert_eq!(catalog.governance_audit_records()?.len(), audits_before);
    assert!(catalog.pin()?.object(previous)?.is_some());
    assert!(catalog.pin()?.object(successor_id)?.is_none());
    assert!(
        DurableOperationAdministration::inspect(&catalog, id2)?
            .ok_or("cold operation")?
            .backup_receipt()
            .is_none()
    );
    let succeeded = DurableOperationAdministration::succeed_backup_with_registration(
        &catalog, actor, id2, receipt, previous, successor, 26,
    )?;
    assert!(catalog.pin()?.object(previous)?.is_none());
    assert!(catalog.pin()?.object(successor_id)?.is_some());
    assert_eq!(
        succeeded.irreversible_boundary(),
        DurableOperationBoundary::BackupRegistryPublished
    );
    assert_eq!(succeeded.backup_receipt(), Some(receipt));
    let record = catalog
        .governance_audit_records()?
        .into_iter()
        .last()
        .ok_or("publication audit")?;
    let GovernanceAuditEntry::DurableOperation(entry) = GovernanceAuditEntry::decode(&record)?
    else {
        return Err("wrong audit owner".into());
    };
    assert_eq!(entry.backup_receipt(), Some(receipt));
    for length in [0, 8, 32, record.intent().len() - 1] {
        assert!(
            GovernanceAuditEntry::decode_fields(
                record.position(),
                record.transaction().to_bytes(),
                &record.intent()[..length]
            )
            .is_err()
        );
    }
    let mut trailing = record.intent().to_vec();
    trailing.push(0);
    assert!(
        GovernanceAuditEntry::decode_fields(
            record.position(),
            record.transaction().to_bytes(),
            &trailing
        )
        .is_err()
    );

    let repository = entry.backup_repository().ok_or("repository binding")?;
    assert_eq!(
        repository.repository_id(),
        parameters.repository().repository_id()
    );
    assert_eq!(repository.instance_id(), instance.to_bytes());
    assert_eq!(
        repository.prefix_commitment(),
        parameters.repository().prefix_commitment()
    );
    let request3 = DurableOperationRequest::backup_snapshot(
        actor.principal_id(),
        AdministrativeIdempotencyKey::new([0xf3; 16])?,
        instance.to_bytes(),
        catalog.pin()?.number(),
        27,
        parameters.intent_digest(),
    )?;
    let accepted3 = DurableOperationAdministration::accept_backup_registered(
        &catalog,
        actor,
        request3,
        parameters,
        successor_id,
    )?;
    let id3 = accepted3.operation_id();
    DurableOperationAdministration::begin(&catalog, actor, id3, 28)?;
    assert_eq!(
        DurableOperationAdministration::cancel_backup(
            &catalog,
            actor,
            id3,
            AdministrativeIdempotencyKey::new([0xf9; 16])?,
            DurableOperationAdministration::inspect(&catalog, id3)?
                .ok_or("operation revision")?
                .revision(),
            29
        ),
        Err(DurableOperationFailure::IdempotencyConflict)
    );
    DurableOperationAdministration::cancel_backup(
        &catalog,
        actor,
        id3,
        AdministrativeIdempotencyKey::new([0xf4; 16])?,
        DurableOperationAdministration::inspect(&catalog, id3)?
            .ok_or("operation revision")?
            .revision(),
        29,
    )?;
    let cleanup = BackupCleanupReceipt::new(id3.to_bytes(), [0xa1; 32], [0xa2; 32], 1, 2, 3)?;
    assert!(BackupCleanupReceipt::new([0; 16], [0xa1; 32], [0xa2; 32], 1, 2, 3).is_err());
    assert!(BackupCleanupReceipt::new(id3.to_bytes(), [0; 32], [0xa2; 32], 1, 2, 3).is_err());
    assert!(BackupCleanupReceipt::new(id3.to_bytes(), [0xa1; 32], [0; 32], 1, 2, 3).is_err());
    assert!(
        BackupCleanupReceipt::new(id3.to_bytes(), [0xa1; 32], [0xa2; 32], u32::MAX, 1, 0).is_err()
    );
    let cleanup_registration =
        CatalogObject::new(b"cleanup anchored registration".to_vec())?.identity();
    let before_cleanup = catalog.pin()?.number();
    let before_cleanup_audits = catalog.governance_audit_records()?.len();
    let fault = positron_kernel::with_catalog_publication_fault_after(
        positron_kernel::CatalogPublicationFault::SynchronizeCommit,
        0,
        || {
            DurableOperationAdministration::complete_backup_cancellation_with_registration(
                &catalog,
                actor,
                id3,
                cleanup,
                successor_id,
                CatalogObject::new(b"cleanup anchored registration".to_vec())
                    .expect("registration"),
                30,
            )
        },
    );
    assert_eq!(fault, Err(DurableOperationFailure::PersistenceUnavailable));
    drop(catalog);
    let catalog = Catalog::open(&authority, instance, keys.catalog_secret(instance)?)?;
    assert_eq!(catalog.pin()?.number(), before_cleanup);
    assert_eq!(
        catalog.governance_audit_records()?.len(),
        before_cleanup_audits
    );
    assert!(catalog.pin()?.object(successor_id)?.is_some());
    assert!(catalog.pin()?.object(cleanup_registration)?.is_none());
    assert!(
        DurableOperationAdministration::inspect(&catalog, id3)?
            .ok_or("cold cancellation")?
            .backup_cleanup_receipt()
            .is_none()
    );
    let cancelled = DurableOperationAdministration::complete_backup_cancellation_with_registration(
        &catalog,
        actor,
        id3,
        cleanup,
        successor_id,
        CatalogObject::new(b"cleanup anchored registration".to_vec())?,
        30,
    )?;
    assert_eq!(cancelled.backup_cleanup_receipt(), Some(cleanup));
    assert_eq!(
        DurableOperationAdministration::complete_backup_cancellation_with_registration(
            &catalog,
            actor,
            id3,
            cleanup,
            successor_id,
            CatalogObject::new(b"cleanup anchored registration".to_vec())?,
            30
        )?,
        cancelled
    );
    let cleanup_audit = catalog
        .governance_audit_records()?
        .into_iter()
        .last()
        .ok_or("cleanup audit")?;
    let mut wrong_cleanup = cleanup_audit.intent().to_vec();
    let snapshot_offset = wrong_cleanup
        .len()
        .checked_sub(92)
        .ok_or("cleanup evidence length")?;
    *wrong_cleanup
        .get_mut(snapshot_offset)
        .ok_or("cleanup snapshot")? ^= 1;
    assert!(
        GovernanceAuditEntry::decode_fields(
            cleanup_audit.position(),
            cleanup_audit.transaction().to_bytes(),
            &wrong_cleanup
        )
        .is_err()
    );
    let GovernanceAuditEntry::DurableOperation(cleanup_audit) =
        GovernanceAuditEntry::decode(&cleanup_audit)?
    else {
        return Err("cleanup audit owner".into());
    };
    assert_eq!(cleanup_audit.backup_cleanup_receipt(), Some(cleanup));
    drop(catalog);
    let reopened = Catalog::open(&authority, instance, keys.catalog_secret(instance)?)?;
    assert_eq!(
        DurableOperationAdministration::inspect(&reopened, id2)?,
        Some(succeeded)
    );
    assert_eq!(
        DurableOperationAdministration::inspect(&reopened, id3)?,
        Some(cancelled)
    );
    Ok(())
}

#[test]
fn backup_retention_claim_and_refusal_are_durable() -> Result<(), Box<dyn std::error::Error>> {
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
    let actor = crate::Identity::open(&catalog.pin()?)?.attribute(
        &keys,
        crate::PresentedCredential::parse(&format!("pos_{}", "e3".repeat(32)))?,
        crate::RequestedIntent::SystemAdministration,
        crate::CompatibilityHints::none(),
    )?;
    let repository = RepositoryOperationParameters::local(
        RepositoryAction::Verify,
        "/protected/repository",
        [0xf5; 16],
        [0xf6; 32],
        [0xf7; 32],
    )?;
    let registration = CatalogObject::new(b"cleanup anchored registration".to_vec())?;
    let cleanup_registration = registration.identity();
    let parameters =
        BackupSnapshotParameters::new(repository, 3600, cleanup_registration.to_bytes())?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([0xc1; 16])?,
            positron_kernel::FormatEpoch::CATALOG_V1,
            vec![registration],
        )?,
        None,
    )?;
    let id2 = OperationId::from_bytes([0xc2; 16])?;
    let id3 = OperationId::from_bytes([0xc3; 16])?;
    let manifest = [0xfc; 32];
    let retention = BackupRetentionParameters::new(
        parameters.repository(),
        parameters.registration_identity(),
        id2.to_bytes(),
        manifest,
    )?;
    let retention_request = DurableOperationRequest::backup_retention(
        actor.principal_id(),
        AdministrativeIdempotencyKey::new([0xb1; 16])?,
        instance.to_bytes(),
        catalog.pin()?.number(),
        31,
        retention.intent_digest(),
    )?;
    let retention_operation = DurableOperationAdministration::accept_backup_retention_registered(
        &catalog,
        actor,
        retention_request,
        retention,
        cleanup_registration,
    )?;
    let retention_id = retention_operation.operation_id();
    assert_eq!(
        retention_operation.kind(),
        DurableOperationKind::BackupRetention
    );
    DurableOperationAdministration::begin(&catalog, actor, retention_id, 32)?;
    let scanning = DurableOperationAdministration::advance_backup_retention(
        &catalog,
        actor,
        retention_id,
        BackupRetentionStage::Scanning,
        33,
    )?;
    assert_eq!(scanning.phase(), DurableOperationPhase::BackupRetentionScan);
    let cancel_request = DurableOperationRequest::backup_retention(
        actor.principal_id(),
        AdministrativeIdempotencyKey::new([0xb5; 16])?,
        instance.to_bytes(),
        catalog.pin()?.number(),
        33,
        retention.intent_digest(),
    )?;
    let cancellable = DurableOperationAdministration::accept_backup_retention_registered(
        &catalog,
        actor,
        cancel_request,
        retention,
        cleanup_registration,
    )?;
    DurableOperationAdministration::begin(&catalog, actor, cancellable.operation_id(), 33)?;
    let cancellable = DurableOperationAdministration::advance_backup_retention(
        &catalog,
        actor,
        cancellable.operation_id(),
        BackupRetentionStage::Scanning,
        33,
    )?;
    let requested = DurableOperationAdministration::cancel_backup(
        &catalog,
        actor,
        cancellable.operation_id(),
        AdministrativeIdempotencyKey::new([0xb6; 16])?,
        cancellable.revision(),
        33,
    )?;
    assert_eq!(
        requested.cancellation(),
        DurableOperationCancellation::Requested
    );
    assert_eq!(
        DurableOperationAdministration::complete_backup_cancellation(
            &catalog,
            actor,
            requested.operation_id(),
            33
        )?
        .status(),
        DurableOperationStatus::Cancelled
    );
    let early_request = DurableOperationRequest::backup_retention(
        actor.principal_id(),
        AdministrativeIdempotencyKey::new([0xb7; 16])?,
        instance.to_bytes(),
        catalog.pin()?.number(),
        33,
        retention.intent_digest(),
    )?;
    let early = DurableOperationAdministration::accept_backup_retention_registered(
        &catalog,
        actor,
        early_request,
        retention,
        cleanup_registration,
    )?;
    DurableOperationAdministration::begin(&catalog, actor, early.operation_id(), 33)?;
    DurableOperationAdministration::advance_backup_retention(
        &catalog,
        actor,
        early.operation_id(),
        BackupRetentionStage::Scanning,
        33,
    )?;
    let rejected = DurableOperationAdministration::reject_backup_retention_not_due(
        &catalog,
        actor,
        early.operation_id(),
        33,
    )?;
    assert_eq!(rejected.status(), DurableOperationStatus::Failed);
    assert_eq!(
        rejected.terminal_error(),
        Some(DurableOperationTerminalError::BackupRetentionNotDue)
    );
    assert_eq!(
        rejected.irreversible_boundary(),
        DurableOperationBoundary::NotCrossed
    );
    assert_eq!(
        DurableOperationAdministration::accept_backup_retention_registered(
            &catalog,
            actor,
            early_request,
            retention,
            cleanup_registration
        )?,
        rejected
    );
    let publishing = DurableOperationAdministration::advance_backup_retention(
        &catalog,
        actor,
        retention_id,
        BackupRetentionStage::Publishing,
        34,
    )?;
    assert_eq!(
        DurableOperationAdministration::cancel_backup(
            &catalog,
            actor,
            retention_id,
            AdministrativeIdempotencyKey::new([0xb2; 16])?,
            publishing.revision(),
            35
        ),
        Err(DurableOperationFailure::CancellationUnavailable)
    );
    let expired_registration = CatalogObject::new(b"expiry claim anchored registration".to_vec())?;
    let expired_registration_id = expired_registration.identity();
    let claimed = DurableOperationAdministration::publish_backup_retention_claim_with_registration(
        &catalog,
        actor,
        retention_id,
        BackupRetentionClaimReceipt::new([0xb3; 32])?,
        cleanup_registration,
        expired_registration,
        35,
    )?;
    assert_eq!(
        claimed.irreversible_boundary(),
        DurableOperationBoundary::BackupRegistryExpired
    );
    assert_eq!(
        claimed.phase(),
        DurableOperationPhase::BackupRetentionCleanup
    );
    let retention_receipt =
        BackupCleanupReceipt::new(id2.to_bytes(), manifest, [0xb4; 32], 2, 1, 3)?;
    let wrong_target = BackupCleanupReceipt::new(id3.to_bytes(), manifest, [0xb4; 32], 2, 1, 3)?;
    assert_eq!(
        DurableOperationAdministration::succeed_backup_retention_with_registration(
            &catalog,
            actor,
            retention_id,
            wrong_target,
            expired_registration_id,
            CatalogObject::new(b"expiry completed anchored registration".to_vec())?,
            36
        ),
        Err(DurableOperationFailure::InvalidInput)
    );
    let wrong_manifest =
        BackupCleanupReceipt::new(id2.to_bytes(), [0xb8; 32], [0xb4; 32], 2, 1, 3)?;
    assert_eq!(
        DurableOperationAdministration::succeed_backup_retention_with_registration(
            &catalog,
            actor,
            retention_id,
            wrong_manifest,
            expired_registration_id,
            CatalogObject::new(b"expiry completed anchored registration".to_vec())?,
            36
        ),
        Err(DurableOperationFailure::InvalidInput)
    );
    let before_expiry_completion = catalog.pin()?.number();
    let fault = positron_kernel::with_catalog_publication_fault_after(
        positron_kernel::CatalogPublicationFault::SynchronizeCommit,
        0,
        || {
            DurableOperationAdministration::succeed_backup_retention_with_registration(
                &catalog,
                actor,
                retention_id,
                retention_receipt,
                expired_registration_id,
                CatalogObject::new(b"expiry completed anchored registration".to_vec())
                    .expect("registration"),
                36,
            )
        },
    );
    assert_eq!(fault, Err(DurableOperationFailure::PersistenceUnavailable));
    drop(catalog);
    let catalog = Catalog::open(&authority, instance, keys.catalog_secret(instance)?)?;
    assert_eq!(catalog.pin()?.number(), before_expiry_completion);
    assert_eq!(
        DurableOperationAdministration::inspect(&catalog, retention_id)?.ok_or("cold retention")?,
        claimed
    );
    assert!(catalog.pin()?.object(expired_registration_id)?.is_some());
    let retained = DurableOperationAdministration::succeed_backup_retention_with_registration(
        &catalog,
        actor,
        retention_id,
        retention_receipt,
        expired_registration_id,
        CatalogObject::new(b"expiry completed anchored registration".to_vec())?,
        36,
    )?;
    assert_eq!(retained.status(), DurableOperationStatus::Succeeded);
    assert_eq!(retained.backup_cleanup_receipt(), Some(retention_receipt));
    drop(catalog);
    let reopened = Catalog::open(&authority, instance, keys.catalog_secret(instance)?)?;
    assert_eq!(
        DurableOperationAdministration::inspect(&reopened, retention_id)?,
        Some(retained)
    );
    assert_eq!(
        DurableOperationAdministration::inspect(&reopened, rejected.operation_id())?,
        Some(rejected)
    );
    Ok(())
}
