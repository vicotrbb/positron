use super::*;
use crate::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct FailureFixture {
    authority: StorageKernelResourceAuthority,
    keys: BootstrapKeyCustody,
    instance: positron_kernel::InstanceId,
    actor: AuthorizedContext,
    failed: DurableOperation,
    previous: positron_kernel::CatalogObjectId,
    _root: PagedCatalogRoot,
}
impl FailureFixture {
    fn new() -> TestResult<Self> {
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
        let initial =
            crate::InitialGovernanceIntent::create_tenant(crate::InitialTenantIntent::new(
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
        let previous = registration.identity();
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
        let id = accepted.operation_id();
        DurableOperationAdministration::begin(&catalog, actor, id, 19)?;
        DurableOperationAdministration::advance_backup(
            &catalog,
            actor,
            id,
            BackupOperationStage::Transferring,
            20,
        )?;
        let failed = DurableOperationAdministration::fail_backup(&catalog, actor, id, 21)?;
        drop(catalog);
        Ok(Self {
            authority,
            keys,
            instance,
            actor,
            failed,
            previous,
            _root: root,
        })
    }
    fn catalog(&self) -> TestResult<Catalog<'_>> {
        Ok(Catalog::open(
            &self.authority,
            self.instance,
            self.keys.catalog_secret(self.instance)?,
        )?)
    }
}
#[test]
fn failed_backup_cleanup_preserves_failure_without_user_cancellation() -> TestResult {
    let fixture = FailureFixture::new()?;
    let catalog = fixture.catalog()?;
    let failed = fixture.failed;
    let actor = fixture.actor;
    let id = failed.operation_id();
    let generation = catalog.pin()?.number();
    let audits = catalog.governance_audit_records()?.len();
    let completed =
        DurableOperationAdministration::complete_backup_failure_cleanup(&catalog, actor, id, 22)?;
    assert_eq!(completed, failed);
    assert_eq!(completed.status(), DurableOperationStatus::Failed);
    assert_eq!(
        completed.terminal_error(),
        Some(DurableOperationTerminalError::HandlerRejected)
    );
    assert!(completed.cancellation_idempotency_key().is_none());
    assert_eq!(catalog.pin()?.number(), generation);
    assert_eq!(catalog.governance_audit_records()?.len(), audits);
    Ok(())
}

#[test]
fn failed_backup_signed_cleanup_is_atomic_recoverable_and_exactly_replayed() -> TestResult {
    let fixture = FailureFixture::new()?;
    let catalog = fixture.catalog()?;
    let failed = fixture.failed;
    let actor = fixture.actor;
    let id = failed.operation_id();
    let receipt = BackupCleanupReceipt::new(id.to_bytes(), [0xa1; 32], [0xa2; 32], 1, 2, 3)?;
    let successor = CatalogObject::new(b"failed-cleanup registration".to_vec())?.identity();
    let before = catalog.pin()?.number();
    let audits = catalog.governance_audit_records()?.len();
    let fault = positron_kernel::with_catalog_publication_fault_after(
        positron_kernel::CatalogPublicationFault::SynchronizeCommit,
        0,
        || {
            DurableOperationAdministration::complete_backup_failure_cleanup_with_registration(
                &catalog,
                actor,
                id,
                receipt,
                fixture.previous,
                CatalogObject::new(b"failed-cleanup registration".to_vec()).expect("registration"),
                22,
            )
        },
    );
    assert_eq!(fault, Err(DurableOperationFailure::PersistenceUnavailable));
    assert_eq!(catalog.pin()?.number(), before);
    assert_eq!(catalog.governance_audit_records()?.len(), audits);
    drop(catalog);
    let catalog = fixture.catalog()?;
    assert_eq!(
        DurableOperationAdministration::inspect(&catalog, id)?,
        Some(failed)
    );
    assert!(catalog.pin()?.object(fixture.previous)?.is_some());
    assert!(catalog.pin()?.object(successor)?.is_none());
    let completed =
        DurableOperationAdministration::complete_backup_failure_cleanup_with_registration(
            &catalog,
            actor,
            id,
            receipt,
            fixture.previous,
            CatalogObject::new(b"failed-cleanup registration".to_vec())?,
            23,
        )?;
    assert_eq!(completed.status(), DurableOperationStatus::Failed);
    assert_eq!(completed.terminal_error(), failed.terminal_error());
    assert_eq!(completed.phase(), failed.phase());
    assert_eq!(
        completed.completed_at_unix_seconds(),
        failed.completed_at_unix_seconds()
    );
    assert_eq!(completed.revision(), failed.revision() + 1);
    assert_eq!(completed.lookup_retention(), failed.lookup_retention());
    assert_eq!(completed.updated_at_unix_seconds(), 22);
    assert_eq!(completed.backup_cleanup_receipt(), Some(receipt));
    assert!(completed.backup_receipt().is_none());
    assert!(completed.cancellation_idempotency_key().is_none());
    assert!(catalog.pin()?.object(fixture.previous)?.is_none());
    assert!(catalog.pin()?.object(successor)?.is_some());
    assert_eq!(catalog.governance_audit_records()?.len(), audits + 1);
    let audit = catalog
        .governance_audit_records()?
        .into_iter()
        .last()
        .ok_or("cleanup audit")?;
    let GovernanceAuditEntry::DurableOperation(entry) = GovernanceAuditEntry::decode(&audit)?
    else {
        return Err("wrong audit owner".into());
    };
    assert_eq!(entry.outcome(), DurableOperationStatus::Failed);
    assert_eq!(entry.backup_cleanup_receipt(), Some(receipt));
    assert!(entry.cancellation_request_id().is_none());
    let mut wrong_snapshot = audit.intent().to_vec();
    let offset = wrong_snapshot
        .len()
        .checked_sub(92)
        .ok_or("cleanup audit length")?;
    *wrong_snapshot.get_mut(offset).ok_or("cleanup snapshot")? ^= 1;
    assert!(
        GovernanceAuditEntry::decode_fields(
            audit.position(),
            audit.transaction().to_bytes(),
            &wrong_snapshot
        )
        .is_err()
    );
    let generation = catalog.pin()?.number();
    let audits = catalog.governance_audit_records()?.len();
    assert_eq!(
        DurableOperationAdministration::complete_backup_failure_cleanup_with_registration(
            &catalog,
            actor,
            id,
            receipt,
            fixture.previous,
            CatalogObject::new(b"failed-cleanup registration".to_vec())?,
            24
        )?,
        completed
    );
    assert_eq!(catalog.pin()?.number(), generation);
    assert_eq!(catalog.governance_audit_records()?.len(), audits);
    let conflicting = BackupCleanupReceipt::new(id.to_bytes(), [0xb1; 32], [0xa2; 32], 1, 2, 3)?;
    assert_eq!(
        DurableOperationAdministration::complete_backup_failure_cleanup_with_registration(
            &catalog,
            actor,
            id,
            conflicting,
            fixture.previous,
            CatalogObject::new(b"failed-cleanup registration".to_vec())?,
            24
        ),
        Err(DurableOperationFailure::IdempotencyConflict)
    );
    assert!(
        DurableOperationAdministration::complete_backup_failure_cleanup_with_registration(
            &catalog,
            actor,
            id,
            receipt,
            fixture.previous,
            CatalogObject::new(b"different registration".to_vec())?,
            24
        )
        .is_err()
    );
    assert!(
        DurableOperationAdministration::complete_backup_failure_cleanup_with_registration(
            &catalog,
            actor,
            id,
            receipt,
            successor,
            CatalogObject::new(b"failed-cleanup registration".to_vec())?,
            24
        )
        .is_err()
    );
    drop(catalog);
    let reopened = fixture.catalog()?;
    assert_eq!(
        DurableOperationAdministration::inspect(&reopened, id)?,
        Some(completed)
    );
    Ok(())
}

#[test]
fn failed_cleanup_rejects_wrong_snapshot_missing_anchor_and_nonfailed_state() -> TestResult {
    let fixture = FailureFixture::new()?;
    let catalog = fixture.catalog()?;
    let actor = fixture.actor;
    let failed = fixture.failed;
    let id = failed.operation_id();
    let receipt = BackupCleanupReceipt::new(id.to_bytes(), [0xa1; 32], [0xa2; 32], 1, 2, 3)?;
    let wrong = BackupCleanupReceipt::new([0xb1; 16], [0xa1; 32], [0xa2; 32], 1, 2, 3)?;
    let generation = catalog.pin()?.number();
    let audits = catalog.governance_audit_records()?.len();
    assert_eq!(
        DurableOperationAdministration::complete_backup_failure_cleanup(&catalog, actor, id, 20),
        Err(DurableOperationFailure::InvalidState)
    );
    assert_eq!(
        DurableOperationAdministration::complete_backup_failure_cleanup_with_registration(
            &catalog,
            actor,
            id,
            wrong,
            fixture.previous,
            CatalogObject::new(b"replacement".to_vec())?,
            22
        ),
        Err(DurableOperationFailure::InvalidInput)
    );
    let missing = CatalogObject::new(b"not a current registration".to_vec())?.identity();
    assert_eq!(
        DurableOperationAdministration::complete_backup_failure_cleanup_with_registration(
            &catalog,
            actor,
            id,
            receipt,
            missing,
            CatalogObject::new(b"replacement".to_vec())?,
            22
        ),
        Err(DurableOperationFailure::InvalidInput)
    );
    assert_eq!(
        DurableOperationAdministration::complete_backup_failure_cleanup_with_registration(
            &catalog,
            actor,
            id,
            receipt,
            fixture.previous,
            CatalogObject::new(b"bound backup repository fixture".to_vec())?,
            22
        ),
        Err(DurableOperationFailure::InvalidInput)
    );
    assert_eq!(
        DurableOperationAdministration::inspect(&catalog, id)?,
        Some(failed)
    );
    assert_eq!(catalog.pin()?.number(), generation);
    assert_eq!(catalog.governance_audit_records()?.len(), audits);
    let parameters = failed.backup_parameters().ok_or("snapshot parameters")?;
    let request = DurableOperationRequest::backup_snapshot(
        actor.principal_id(),
        AdministrativeIdempotencyKey::new([0xb2; 16])?,
        fixture.instance.to_bytes(),
        catalog.pin()?.number(),
        22,
        parameters.intent_digest(),
    )?;
    let pending = DurableOperationAdministration::accept_backup_registered(
        &catalog,
        actor,
        request,
        parameters,
        fixture.previous,
    )?;
    assert_eq!(
        DurableOperationAdministration::complete_backup_failure_cleanup(
            &catalog,
            actor,
            pending.operation_id(),
            23
        ),
        Err(DurableOperationFailure::InvalidState)
    );
    let receipt = BackupCleanupReceipt::new(
        pending.operation_id().to_bytes(),
        [0xa1; 32],
        [0xa2; 32],
        1,
        2,
        3,
    )?;
    assert_eq!(
        DurableOperationAdministration::complete_backup_failure_cleanup_with_registration(
            &catalog,
            actor,
            pending.operation_id(),
            receipt,
            fixture.previous,
            CatalogObject::new(b"replacement".to_vec())?,
            23
        ),
        Err(DurableOperationFailure::InvalidState)
    );
    Ok(())
}

#[test]
fn expired_failed_backup_retains_parameters_until_bound_cleanup_owner_finishes() -> TestResult {
    use positron_kernel::{
        MaintenanceCoordinator, MaintenancePreconditions, RepositoryOperationBinding,
    };
    let fixture = FailureFixture::new()?;
    let catalog = fixture.catalog()?;
    let failed = fixture.failed;
    let parameters = failed.backup_parameters().ok_or("backup parameters")?;
    let expiry = failed
        .earliest_lookup_expiry_unix_seconds()
        .ok_or("expiry")?;
    let coordinator = MaintenanceCoordinator::new();
    let binding = RepositoryOperationBinding::new(
        failed.operation_id().to_bytes(),
        parameters.intent_digest(),
    )
    .expect("binding");
    let task = coordinator
        .submit_backup_operation_with_resources_and_persist(
            &catalog,
            binding,
            MaintenancePreconditions::new(catalog.pin()?.number(), 1).expect("preconditions"),
            positron_kernel::ResourceAmounts::new([
                4 * 1024 * 1024,
                1,
                1,
                0,
                1,
                0,
                1,
                1,
                1,
                8,
                16384,
            ]),
            22,
        )
        .expect("submit");
    assert!(
        binding
            .has_live_backup_owner(&catalog.pin()?)
            .expect("live owner")
    );
    assert!(
        !RepositoryOperationBinding::new(failed.operation_id().to_bytes(), [0x77; 32])
            .expect("different intent")
            .has_live_backup_owner(&catalog.pin()?)
            .expect("query")
    );
    drop(catalog);
    let catalog = fixture.catalog()?;
    for (key, now) in [(0xa1, expiry), (0xa2, expiry + 1)] {
        let request = DurableOperationRequest::backup_snapshot(
            fixture.actor.principal_id(),
            AdministrativeIdempotencyKey::new([key; 16])?,
            fixture.instance.to_bytes(),
            catalog.pin()?.number(),
            now,
            parameters.intent_digest(),
        )?;
        DurableOperationAdministration::accept_backup_registered(
            &catalog,
            fixture.actor,
            request,
            parameters,
            fixture.previous,
        )?;
        if key == 0xa1 {
            assert_eq!(
                DurableOperationAdministration::inspect(&catalog, failed.operation_id())?,
                Some(failed)
            );
            coordinator
                .cancel_and_persist(&catalog, task.identity())
                .expect("cancel owner");
            assert!(
                !binding
                    .has_live_backup_owner(&catalog.pin()?)
                    .expect("terminal owner")
            );
        } else {
            assert!(
                DurableOperationAdministration::inspect(&catalog, failed.operation_id())?.is_none()
            );
        }
    }
    Ok(())
}

#[test]
fn malformed_maintenance_owner_refuses_expired_backup_pruning() -> TestResult {
    let fixture = FailureFixture::new()?;
    let catalog = fixture.catalog()?;
    let failed = fixture.failed;
    let parameters = failed.backup_parameters().ok_or("parameters")?;
    let snapshot = catalog.pin()?;
    let mut objects = Vec::new();
    for identity in snapshot.object_identities() {
        objects.push(CatalogObject::new(
            snapshot.object(identity)?.ok_or("object")?.to_vec(),
        )?);
    }
    objects.push(CatalogObject::new(b"PMTC0006truncated".to_vec())?);
    catalog.commit(
        snapshot.identity(),
        CatalogProposal::new(
            TransactionId::new([0x73; 16])?,
            positron_kernel::FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    let generation = catalog.pin()?.number();
    let request = DurableOperationRequest::backup_snapshot(
        fixture.actor.principal_id(),
        AdministrativeIdempotencyKey::new([0x74; 16])?,
        fixture.instance.to_bytes(),
        generation,
        failed
            .earliest_lookup_expiry_unix_seconds()
            .ok_or("expiry")?,
        parameters.intent_digest(),
    )?;
    assert_eq!(
        DurableOperationAdministration::accept_backup_registered(
            &catalog,
            fixture.actor,
            request,
            parameters,
            fixture.previous
        ),
        Err(DurableOperationFailure::PersistenceUnavailable)
    );
    assert_eq!(catalog.pin()?.number(), generation);
    assert_eq!(
        DurableOperationAdministration::inspect(&catalog, failed.operation_id())?,
        Some(failed)
    );
    Ok(())
}
