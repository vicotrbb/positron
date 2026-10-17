use super::*;
#[test]
fn live_purge_requires_purging_and_verified_historical_key_removal()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_live_purge(false)
}

#[test]
fn secondary_live_purge_removes_profile_and_preserves_other_tenant_authority()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_live_purge(true)
}

fn exercise_live_purge(secondary: bool) -> Result<(), Box<dyn std::error::Error>> {
    let root = PagedCatalogRoot::new()?;
    let instance = positron_kernel::InstanceId::new([0xe1; 16])?;
    let default_tenant = tenant(1)?;
    let authority = fixture_authority_with_purge_pool(
        PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?,
        default_tenant,
        Some(if secondary {
            tenant(77)?
        } else {
            default_tenant
        }),
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
    let basis = catalog.pin()?;
    let governance = basis.governance_object()?.0;
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xf0; 16])?,
            positron_kernel::FormatEpoch::CATALOG_V2,
            vec![
                CatalogObject::new(basis.object(governance)?.ok_or("governance")?.to_vec())?,
                TenantAdministration::epoch_two_registry(&basis)?,
            ],
        )?,
        None,
    )?;

    let actor = Identity::open(&catalog.pin()?)?.attribute(
        &keys,
        PresentedCredential::parse(&format!("pos_{}", "e3".repeat(32)))?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let target = if secondary {
        let target = tenant(77)?;
        TenantAdministration::create(
            &catalog,
            &keys,
            instance,
            administrator,
            TenantCreateRequest::new(
                actor,
                TenantCreateConfiguration::new(
                    TenantSlug::parse_canonical("secondary")?,
                    "Secret profile label",
                    60,
                    1,
                    [1; 11],
                ),
                AdministrativeIdempotencyKey::new([0xd1; 16])?,
            )
            .with_generated_tenant(target),
        )?;
        target
    } else {
        default_tenant
    };
    reject_unrelated_purge_transitions(&catalog, actor, target)?;
    let proof_digest = [88; 32];
    assert!(
        TenantAdministration::live_purge_objects(
            &catalog.pin()?,
            target,
            proof_digest,
            [0xa1; 16],
            17
        )
        .is_err()
    );
    let (_, generation) = TenantAdministration::lifecycle_state(&catalog.pin()?, target)?;
    crate::TenantLifecycleAdministration::transition(
        &catalog,
        administrator,
        crate::TenantLifecycleTransitionRequest::new(
            actor,
            target,
            positron_domain::lifecycle::TenantLifecycleState::Purging,
            generation,
            AdministrativeIdempotencyKey::new([0xf1; 16])?,
        ),
        || Ok(18),
    )?;
    assert!(matches!(
        crate::TenantLifecycleAdministration::transition(
            &catalog,
            administrator,
            crate::TenantLifecycleTransitionRequest::new(
                actor,
                target,
                positron_domain::lifecycle::TenantLifecycleState::Purged,
                TenantAdministration::lifecycle_state(&catalog.pin()?, target)?.1,
                AdministrativeIdempotencyKey::new([0xa2; 16])?
            ),
            || Ok(19)
        ),
        Err(crate::TenantLifecycleAdministrationFailure::PurgeCompletionUnavailable)
    ));
    let basis = catalog.pin()?;
    let mut objects =
        TenantAdministration::live_purge_objects(&basis, target, proof_digest, [0xa1; 16], 17)?;
    objects.extend(
        catalog.prepare_tenant_key_reclamation(target, proof_digest, |bytes| {
            TenantAdministration::is_tenant_key_object(bytes, target)
        })?,
    );
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xf2; 16])?,
            positron_kernel::FormatEpoch::CATALOG_V2,
            objects,
        )?,
        Some(AuditIntent::new(
            b"live envelopes removed fixture".to_vec(),
        )?),
    )?;
    assert!(matches!(
        TenantAdministration::begin_live_purge_inventory(&catalog, target, [89; 32]),
        Err(TenantAdministrationFailure::InvalidInput)
    ));
    let stale_proof = TenantAdministration::reclaim_live_purge(&catalog, target, proof_digest)?;
    let request = DurableOperationRequest::tenant_purge(
        administrator,
        target,
        AdministrativeIdempotencyKey::new([0xb3; 16])?,
        catalog.pin()?.number(),
        24,
        [0xb4; 32],
    )?;
    let accepted = DurableOperationAdministration::accept_tenant_purge(&catalog, actor, request)?;
    let operation =
        DurableOperationAdministration::begin(&catalog, actor, accepted.operation_id(), 24)?;
    DurableOperationAdministration::mark_draining(&catalog, actor, operation.operation_id(), 25)?;
    DurableOperationAdministration::publish_tenant_purge_boundary(
        &catalog,
        actor,
        operation.operation_id(),
        25,
    )?;
    let basis = catalog.pin()?;
    let mut progress_objects = Vec::new();
    for id in basis.object_identities() {
        progress_objects.push(CatalogObject::new(
            basis.object(id)?.ok_or("object")?.to_vec(),
        )?);
    }
    let progress = DurableOperationAdministration::publish_tenant_purge_progress(
        &catalog,
        actor,
        operation.operation_id(),
        progress_objects,
        26,
    )?;
    assert_eq!(progress.status(), DurableOperationStatus::Running);
    assert_eq!(
        TenantAdministration::lifecycle_state(&catalog.pin()?, target)?.0,
        positron_domain::lifecycle::TenantLifecycleState::Purging
    );
    assert!(matches!(
        DurableOperationAdministration::complete_tenant_purge(
            &catalog,
            actor,
            operation.operation_id(),
            &stale_proof,
            27
        ),
        Err(DurableOperationFailure::InvalidState)
    ));
    let proof = TenantAdministration::reclaim_live_purge(&catalog, target, proof_digest)?;
    let completed = DurableOperationAdministration::complete_tenant_purge(
        &catalog,
        actor,
        operation.operation_id(),
        &proof,
        27,
    )?;
    assert_eq!(completed.status(), DurableOperationStatus::Succeeded);
    let snapshot = catalog.pin()?;
    assert_eq!(
        TenantAdministration::inspect(&snapshot, target)?.lifecycle(),
        positron_domain::lifecycle::TenantLifecycleState::Purged
    );
    assert_eq!(
        TenantAdministration::restore_key_tenant_ids(&snapshot)?,
        if secondary {
            vec![default_tenant]
        } else {
            Vec::new()
        }
    );
    let inspection = TenantAdministration::inspect(&snapshot, target)?;
    assert_eq!(inspection.display_name(), None);
    assert_eq!(inspection.retention_seconds(), None);
    if !secondary {
        assert_eq!(snapshot.governance_object()?.1.credentials().len(), 1);
        let terminal = snapshot.governance_object()?.1;
        assert!(
            terminal
                .with_credentials(0, terminal.credentials())
                .is_err()
        );
        assert!(!TenantAdministration::backup_catalog_objects(&snapshot, &[])?.is_empty());
    } else {
        assert!(
            TenantAdministration::inspect(&snapshot, default_tenant)?
                .display_name()
                .is_some()
        );
    }
    assert!(Identity::open(&snapshot).is_ok());
    assert!(TenantAdministration::complete_live_purge_objects(&snapshot, target, &proof).is_ok());
    let reservations = TenantAdministration::restore_purge_exclusions(&snapshot)?;
    assert_eq!(
        reservations
            .first()
            .ok_or("permanent exclusion")?
            .operation_id(),
        Some([0xa1; 16])
    );
    assert_eq!(
        reservations
            .first()
            .ok_or("permanent exclusion")?
            .accepted_at_unix_seconds(),
        Some(17)
    );
    let exclusion = RestorePurgeExclusion::new(
        target,
        TenantSlug::parse_canonical(inspection.slug())?,
        [99; 32],
    )?;
    let objects = TenantAdministration::apply_restore_purge_exclusions(&snapshot, &[exclusion])?;
    catalog.commit(
        snapshot.identity(),
        CatalogProposal::new(
            TransactionId::new([0xf4; 16])?,
            positron_kernel::FormatEpoch::CATALOG_V2,
            objects,
        )?,
        None,
    )?;
    assert_eq!(
        TenantAdministration::restore_purge_exclusions(&catalog.pin()?)?,
        reservations
    );
    drop(catalog);
    let catalog = Catalog::open(&authority, instance, keys.catalog_secret(instance)?)?;
    assert_eq!(
        TenantAdministration::inspect(&catalog.pin()?, target)?.lifecycle(),
        positron_domain::lifecycle::TenantLifecycleState::Purged
    );
    assert_eq!(
        TenantAdministration::restore_purge_exclusions(&catalog.pin()?)?.len(),
        1
    );
    Ok(())
}

fn reject_unrelated_purge_transitions(
    catalog: &Catalog<'_>,
    actor: crate::AuthorizedContext,
    target: TenantId,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::*;
    let create = |key, now| -> Result<DurableOperation, Box<dyn std::error::Error>> {
        let request = DurableOperationRequest::tenant_purge(
            actor.principal_id(),
            target,
            AdministrativeIdempotencyKey::new([key; 16])?,
            catalog.pin()?.number(),
            now,
            [0x97; 32],
        )?;
        let accepted =
            DurableOperationAdministration::accept_tenant_purge(catalog, actor, request)?;
        Ok(DurableOperationAdministration::begin(
            catalog,
            actor,
            accepted.operation_id(),
            now,
        )?)
    };
    let first = create(0xb1, 17)?;
    let success = DurableOperationAdministration::succeed_catalog_format_migration(
        catalog,
        actor,
        first.operation_id(),
        18,
    );
    let second = create(0xb2, 19)?;
    DurableOperationAdministration::mark_draining(catalog, actor, second.operation_id(), 20)?;
    let drained =
        DurableOperationAdministration::mark_drained(catalog, actor, second.operation_id(), 21);
    let failed = DurableOperationAdministration::fail_catalog_format_migration(
        catalog,
        actor,
        second.operation_id(),
        22,
        DurableOperationTerminalError::HandlerRejected,
    );
    assert!(
        matches!(success, Err(DurableOperationFailure::InvalidState))
            && matches!(drained, Err(DurableOperationFailure::InvalidState))
            && matches!(failed, Err(DurableOperationFailure::InvalidState)),
        "unrelated migration transitions accepted purge: success={success:?}, drained={drained:?}, failed={failed:?}"
    );
    DurableOperationAdministration::reject_tenant_purge(catalog, actor, first.operation_id(), 22)?;
    DurableOperationAdministration::reject_tenant_purge(catalog, actor, second.operation_id(), 22)?;
    Ok(())
}
