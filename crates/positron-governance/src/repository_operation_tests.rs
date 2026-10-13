use super::*;
#[test]
fn repository_acceptance_is_atomic_replay_safe_and_reopens_exact_parameters()
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
    let parameters = crate::RepositoryOperationParameters::local(
        crate::RepositoryAction::Doctor,
        "/protected/repository",
        [0xf5; 16],
        [0xf6; 32],
        [0xf7; 32],
    )?;
    let generation = catalog.pin()?.number();
    let key = AdministrativeIdempotencyKey::new([0xf8; 16])?;
    let request = DurableOperationRequest::repository(
        actor.principal_id(),
        key,
        instance.to_bytes(),
        generation,
        18,
        parameters.intent_digest(),
    )?;
    let accepted =
        DurableOperationAdministration::accept_repository(&catalog, actor, request, parameters)?;
    assert_eq!(accepted.status(), DurableOperationStatus::Pending);
    assert_eq!(
        DurableOperationAdministration::accept_repository(&catalog, actor, request, parameters)?,
        accepted
    );
    drop(catalog);
    let reopened = Catalog::open(&authority, instance, keys.catalog_secret(instance)?)?;
    let recovered = DurableOperationAdministration::inspect_authorized(
        &reopened,
        actor,
        accepted.operation_id(),
    )?
    .ok_or("lost accepted operation")?;
    assert_eq!(recovered.repository_parameters(), Some(parameters));
    assert_eq!(recovered, accepted);
    assert_eq!(
        DurableOperationAdministration::resume_repository_actor(
            &reopened,
            accepted.operation_id(),
            19
        )?
        .principal_id(),
        actor.principal_id()
    );
    let running =
        DurableOperationAdministration::begin(&reopened, actor, accepted.operation_id(), 19)?;
    assert_eq!(running.status(), DurableOperationStatus::Running);
    DurableOperationAdministration::mark_draining(&reopened, actor, accepted.operation_id(), 19)?;
    let completed = DurableOperationAdministration::succeed_repository(
        &reopened,
        actor,
        accepted.operation_id(),
        20,
    )?;
    assert_eq!(completed.status(), DurableOperationStatus::Succeeded);
    assert_eq!(
        DurableOperationAdministration::inspect_authorized(
            &reopened,
            actor,
            accepted.operation_id()
        )?,
        Some(completed)
    );

    let conflict = crate::RepositoryOperationParameters::local(
        crate::RepositoryAction::Verify,
        "/protected/repository",
        [0xf5; 16],
        [0xf6; 32],
        [0xf7; 32],
    )?;
    assert_eq!(
        DurableOperationAdministration::accept_repository(
            &reopened,
            actor,
            DurableOperationRequest::repository(
                actor.principal_id(),
                key,
                instance.to_bytes(),
                generation,
                18,
                conflict.intent_digest()
            )?,
            conflict
        ),
        Err(DurableOperationFailure::IdempotencyConflict)
    );
    Ok(())
}
