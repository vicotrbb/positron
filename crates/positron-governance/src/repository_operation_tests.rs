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
    let policy = positron_domain::repository::RepositoryPolicy {
        soft_delete: Some(positron_domain::repository::PolicyObservation::Observed(
            604800,
        )),
        doctor_probe: Some(positron_domain::repository::ObjectProtection {
            retention: positron_domain::repository::PolicyObservation::Observed(
                positron_domain::repository::ObjectRetention {
                    mode: positron_domain::repository::RetentionMode::Compliance,
                    retain_until_unix_seconds: 1_900_000_000,
                },
            ),
            legal_hold: positron_domain::repository::PolicyObservation::Unavailable(
                positron_domain::repository::RepositoryFailure::PermissionDenied,
            ),
            event_hold: positron_domain::repository::PolicyObservation::Observed(Some(
                positron_domain::repository::RetentionPeriod::UntilRelease,
            )),
        }),
        ..positron_domain::repository::RepositoryPolicy::local()
    };
    let invalid_policy = positron_domain::repository::RepositoryPolicy {
        object_lock: positron_domain::repository::PolicyObservation::Observed(
            positron_domain::repository::ObjectLockPolicy::Enabled {
                default_retention: Some(positron_domain::repository::RetentionPolicy {
                    mode: positron_domain::repository::RetentionMode::Compliance,
                    period: positron_domain::repository::RetentionPeriod::Days(0),
                }),
            },
        ),
        ..policy
    };
    assert_eq!(
        DurableOperationAdministration::succeed_repository_with_policy(
            &reopened,
            actor,
            accepted.operation_id(),
            20,
            invalid_policy
        ),
        Err(DurableOperationFailure::PersistenceUnavailable)
    );
    assert_eq!(
        DurableOperationAdministration::inspect_authorized(
            &reopened,
            actor,
            accepted.operation_id()
        )?
        .ok_or("running operation")?
        .status(),
        DurableOperationStatus::Running
    );

    let completed = DurableOperationAdministration::succeed_repository_with_policy(
        &reopened,
        actor,
        accepted.operation_id(),
        20,
        policy,
    )?;
    assert_eq!(completed.repository_policy(), Some(policy));
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
    let native = crate::RepositoryOperationParameters::aws_s3(
        crate::RepositoryAction::Doctor,
        "positron-backup\0us-east-1\0https://s3.us-east-1.amazonaws.com\x00123456789012\0owned/",
        [0xa1; 16],
        [0xa2; 32],
        [0xa3; 32],
    )?;
    let native_key = AdministrativeIdempotencyKey::new([0xa4; 16])?;
    let native_request = DurableOperationRequest::repository(
        actor.principal_id(),
        native_key,
        instance.to_bytes(),
        reopened.pin()?.number(),
        21,
        native.intent_digest(),
    )?;
    let native_accepted = DurableOperationAdministration::accept_repository(
        &reopened,
        actor,
        native_request,
        native,
    )?;
    assert_eq!(
        DurableOperationAdministration::accept_repository(
            &reopened,
            actor,
            native_request,
            native
        )?,
        native_accepted
    );
    drop(reopened);
    let reopened = Catalog::open(&authority, instance, keys.catalog_secret(instance)?)?;
    let native_restored = DurableOperationAdministration::inspect_authorized(
        &reopened,
        actor,
        native_accepted.operation_id(),
    )?
    .ok_or("lost native operation")?;
    assert_eq!(native_restored.repository_parameters(), Some(native));
    assert_eq!(
        native_restored
            .repository_parameters()
            .ok_or("parameters")?
            .provider_kind(),
        crate::RepositoryProviderKind::AwsS3
    );
    let changed = crate::RepositoryOperationParameters::aws_s3(
        crate::RepositoryAction::Doctor,
        "another-backup\0us-east-1\0https://s3.us-east-1.amazonaws.com\x00123456789012\0owned/",
        [0xa1; 16],
        [0xa2; 32],
        [0xa3; 32],
    )?;
    assert_eq!(
        DurableOperationAdministration::accept_repository(
            &reopened,
            actor,
            DurableOperationRequest::repository(
                actor.principal_id(),
                native_key,
                instance.to_bytes(),
                native_request.accepted_generation(),
                21,
                changed.intent_digest()
            )?,
            changed
        ),
        Err(DurableOperationFailure::IdempotencyConflict)
    );
    DurableOperationAdministration::begin(&reopened, actor, native_accepted.operation_id(), 22)?;
    DurableOperationAdministration::mark_draining(
        &reopened,
        actor,
        native_accepted.operation_id(),
        22,
    )?;
    assert_eq!(
        DurableOperationAdministration::succeed_repository(
            &reopened,
            actor,
            native_accepted.operation_id(),
            23
        ),
        Err(DurableOperationFailure::InvalidState)
    );
    assert_eq!(
        DurableOperationAdministration::inspect_authorized(
            &reopened,
            actor,
            native_accepted.operation_id()
        )?
        .ok_or("native operation")?
        .status(),
        DurableOperationStatus::Running
    );
    DurableOperationAdministration::succeed_repository_with_policy(
        &reopened,
        actor,
        native_accepted.operation_id(),
        23,
        policy,
    )?;
    drop(reopened);
    let reopened = Catalog::open(&authority, instance, keys.catalog_secret(instance)?)?;
    let receipt = DurableOperationAdministration::inspect_authorized(
        &reopened,
        actor,
        accepted.operation_id(),
    )?
    .ok_or("lost terminal policy receipt")?;
    assert_eq!(receipt.status(), DurableOperationStatus::Succeeded);
    assert_eq!(receipt.repository_policy(), Some(policy));
    assert_eq!(receipt.repository_parameters(), Some(parameters));
    Ok(())
}

#[test]
fn google_repository_parameters_bind_exact_native_locator_without_credentials() {
    use crate::{RepositoryAction, RepositoryOperationParameters, RepositoryProviderKind};
    let locator = "positron-backup\0".to_owned() + "123456789012\0US-CENTRAL1\0owned/";
    let value = RepositoryOperationParameters::google_cloud_storage(
        RepositoryAction::Doctor,
        &locator,
        [1; 16],
        [2; 32],
        [3; 32],
    )
    .expect("native parameters");
    assert_eq!(
        value.provider_kind(),
        RepositoryProviderKind::GoogleCloudStorage
    );
    assert_eq!(value.locator().expect("locator"), locator);
    assert!(
        RepositoryOperationParameters::google_cloud_storage(
            RepositoryAction::Doctor,
            &(locator.clone() + "\0extra"),
            [1; 16],
            [2; 32],
            [3; 32]
        )
        .is_err()
    );
    assert!(!format!("{value:?}").contains("positron-backup"));
}

#[test]
fn azure_native_parameters_preserve_provider_and_reject_locator_expansion() {
    use crate::{RepositoryAction, RepositoryOperationParameters, RepositoryProviderKind};
    let value = RepositoryOperationParameters::azure_blob(
        RepositoryAction::Verify,
        "account\0container\0owned/",
        [1; 16],
        [2; 32],
        [3; 32],
    )
    .expect("azure parameters");
    assert_eq!(value.provider_kind(), RepositoryProviderKind::AzureBlob);
    assert_eq!(
        value.locator().expect("locator"),
        "account\0container\0owned/"
    );
    assert!(
        RepositoryOperationParameters::azure_blob(
            RepositoryAction::Verify,
            "account\0container\0owned/\0secret",
            [1; 16],
            [2; 32],
            [3; 32]
        )
        .is_err()
    );
}
