use positron_domain::identity::PrincipalId;
use positron_governance::{
    AdministrativeIdempotencyKey, DurableOperationKind, DurableOperationRequest, OperationId,
};

#[test]
fn provider_migration_operation_binds_principal_generation_and_exact_phase_intent()
-> Result<(), Box<dyn std::error::Error>> {
    let principal = PrincipalId::from_bytes([0x41; 16])?;
    let key = AdministrativeIdempotencyKey::new([0x42; 16])?;
    let request = DurableOperationRequest::key_provider_migration(
        principal, key, [0x43; 16], 7, 100, [0x44; 32],
    )?;
    let retry = DurableOperationRequest::key_provider_migration(
        principal, key, [0x43; 16], 7, 200, [0x44; 32],
    )?;
    assert_eq!(request.operation_id(), retry.operation_id());
    for (actor, generation, intent) in [
        (PrincipalId::from_bytes([0x45; 16])?, 7, [0x44; 32]),
        (principal, 8, [0x44; 32]),
        (principal, 7, [0x46; 32]),
    ] {
        let changed = DurableOperationRequest::key_provider_migration(
            actor, key, [0x43; 16], generation, 100, intent,
        )?;
        assert_ne!(request.operation_id(), changed.operation_id());
    }
    assert_eq!(request.kind(), DurableOperationKind::KeyProviderMigration);
    assert!(
        DurableOperationRequest::key_provider_migration(
            principal, key, [0x43; 16], 7, 100, [0; 32],
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn operation_identity_is_stable_for_an_exact_administrative_request()
-> Result<(), Box<dyn std::error::Error>> {
    let request = DurableOperationRequest::catalog_format_migration(
        PrincipalId::from_bytes([0x11; 16])?,
        AdministrativeIdempotencyKey::new([0x22; 16])?,
        [0x33; 16],
        1,
        17,
    )?;
    assert_eq!(request.kind(), DurableOperationKind::CatalogFormatMigration);
    assert_eq!(request.operation_id(), OperationId::from_request(&request));
    Ok(())
}

#[test]
fn segment_abandonment_request_binds_exact_confirmed_loss_and_declares_irreversibility() {
    let principal =
        positron_domain::identity::PrincipalId::from_bytes([0xa1; 16]).expect("principal");
    let tenant = positron_domain::identity::TenantId::from_bytes([0xa2; 16]).expect("tenant");
    let key = positron_governance::AdministrativeIdempotencyKey::new([0xa3; 16]).expect("key");
    let request = positron_governance::DurableOperationRequest::segment_abandonment(
        principal, tenant, key, [0xa4; 16], 3, 100, [0xa5; 32],
    )
    .expect("confirmed request");
    let changed = positron_governance::DurableOperationRequest::segment_abandonment(
        principal, tenant, key, [0xa4; 16], 3, 100, [0xa6; 32],
    )
    .expect("changed request");
    assert_ne!(request.operation_id(), changed.operation_id());
    assert_eq!(
        request.kind().declared_irreversible_boundary(),
        positron_governance::DurableOperationBoundary::CatalogGenerationPublished
    );
    assert!(
        positron_governance::DurableOperationRequest::segment_abandonment(
            principal, tenant, key, [0xa4; 16], 3, 100, [0; 32]
        )
        .is_err()
    );
}

#[test]
fn repository_operation_binds_native_locator_identity_actor_and_action()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_governance::{RepositoryAction, RepositoryOperationParameters};
    let parameters = RepositoryOperationParameters::local(
        RepositoryAction::Doctor,
        "/protected/repository",
        [61; 16],
        [62; 32],
        [63; 32],
    )?;
    let principal = PrincipalId::from_bytes([64; 16])?;
    let key = AdministrativeIdempotencyKey::new([65; 16])?;
    let request = DurableOperationRequest::repository(
        principal,
        key,
        [66; 16],
        7,
        100,
        parameters.intent_digest(),
    )?;
    let retry = DurableOperationRequest::repository(
        principal,
        key,
        [66; 16],
        7,
        200,
        parameters.intent_digest(),
    )?;
    assert_eq!(request.operation_id(), retry.operation_id());
    let changed = RepositoryOperationParameters::local(
        RepositoryAction::Verify,
        "/protected/repository",
        [61; 16],
        [62; 32],
        [63; 32],
    )?;
    assert_ne!(
        request.operation_id(),
        DurableOperationRequest::repository(
            principal,
            key,
            [66; 16],
            7,
            100,
            changed.intent_digest()
        )?
        .operation_id()
    );
    assert_eq!(request.kind(), DurableOperationKind::RepositoryInspection);
    assert!(!format!("{parameters:?}").contains("/protected/repository"));
    assert!(
        RepositoryOperationParameters::local(
            RepositoryAction::Doctor,
            "/protected/../other",
            [61; 16],
            [62; 32],
            [63; 32]
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn upgrade_request_binds_the_complete_declarative_plan() -> Result<(), Box<dyn std::error::Error>> {
    let principal = PrincipalId::from_bytes([0x71; 16])?;
    let key = AdministrativeIdempotencyKey::new([0x72; 16])?;
    let request = DurableOperationRequest::upgrade(principal, key, [0x73; 16], 7, 100, [0x74; 32])?;
    let retry = DurableOperationRequest::upgrade(principal, key, [0x73; 16], 7, 200, [0x74; 32])?;
    assert_eq!(request.operation_id(), retry.operation_id());
    assert_eq!(request.kind(), DurableOperationKind::Upgrade);
    for (instance, generation, plan) in [
        ([0x75; 16], 7, [0x74; 32]),
        ([0x73; 16], 8, [0x74; 32]),
        ([0x73; 16], 7, [0x76; 32]),
    ] {
        assert_ne!(
            request.operation_id(),
            DurableOperationRequest::upgrade(principal, key, instance, generation, 100, plan)?
                .operation_id()
        );
    }
    assert!(DurableOperationRequest::upgrade(principal, key, [0x73; 16], 7, 100, [0; 32]).is_err());
    Ok(())
}
