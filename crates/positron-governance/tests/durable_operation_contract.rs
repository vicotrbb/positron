use positron_domain::identity::PrincipalId;
use positron_governance::{
    AdministrativeIdempotencyKey, DurableOperationKind, DurableOperationRequest, OperationId,
};

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
