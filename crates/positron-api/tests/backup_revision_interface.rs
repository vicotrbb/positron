use positron_api::backup::BackupRequest;
#[test]
fn cancel_uses_the_target_operation_revision() {
    let wire=br#"{"action":"cancel","operation_id":"11111111111111111111111111111111","idempotency_key":"22222222-2222-4222-8222-222222222222","expected_operation_revision":1}"#;
    let request = BackupRequest::decode(wire).expect("operation revision cancellation");
    assert!(request.encode().is_ok());
}
#[test]
fn cancel_rejects_global_catalog_generation() {
    assert!(BackupRequest::decode(br#"{"action":"cancel","operation_id":"11111111111111111111111111111111","idempotency_key":"22222222-2222-4222-8222-222222222222","expected_catalog_generation":1}"#).is_err());
}
#[test]
fn cancellation_revision_is_nonzero_exclusive_and_action_specific() {
    let mut request=BackupRequest::decode(br#"{"action":"cancel","operation_id":"11111111111111111111111111111111","idempotency_key":"22222222-2222-4222-8222-222222222222","expected_operation_revision":1}"#).expect("request");
    request.expected_operation_revision = Some(0);
    assert!(request.encode().is_err());
    request.expected_operation_revision = Some(1);
    request.expected_catalog_generation = Some(1);
    assert!(request.encode().is_err());
    request.expected_catalog_generation = None;
    request.repository_id = Some("33333333-3333-4333-8333-333333333333".into());
    assert!(request.encode().is_err());
    request.repository_id = None;
    request.retention_seconds = Some(60);
    assert!(request.encode().is_err());
    request.retention_seconds = None;
    request.snapshot_id = Some("4".repeat(32));
    assert!(request.encode().is_err());
    request.snapshot_id = None;
    request.expected_manifest_checksum = Some("5".repeat(64));
    assert!(request.encode().is_err());
    request.expected_manifest_checksum = None;
    request.locator = Some("/backup".into());
    assert!(request.encode().is_err());
    request.locator = None;
    request.action = "status".into();
    request.idempotency_key = None;
    assert!(request.encode().is_err());
    request.expected_operation_revision = None;
    assert!(request.encode().is_ok());
}
#[test]
fn response_revision_is_required_and_nonzero() {
    use positron_api::backup::BackupResponse;
    let wire = r#"{"operation_revision":7,"kind":"snapshot","cleanup_pending":false,"operation":{"id":"11111111111111111111111111111111","status":"running","phase":"backup_transfer","progress_percent":20,"retry":"inspect_by_operation_id","cancellation":"allowed_before_publication","irreversible_boundary":"not_crossed"}}"#;
    let response = BackupResponse::decode(wire.as_bytes()).expect("response");
    assert_eq!(response.operation_revision, 7);
    assert!(
        BackupResponse::decode(wire.replace("\"operation_revision\":7,", "").as_bytes()).is_err()
    );
    assert!(
        BackupResponse::decode(
            wire.replace("\"operation_revision\":7", "\"operation_revision\":0")
                .as_bytes()
        )
        .is_err()
    );
}
