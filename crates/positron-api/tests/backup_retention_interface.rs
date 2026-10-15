use positron_api::backup::BackupRequest;
#[test]
fn retention_expiry_requires_exact_published_snapshot_and_manifest() {
    let wire=br#"{"action":"expire","repository_id":"11111111-1111-4111-8111-111111111111","snapshot_id":"22222222222222222222222222222222","expected_manifest_checksum":"3333333333333333333333333333333333333333333333333333333333333333","expected_catalog_generation":1,"idempotency_key":"44444444-4444-4444-8444-444444444444"}"#;
    let request = BackupRequest::decode(wire).expect("expiry request");
    assert!(request.encode().is_ok());
}
#[test]
fn expiry_rejects_unbound_or_ambiguous_requests() {
    let wire = r#"{"action":"expire","repository_id":"11111111-1111-4111-8111-111111111111","snapshot_id":"22222222222222222222222222222222","expected_manifest_checksum":"3333333333333333333333333333333333333333333333333333333333333333","expected_catalog_generation":1,"idempotency_key":"44444444-4444-4444-8444-444444444444"}"#;
    let request = BackupRequest::decode(wire.as_bytes()).expect("request");
    let mut invalid = request.clone();
    invalid.snapshot_id = None;
    assert!(invalid.encode().is_err());
    invalid = request.clone();
    invalid.expected_manifest_checksum = None;
    assert!(invalid.encode().is_err());
    invalid = request.clone();
    invalid.snapshot_id = Some("0".repeat(32));
    assert!(invalid.encode().is_err());
    invalid = request.clone();
    invalid.expected_manifest_checksum = Some("A".repeat(64));
    assert!(invalid.encode().is_err());
    invalid = request.clone();
    invalid.locator = Some("/backup".into());
    assert!(invalid.encode().is_err());
    invalid = request.clone();
    invalid.retention_seconds = Some(60);
    assert!(invalid.encode().is_err());
    invalid = request.clone();
    invalid.operation_id = Some("5".repeat(32));
    assert!(invalid.encode().is_err());
    invalid = request.clone();
    invalid.action = "lookup".into();
    assert!(invalid.encode().is_err());
    invalid = request.clone();
    invalid.repository_id = None;
    assert!(invalid.encode().is_err());
    invalid = request;
    invalid.expected_catalog_generation = Some(0);
    assert!(invalid.encode().is_err());
}
fn pending(kind: &str, phase: &str, cleanup: bool) -> positron_api::backup::BackupResponse {
    positron_api::backup::BackupResponse::decode(format!(r#"{{"operation_revision":1,"kind":"{kind}","cleanup_pending":{cleanup},"operation":{{"id":"11111111111111111111111111111111","status":"running","phase":"{phase}","progress_percent":20,"retry":"inspect_by_operation_id","cancellation":"allowed_before_publication","irreversible_boundary":"not_crossed"}}}}"#).as_bytes()).expect("pending response")
}
#[test]
fn cancellation_stays_running_until_real_cleanup_finishes() {
    use positron_api::backup::BackupResponse;
    for kind in ["snapshot", "retention"] {
        let mut response = pending(kind, "preflight", false);
        response.operation.phase = "backup_cancellation".into();
        response.operation.cancellation = "cancel_requested_cleanup_pending".into();
        assert!(response.encode().is_err());
        response.cleanup_pending = true;
        assert_eq!(
            BackupResponse::decode(&response.encode().expect("requested")).expect("decode"),
            response
        );
        response.operation.status = "cancelled".into();
        response.operation.phase = "cancelled".into();
        response.operation.cancellation = "cancelled".into();
        assert!(response.encode().is_err());
        response.cleanup_pending = false;
        assert!(response.encode().is_ok());
    }
    let mut failed = pending("snapshot", "preflight", true);
    failed.operation.phase = "backup_publication".into();
    failed.operation.cancellation = "not_allowed_during_publication".into();
    failed.operation.status = "failed".into();
    failed.terminal_error_code = Some("handler_rejected".into());
    assert!(failed.encode().is_ok());
}
#[test]
fn terminal_retention_receipts_cannot_be_snapshot_success_or_pending_cleanup() {
    use positron_api::backup::{BackupResponse, BackupRetentionReceipt};
    use positron_api::repository::RepositoryIdentity;
    let mut response = pending("retention", "backup_retention_scan", false);
    response.operation.phase = "backup_retention_cleanup".into();
    assert!(response.encode().is_err());
    response.cleanup_pending = true;
    assert!(response.encode().is_err());
    response.operation.irreversible_boundary = "backup_registry_expired".into();
    response.operation.cancellation = "not_allowed_during_publication".into();
    assert!(response.encode().is_ok());
    response.operation.status = "succeeded".into();
    response.operation.phase = "published".into();
    response.operation.progress_percent = 100;
    response.operation.irreversible_boundary = "backup_registry_expired".into();
    response.operation.cancellation = "not_allowed_during_publication".into();
    response.repository = Some(RepositoryIdentity {
        repository_id: "11111111-1111-4111-8111-111111111111".into(),
        instance_id: "22222222-2222-4222-8222-222222222222".into(),
        provider_kind: "local_filesystem".into(),
        format_epoch: 1,
        integrity_fingerprint: "1".repeat(64),
        prefix_commitment: "2".repeat(64),
    });
    response.retention_receipt = Some(BackupRetentionReceipt {
        snapshot_id: "3".repeat(32),
        manifest_checksum: "4".repeat(64),
        registry_generation_checksum: "5".repeat(64),
        deleted_objects: 3,
        already_absent_objects: 2,
        retained_shared_objects: 1,
    });
    assert!(response.encode().is_err());
    response.cleanup_pending = false;
    assert_eq!(
        BackupResponse::decode(&response.encode().expect("retention receipt")).expect("decode"),
        response
    );
    let mut invalid = response.clone();
    invalid.kind = "snapshot".into();
    assert!(invalid.encode().is_err());
    invalid = response.clone();
    invalid.operation.irreversible_boundary = "backup_registry_published".into();
    assert!(invalid.encode().is_err());
    invalid = response.clone();
    invalid.retention_receipt = None;
    assert!(invalid.encode().is_err());
    invalid = response.clone();
    invalid
        .retention_receipt
        .as_mut()
        .expect("receipt")
        .registry_generation_checksum = "0".repeat(64);
    assert!(invalid.encode().is_err());
    invalid = response;
    invalid.operation.status = "running".into();
    assert!(invalid.encode().is_err());
}
#[test]
fn kind_is_required_and_cannot_cross_operation_phases() {
    let mut response = pending("snapshot", "backup_transfer", false);
    response.kind = "retention".into();
    assert!(response.encode().is_err());
    response = pending("retention", "backup_retention_scan", false);
    response.kind = "snapshot".into();
    assert!(response.encode().is_err());
    let wire = String::from_utf8(
        pending("snapshot", "preflight", false)
            .encode()
            .expect("encoded"),
    )
    .expect("utf8");
    assert!(
        positron_api::backup::BackupResponse::decode(
            wire.replace("\"kind\":\"snapshot\",", "").as_bytes()
        )
        .is_err()
    );
    assert!(
        positron_api::backup::BackupResponse::decode(
            wire.replace("\"cleanup_pending\":false,", "").as_bytes()
        )
        .is_err()
    );
}
#[test]
fn failed_expiry_exposes_the_durable_terminal_reason() {
    use positron_api::backup::BackupResponse;
    let wire = r#"{"operation_revision":2,"kind":"retention","cleanup_pending":false,"terminal_error_code":"backup_retention_not_due","operation":{"id":"11111111111111111111111111111111","status":"failed","phase":"backup_retention_scan","progress_percent":20,"retry":"never","cancellation":"allowed_before_publication","irreversible_boundary":"not_crossed"}}"#;
    let response = BackupResponse::decode(wire.as_bytes()).expect("known not-due failure");
    assert!(response.encode().is_ok());
}
#[test]
fn terminal_reason_is_closed_and_present_only_for_failure() {
    use positron_api::backup::BackupResponse;
    let mut response = pending("retention", "backup_retention_scan", false);
    response.operation.status = "failed".into();
    assert!(response.encode().is_err());
    for code in [
        "handler_rejected",
        "legacy_unknown",
        "backup_retention_not_due",
    ] {
        response.terminal_error_code = Some(code.into());
        assert_eq!(
            BackupResponse::decode(&response.encode().expect("known terminal reason"))
                .expect("decode"),
            response
        );
    }
    response.terminal_error_code = Some("provider_secret_or_unknown_code".into());
    assert!(response.encode().is_err());
    response.terminal_error_code = Some("backup_retention_not_due".into());
    response.operation.status = "running".into();
    assert!(response.encode().is_err());
    response.operation.status = "cancelled".into();
    response.operation.phase = "cancelled".into();
    response.operation.cancellation = "cancelled".into();
    assert!(response.encode().is_err());
}
