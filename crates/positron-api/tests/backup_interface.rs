use positron_api::backup::BackupRequest;
#[test]
fn backup_requires_retention_and_exact_selector() {
    let valid=br#"{"action":"create","expected_catalog_generation":1,"idempotency_key":"11111111-1111-4111-8111-111111111111","repository_id":"22222222-2222-4222-8222-222222222222","locator":"/backup","retention_seconds":60}"#;
    let request = BackupRequest::decode(valid).expect("bounded backup request");
    assert_eq!(request.retention_seconds, Some(60));
    let mut invalid = request.clone();
    invalid.retention_seconds = Some(59);
    assert!(invalid.encode().is_err());
    invalid = request.clone();
    invalid.retention_seconds = None;
    assert!(invalid.encode().is_err());
    invalid = request;
    invalid.action = "status".into();
    assert!(invalid.encode().is_err());
}
#[test]
fn backup_status_lookup_cancel_and_wire_bounds_are_explicit() {
    for valid in [
        r#"{"action":"status","operation_id":"11111111111111111111111111111111"}"#,
        r#"{"action":"lookup","idempotency_key":"11111111-1111-4111-8111-111111111111"}"#,
        r#"{"action":"cancel","expected_operation_revision":1,"idempotency_key":"11111111-1111-4111-8111-111111111111","operation_id":"11111111111111111111111111111111"}"#,
    ] {
        let request = BackupRequest::decode(valid.as_bytes()).expect("valid operation request");
        assert!(request.encode().is_ok());
    }
    for invalid in [
        r#"{"action":"status"}"#,
        r#"{"action":"lookup"}"#,
        r#"{"action":"status","operation_id":"bad"}"#,
        r#"{"action":"status","operation_id":"11111111111111111111111111111111","retention_seconds":60}"#,
        r#"{"action":"restore"}"#,
        r#"{"action":"status","secret":"hidden"}"#,
    ] {
        assert!(BackupRequest::decode(invalid.as_bytes()).is_err());
    }
    assert!(BackupRequest::decode(&vec![b' '; 4097]).is_err());
}
#[test]
fn backup_response_only_reports_verified_publication_as_success() {
    use positron_api::backup::BackupResponse;
    let pending = r#"{"operation_revision":1,"kind":"snapshot","cleanup_pending":false,"operation":{"id":"11111111111111111111111111111111","status":"running","phase":"backup_transfer","progress_percent":25,"retry":"inspect_by_operation_id","cancellation":"allowed_before_publication","irreversible_boundary":"not_crossed"}}"#;
    let response = BackupResponse::decode(pending.as_bytes()).expect("pending operation");
    assert!(response.encode().is_ok());
    let mut invalid = response.clone();
    invalid.operation.status = "succeeded".into();
    assert!(invalid.encode().is_err());
    invalid = response.clone();
    invalid.operation.phase = "draining".into();
    assert!(invalid.encode().is_err());
    invalid = response;
    invalid.operation.lookup_expires_at_unix_seconds = Some(1);
    assert!(invalid.encode().is_err());
    assert!(BackupResponse::decode(&vec![b' '; 4097]).is_err());
}
#[test]
fn verified_receipt_roundtrips_without_private_selector() {
    use positron_api::backup::BackupResponse;
    let wire = format!(
        r#"{{"operation_revision":1,"kind":"snapshot","cleanup_pending":false,"operation":{{"id":"11111111111111111111111111111111","status":"succeeded","phase":"published","progress_percent":100,"retry":"never","cancellation":"not_allowed_during_publication","irreversible_boundary":"backup_registry_published","lookup_expires_at_unix_seconds":900}},"repository":{{"repository_id":"11111111-1111-4111-8111-111111111111","instance_id":"22222222-2222-4222-8222-222222222222","provider_kind":"local_filesystem","format_epoch":1,"integrity_fingerprint":"{}","prefix_commitment":"{}"}},"receipt":{{"manifest_checksum":"{}","catalog_generation":7,"catalog_identity":"{}","uploaded_bytes":512,"reused_bytes":1024,"retain_until_unix_seconds":800,"registry_generation_checksum":"5555555555555555555555555555555555555555555555555555555555555555"}}}}"#,
        "1".repeat(64),
        "2".repeat(64),
        "3".repeat(64),
        "4".repeat(64)
    );
    let receipt = BackupResponse::decode(wire.as_bytes()).expect("verified receipt");
    let mut awaiting_cleanup = receipt.clone();
    awaiting_cleanup.cleanup_pending = true;
    assert!(awaiting_cleanup.encode().is_ok());
    assert!(
        BackupResponse::decode(wire.replace("local_filesystem", "azure_blob").as_bytes()).is_ok()
    );
    assert_eq!(
        BackupResponse::decode(&receipt.encode().expect("encode")).expect("decode"),
        receipt
    );
    assert_eq!(
        receipt.receipt.as_ref().expect("receipt").reused_bytes,
        1024
    );
    for invalid in [
        wire.replace("\"catalog_generation\":7", "\"catalog_generation\":0"),
        wire.replace("\"status\":\"succeeded\"", "\"status\":\"running\""),
        wire.replace("backup_registry_published", "not_crossed"),
        wire.replace(&"3".repeat(64), "invalid"),
        wire.replace(&"5".repeat(64), &"0".repeat(64)),
        wire.replace(&"5".repeat(64), &"A".repeat(64)),
        wire.replace(",\"registry_generation_checksum\":\"5555555555555555555555555555555555555555555555555555555555555555\"", ""),
    ] {
        assert!(BackupResponse::decode(invalid.as_bytes()).is_err());
    }
}
