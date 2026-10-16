use positron_api::backup::BackupRequest;

#[test]
fn independent_verification_requires_exact_registered_snapshot() {
    let wire = br#"{"action":"verify","repository_id":"11111111-1111-4111-8111-111111111111","snapshot_id":"22222222222222222222222222222222","expected_manifest_checksum":"3333333333333333333333333333333333333333333333333333333333333333","expected_catalog_generation":1,"idempotency_key":"44444444-4444-4444-8444-444444444444"}"#;
    let request = BackupRequest::decode(wire).expect("independent verification request");
    assert!(request.encode().is_ok());
    let mut invalid = request.clone();
    invalid.expected_manifest_checksum = None;
    assert!(invalid.encode().is_err());
    invalid = request.clone();
    invalid.locator = Some("/backup".into());
    assert!(invalid.encode().is_err());
    invalid = request;
    invalid.retention_seconds = Some(60);
    assert!(invalid.encode().is_err());
}

#[test]
fn verification_report_is_required_for_success_and_checksum_bound() {
    use positron_api::backup::BackupResponse;
    use sha2::{Digest, Sha256};
    let report = b"signed immutable report";
    let encoded = report
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let checksum = Sha256::digest(report)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let wire = serde_json::json!({"operation_revision":4,"kind":"verification","cleanup_pending":false,
        "verification_report":encoded,"verification_report_checksum":checksum,
        "operation":{"id":"11111111111111111111111111111111","status":"succeeded","phase":"published","progress_percent":100,"retry":"never","cancellation":"not_allowed_during_publication","irreversible_boundary":"verification_report_published"},
        "repository":{"repository_id":"11111111-1111-4111-8111-111111111111","instance_id":"22222222-2222-4222-8222-222222222222","provider_kind":"local_filesystem","format_epoch":1,"integrity_fingerprint":"1".repeat(64),"prefix_commitment":"2".repeat(64)}});
    let response = BackupResponse::decode(&serde_json::to_vec(&wire).expect("response bytes"))
        .expect("verified response");
    assert!(response.encode().is_ok());
    let mut invalid = response.clone();
    invalid.verification_report = None;
    assert!(invalid.encode().is_err());
    invalid = response.clone();
    invalid.verification_report_checksum = Some("3".repeat(64));
    assert!(invalid.encode().is_err());
    invalid = response;
    invalid.cleanup_pending = true;
    assert!(invalid.encode().is_err());
}
