use positron_api::repository::RepositoryRequest;
#[test]
fn repository_requests_are_bounded_and_action_specific() -> Result<(), Box<dyn std::error::Error>> {
    let init = br#"{"action":"init","repository_id":"11111111-1111-4111-8111-111111111111","locator":"/protected/repository","expected_catalog_generation":7,"idempotency_key":"22222222-2222-4222-8222-222222222222"}"#;
    let request = RepositoryRequest::decode(init)?;
    assert_eq!(RepositoryRequest::decode(&request.encode()?)?, request);
    for bytes in [
        br#"{"action":"doctor","locator":"/protected/repository"}"#.as_slice(),
        br#"{"action":"status","locator":"/protected/repository"}"#,
        br#"{"action":"status","credential":"secret"}"#,
        br#"{"action":"status","action":"doctor"}"#,
        br#"{"action":"status","operation_id":"00000000000000000000000000000000"}"#,
    ] {
        assert!(RepositoryRequest::decode(bytes).is_err());
    }
    assert!(!format!("{request:?}").contains("/protected/repository"));
    Ok(())
}

#[test]
fn structured_aws_target_roundtrips_without_serialized_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    let bytes = br#"{"action":"doctor","expected_catalog_generation":1,"idempotency_key":"00000000-0000-0000-0000-000000000001","repository_id":"00000000-0000-0000-0000-000000000002","aws_s3":{"bucket":"positron-example","region":"us-east-1","endpoint":"https://s3.us-east-1.amazonaws.com","expected_owner":"123456789012","prefix":"diagnostic/"}}"#;
    let request = positron_api::repository::RepositoryRequest::decode(bytes)?;
    assert_eq!(
        request
            .aws_s3
            .as_ref()
            .ok_or("missing native target")?
            .bucket,
        "positron-example"
    );
    assert_eq!(
        positron_api::repository::RepositoryRequest::decode(&request.encode()?)?,
        request
    );
    let with_secret = std::str::from_utf8(bytes)?.replace(
        "\"bucket\":",
        "\"secret_access_key\":\"must-not-be-accepted\",\"bucket\":",
    );
    assert!(positron_api::repository::RepositoryRequest::decode(with_secret.as_bytes()).is_err());
    let both = std::str::from_utf8(bytes)?.replace(
        "\"action\":",
        "\"locator\":\"/protected/local\",\"action\":",
    );
    assert!(positron_api::repository::RepositoryRequest::decode(both.as_bytes()).is_err());
    assert!(!format!("{request:?}").contains("123456789012"));
    Ok(())
}

#[test]
fn policy_receipts_preserve_unknown_controls_and_reject_false_absence()
-> Result<(), Box<dyn std::error::Error>> {
    let bytes = br#"{"catalog_generation":7,"operation":{"id":"11111111111111111111111111111111","status":"succeeded","phase":"published","progress_percent":100,"retry":"never","cancellation":"not_allowed_after_drain","irreversible_boundary":"catalog_generation_published"},"policy":{"observed_at_unix_seconds":25,"versioning":{"state":"observed","value":"enabled"},"object_lock":{"state":"unavailable","failure":"permission_denied"},"lifecycle":{"state":"unobservable"}}}"#;
    let receipt = positron_api::repository::RepositoryResponse::decode(bytes)?;
    assert_eq!(
        receipt.policy.as_ref().ok_or("policy")?.object_lock.state,
        "unavailable"
    );
    assert_eq!(
        positron_api::repository::RepositoryResponse::decode(&receipt.encode()?)?,
        receipt
    );
    for invalid in [
        std::str::from_utf8(bytes)?.replace(
            "\"failure\":\"permission_denied\"",
            "\"failure\":\"permission_denied\",\"value\":\"disabled\"",
        ),
        std::str::from_utf8(bytes)?.replace("\"value\":\"enabled\"", "\"value\":\"arbitrary\""),
        std::str::from_utf8(bytes)?.replace("\"state\":\"unobservable\"", "\"state\":\"observed\""),
        std::str::from_utf8(bytes)?.replace("\"status\":\"succeeded\"", "\"status\":\"running\""),
    ] {
        assert!(positron_api::repository::RepositoryResponse::decode(invalid.as_bytes()).is_err());
    }
    Ok(())
}

#[test]
fn azure_selector_matches_canonical_additive_contract() -> Result<(), Box<dyn std::error::Error>> {
    let request=RepositoryRequest::decode(br#"{"action":"verify","expected_catalog_generation":1,"idempotency_key":"00000000-0000-0000-0000-000000000001","repository_id":"00000000-0000-0000-0000-000000000002","azure_blob":{"account":"positronbackup","container":"backups","prefix":"owned/"}}"#)?;
    assert_eq!(RepositoryRequest::decode(&request.encode()?)?, request);
    let mut oversized = request.clone();
    oversized.azure_blob.as_mut().ok_or("target")?.prefix = "x".repeat(513);
    assert!(oversized.encode().is_err());
    let with_secret = String::from_utf8(request.encode()?)?.replace(
        "\"account\":",
        "\"account_key\":\"credential-canary\",\"account\":",
    );
    assert!(RepositoryRequest::decode(with_secret.as_bytes()).is_err());
    let mapping: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/http.json"))?;
    assert!(mapping.to_string().contains("RepositoryAzureBlobTarget"));
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/openapi.json"))?;
    assert_eq!(
        schema["components"]["schemas"]["RepositoryRequest"]["properties"]["azure_blob"]["$ref"],
        "#/components/schemas/RepositoryAzureBlobTarget"
    );
    assert!(
        include_str!("../../../api/positron/v1/positron.proto")
            .contains("optional RepositoryAzureBlobTarget azure_blob = 9;")
    );
    Ok(())
}
