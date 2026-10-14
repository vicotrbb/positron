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
