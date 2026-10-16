use positron_api::tenant_purge::{TenantPurgeRequest, TenantPurgeResponse};
#[test]
fn tenant_purge_requires_explicit_confirmation_and_stable_mutation_identity() {
    let valid = br#"{"action":"start","tenant_id":"41414141-4141-4141-4141-414141414141","confirmation_slug":"example","expected_catalog_generation":7,"expected_lifecycle_generation":2,"idempotency_key":"41414141-4141-4141-4141-414141414141"}"#;
    let request = TenantPurgeRequest::decode(valid).expect("complete purge authorization");
    assert_eq!(
        TenantPurgeRequest::decode(&request.encode().expect("encode")).expect("decode"),
        request
    );
    for invalid in [
        br#"{"action":"start"}"#.as_slice(),
        br#"{"action":"status"}"#,
        br#"{"action":"lookup","operation_id":"41414141414141414141414141414141"}"#,
        br#"{"action":"status","operation_id":"41414141414141414141414141414141","unknown":true}"#,
    ] {
        assert!(TenantPurgeRequest::decode(invalid).is_err());
    }
    assert!(TenantPurgeRequest::decode(&vec![b' '; 4097]).is_err());
}
#[test]
fn tenant_purge_response_keeps_managed_scope_explicit() {
    let valid = br#"{"catalog_generation":7,"managed_scope":"managed_repositories_only;unmanaged_copies_not_revoked"}"#;
    let response = TenantPurgeResponse::decode(valid).expect("scope response");
    assert!(response.encode().is_ok());
    assert!(
        TenantPurgeResponse::decode(
            br#"{"catalog_generation":7,"managed_scope":"all_copies_revoked"}"#
        )
        .is_err()
    );
}

#[test]
fn tenant_purge_inspection_lookup_and_cancellation_reject_inapplicable_authority() {
    for valid in [
        br#"{"action":"status","operation_id":"41414141414141414141414141414141"}"#.as_slice(),
        br#"{"action":"lookup","idempotency_key":"41414141-4141-4141-4141-414141414141"}"#,
        br#"{"action":"cancel","operation_id":"41414141414141414141414141414141","expected_catalog_generation":7,"idempotency_key":"41414141-4141-4141-4141-414141414141"}"#,
    ] {
        let request = TenantPurgeRequest::decode(valid).expect("valid durable operation action");
        assert_eq!(TenantPurgeRequest::decode(&request.encode().expect("encode")).expect("decode"), request);
    }
    for invalid in [
        br#"{"action":"status","operation_id":"00000000000000000000000000000000"}"#.as_slice(),
        br#"{"action":"status","operation_id":"41414141414141414141414141414141","expected_catalog_generation":7}"#,
        br#"{"action":"lookup","idempotency_key":"not-an-id"}"#,
        br#"{"action":"cancel","operation_id":"41414141414141414141414141414141","expected_catalog_generation":0,"idempotency_key":"41414141-4141-4141-4141-414141414141"}"#,
        br#"{"action":"start","tenant_id":"41414141414141414141414141414141","confirmation_slug":"example","expected_catalog_generation":7,"expected_lifecycle_generation":2,"idempotency_key":"41414141-4141-4141-4141-414141414141"}"#,
        br#"{"action":"start","tenant_id":"41414141-4141-4141-4141-414141414141","confirmation_slug":"Example","expected_catalog_generation":7,"expected_lifecycle_generation":2,"idempotency_key":"41414141-4141-4141-4141-414141414141"}"#,
        br#"{"action":"start","tenant_id":"41414141-4141-4141-4141-414141414141","confirmation_slug":"example","expected_catalog_generation":7,"expected_lifecycle_generation":0,"idempotency_key":"41414141-4141-4141-4141-414141414141"}"#,
    ] {
        assert!(TenantPurgeRequest::decode(invalid).is_err());
    }
    assert!(TenantPurgeResponse::decode(&vec![b' '; 4097]).is_err());
}
