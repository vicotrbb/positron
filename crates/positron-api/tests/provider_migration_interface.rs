use positron_api::provider_migration::ProviderMigrationRequest;

#[test]
fn migration_wire_requires_exact_mutation_identity_and_protected_reference() {
    let request = br#"{"action":"prepare","expected_catalog_generation":7,"idempotency_key":"41414141-4141-4141-4141-414141414141","configuration_reference":"/protected/target.toml"}"#;
    assert!(ProviderMigrationRequest::decode(request).is_ok());
    for invalid in [
        br#"{"action":"prepare"}"#.as_slice(),
        br#"{"action":"status","expected_catalog_generation":7}"#,
        br#"{"action":"prepare","expected_catalog_generation":7,"idempotency_key":"41414141-4141-4141-4141-414141414141","configuration_reference":"relative.toml"}"#,
        br#"{"action":"status","credential":"secret"}"#,
    ] {
        assert!(ProviderMigrationRequest::decode(invalid).is_err());
    }
    assert!(ProviderMigrationRequest::decode(&vec![b' '; 4097]).is_err());
}

#[test]
fn migration_wire_preserves_the_published_backup_registry_boundary() {
    let bytes = br#"{"catalog_generation":7,"root_phase":"verifying","active_epoch":2,"predecessor_epoch":1,"active_provider":{"family":1,"locator":"local-root/target","version":"2"},"source_provider":{"family":1,"locator":"local-root/source","version":"1"},"operation":{"id":"41414141414141414141414141414141","status":"running","phase":"draining","progress_percent":25,"retry":"inspect_by_operation_id","cancellation":"not_allowed_after_drain","irreversible_boundary":"backup_registry_published","lookup_expires_at_unix_seconds":null}}"#;
    let response = positron_api::provider_migration::ProviderMigrationResponse::decode(bytes)
        .expect("published backup Registry must remain inspectable");
    assert_eq!(
        response
            .operation
            .as_ref()
            .map(|op| op.irreversible_boundary.as_str()),
        Some("backup_registry_published")
    );
    assert!(response.encode().is_ok());
}
