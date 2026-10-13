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
