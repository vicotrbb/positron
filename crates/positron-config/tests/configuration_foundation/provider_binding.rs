#[test]
fn provider_identity_changes_are_audited_restart_required_and_never_render_credentials()
-> Result<(), Box<dyn Error>> {
    let cases = [
        ("aws-standard-chain", "arn:aws:kms:us-east-1:123456789012:key/root-a", "immutable", "", "root-a", "root-b"),
        ("google-application-default", "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1", "1", "", "version = '1'", "version = '2'"),
        ("azure-managed-identity", "https://example.vault.azure.net/keys/root/version", "version", "client_id = 'binding-canary-a'\n", "binding-canary-a", "binding-canary-b"),
        ("azure-managed-identity", "https://example.vault.azure.net/keys/root/version", "version", "object_id = 'binding-canary-a'\n", "binding-canary-a", "binding-canary-b"),
        ("azure-managed-identity", "https://example.vault.azure.net/keys/root/version", "version", "resource_id = 'binding-canary-a'\n", "binding-canary-a", "binding-canary-b"),
        ("azure-workload-identity", "https://example.vault.azure.net/keys/root/version", "version", "tenant_id = 'tenant'\nclient_id = 'client'\ntoken_file = '/protected/binding-canary-a'\n", "binding-canary-a", "binding-canary-b"),
        ("azure-workload-identity", "https://example.vault.azure.net/keys/root/version", "version", "", "version = 'version'", "version = 'next-version'"),
        ("vault-token", "https://transit.example/v1/transit/keys/root", "1", "token_file = '/protected/binding-canary-a'\n", "binding-canary-a", "binding-canary-b"),
        ("openbao-token", "https://transit.example/v1/transit/keys/root", "1", "token_file = '/protected/token'\ntrust_roots_file = '/protected/binding-canary-a'\n", "binding-canary-a", "binding-canary-b"),
        ("vault-kubernetes", "https://transit.example/v1/transit/keys/root", "1", "role = 'binding-canary-a'\njwt_file = '/protected/jwt'\nmount = 'kubernetes'\n", "binding-canary-a", "binding-canary-b"),
        ("openbao-kubernetes", "https://transit.example/v1/transit/keys/root", "1", "role = 'role'\njwt_file = '/protected/binding-canary-a'\nmount = 'kubernetes'\ntrust_roots_file = '/protected/ca'\n", "binding-canary-a", "binding-canary-b"),
        ("vault-jwt", "https://transit.example/v1/transit/keys/root", "1", "role = 'role'\njwt_file = '/protected/jwt'\nmount = 'binding-canary-a'\n", "binding-canary-a", "binding-canary-b"),
        ("openbao-jwt", "https://transit.example/v1/transit/keys/root", "1", "role = 'role'\njwt_file = '/protected/jwt'\nmount = 'jwt'\ntrust_roots_file = '/protected/binding-canary-a'\n", "binding-canary-a", "binding-canary-b"),
    ];
    for (mode, uri, version, selectors, before, after) in cases {
        let document = format!("schema_version = 1\n[security.provider_access]\nuri = '{uri}'\nversion = '{version}'\nauthentication = '{mode}'\n{selectors}");
        assert_eq!(document.matches(before).count(), 1, "one changed input per case");
        let current = resolve(inputs(Some(&document), [], [])?)?;
        let candidate = resolve(inputs(Some(&document.replacen(before, after, 1)), [], [])?)?;
        assert_ne!(current.audit_binding_digest(), candidate.audit_binding_digest(), "{mode}");
        let diff = current.semantic_diff(&candidate);
        assert_eq!(diff.changes().len(), 1, "{mode}");
        let change = &diff.changes()[0];
        assert_eq!(change.setting().path(), "security.provider_access");
        assert!(change.before() == "<redacted>" && change.after() == "<redacted>",
            "provider difference exposed an unredacted value");
        assert_eq!(change.before_source(), Some(SettingSource::ConfigurationFile));
        assert_eq!(change.after_source(), Some(SettingSource::ConfigurationFile));
        assert_eq!(diff.plan(), positron_config::ConfigurationDiffPlan::RestartRequired);
        assert!(matches!(current.plan_update(&candidate)?, ConfigurationPlan::RestartRequired { changed }
            if changed == [Setting::SecurityProviderAccess]));
        for rendered in [format!("{diff:?}"), format!("{candidate:?}"), candidate.redacted_effective()] {
            assert!(!rendered.contains("binding-canary"), "protected selector or reference leaked");
            assert!(!rendered.contains(uri), "provider locator leaked");
        }
        assert!(candidate.semantic_diff(&candidate).changes().is_empty());
    }
    Ok(())
}
