#[test]
fn provider_access_table_whitespace_preserves_the_declared_locator_bound()
-> Result<(), Box<dyn Error>> {
    let uri = format!("https://transit.example/v1/transit/keys/{}", "a".repeat(300));
    for header in ["[security.provider_access]", "[ security.provider_access ]"] {
        let document = format!(
            "schema_version = 1\n{header}\nuri = '{uri}'\nversion = '1'\nauthentication = 'vault-token'\ntoken_file = '/protected/token'\n"
        );
        let effective = resolve(inputs(Some(&document), [], [])?)?;
        assert_eq!(effective.provider_access().ok_or("provider access")?.uri(), uri);
    }
    Ok(())
}

#[test]
fn native_provider_access_is_typed_protected_and_restart_required() -> Result<(), Box<dyn Error>> {
    let document = "schema_version = 1\n[security.provider_access]\nuri = 'kmip://localhost:5696/objects/immutable-id'\nversion = 'sha256:0606060606060606060606060606060606060606060606060606060606060606'\nauthentication = 'kmip-mtls'\ncertificate_file = '/protected/client.pem'\nprivate_key_file = '/protected/key.pem'\ntrust_roots_file = '/protected/ca.pem'\n";
    let effective = resolve(inputs(Some(document), [], [])?)?;
    assert!(effective.provider_access().is_some());
    assert!(!format!("{effective:?}").contains("/protected"));
    assert!(!effective.redacted_effective().contains("/protected"));
    assert_eq!(
        Setting::SecurityProviderAccess.mutability(),
        MutabilityClass::RestartRequired
    );
    let defaults = resolve(inputs(None, [], [])?)?;
    assert!(defaults.provider_access().is_none());
    assert!(matches!(
        defaults.plan_update(&effective)?,
        ConfigurationPlan::RestartRequired { .. }
    ));
    let changed = resolve(inputs(
        Some(&document.replace("/protected/key.pem", "/protected/renewed.pem")),
        [],
        [],
    )?)?;
    assert_ne!(
        effective.audit_binding_digest(),
        changed.audit_binding_digest()
    );
    let diff = effective.semantic_diff(&changed);
    assert!(!format!("{diff:?}").contains("/protected"));
    assert!(
        resolve(inputs(
            Some(document),
            [("POSITRON__SECURITY__PROVIDER_ACCESS", "secret")],
            []
        )?)
        .is_err()
    );
    for extra in [
        "token = 'secret'",
        "token_file = '/protected/token'",
        "family = 'kmip'",
    ] {
        assert!(resolve(inputs(Some(&format!("{document}{extra}\n")), [], [])?).is_err());
    }
    Ok(())
}

#[test]
fn azure_managed_identity_selectors_are_exclusive_and_nonsecret() -> Result<(), Box<dyn Error>> {
    let base = "schema_version = 1\n[security.provider_access]\nuri = 'https://example.vault.azure.net/keys/root/0123456789abcdef0123456789abcdef'\nversion = '0123456789abcdef0123456789abcdef'\nauthentication = 'azure-managed-identity'\n";
    for field in ["client_id", "object_id", "resource_id"] {
        let document = format!("{base}{field} = 'nonsecret-identity-selector'\n");
        let configured = resolve(inputs(Some(&document), [], [])?)?;
        assert!(configured.provider_access().is_some());
        assert!(
            !configured
                .redacted_effective()
                .contains("nonsecret-identity-selector")
        );
        assert!(matches!(
            resolve(inputs(Some(base), [], [])?)?.plan_update(&configured)?,
            ConfigurationPlan::RestartRequired { .. }
        ));
        for other in ["client_id", "object_id", "resource_id"] {
            if field != other {
                assert!(
                    resolve(inputs(
                        Some(&format!("{document}{other} = 'ambiguous'\n")),
                        [],
                        []
                    )?)
                    .is_err()
                );
            }
        }
    }
    Ok(())
}

#[test]
fn transit_protected_token_access_has_no_renewable_authentication_mount()
-> Result<(), Box<dyn Error>> {
    for mode in ["vault-token", "openbao-token"] {
        let document = format!(
            "schema_version = 1\n[security.provider_access]\nuri = 'https://transit.example:8200/v1/transit/keys/root'\nversion = '1'\nauthentication = '{mode}'\ntoken_file = '/protected/token'\n"
        );
        assert!(
            resolve(inputs(Some(&document), [], [])?)?
                .provider_access()
                .is_some()
        );
        assert!(
            resolve(inputs(
                Some(&format!("{document}mount = 'unrelated-auth'\n")),
                [],
                []
            )?)
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn provider_credential_references_follow_the_canonical_protected_path_policy()
-> Result<(), Box<dyn Error>> {
    let base = "schema_version = 1\n[security.provider_access]\nuri = 'https://transit.example:8200/v1/transit/keys/root'\nversion = '1'\nauthentication = 'vault-token'\n";
    let accepted = format!("{base}token_file = '/protected credentials/token'\n");
    let effective = resolve(inputs(Some(&accepted), [], [])?)?;
    assert!(effective.provider_access().is_some());
    assert!(
        !effective
            .redacted_effective()
            .contains("protected credentials")
    );
    for path in [
        "relative/token",
        "/protected/../token",
        "/protected\u{7f}/token",
    ] {
        let document = format!("{base}token_file = '{path}'\n");
        assert!(resolve(inputs(Some(&document), [], [])?).is_err());
    }
    Ok(())
}
