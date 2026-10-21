use positron_config::{CommandLineOverrides, ConfigurationInputs, EnvironmentOverrides, resolve};
#[test]
fn operator_installed_release_references_resolve_through_canonical_configuration() {
    let document = "schema_version = 1\n[release.installation]\nproject_trust_root_file = '/release/root.pub'\ncurrent_manifest_file = '/release/current.manifest'\ncandidate_manifest_file = '/release/candidate.manifest'\ncandidate_artifact_files = ['/release/native', '/release/schema']\n";
    let inputs = ConfigurationInputs::try_new(
        Some(document),
        EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0]).expect("environment"),
        CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0]).expect("CLI"),
    )
    .expect("inputs");
    assert!(resolve(inputs).is_ok());
}

fn configuration(
    document: &str,
) -> Result<positron_config::EffectiveConfiguration, positron_config::ConfigurationFailure> {
    resolve(ConfigurationInputs::try_new(
        Some(document),
        EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])?,
        CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
    )?)
}
#[test]
fn installed_release_requires_complete_closed_operator_owned_references() {
    let base = "schema_version=1\n[release.installation]\nproject_trust_root_file='/release/root'\ncurrent_manifest_file='/release/current'\n";
    for extra in [
        "unknown='value'\n",
        "candidate_manifest_file='/release/next'\n",
        "candidate_artifact_files=['/release/native']\n",
        "query_credential_file='relative/key'\n",
        "candidate_manifest_file='/release/next'\ncandidate_artifact_files=['/release/../a']\n",
    ] {
        assert!(configuration(&format!("{base}{extra}")).is_err());
    }
    for document in [
        "schema_version=1\n[release.installation]\ncurrent_manifest_file='/release/current'\n",
        "schema_version=1\n[release.installation]\nproject_trust_root_file='/release/root'\n",
    ] {
        assert!(configuration(document).is_err());
    }
    let files = std::iter::repeat_n("'/release/a'", 65)
        .collect::<Vec<_>>()
        .join(",");
    assert!(
        configuration(&format!(
            "{base}candidate_manifest_file='/release/next'\ncandidate_artifact_files=[{files}]\n"
        ))
        .is_err()
    );
    let current = configuration("schema_version=1\n").expect("ordinary configuration");
    assert!(current.installed_release().is_none());
    let installed = configuration(base).expect("installed configuration");
    let release = installed.installed_release().expect("release references");
    assert_eq!(
        release.project_trust_root_file().as_path(),
        std::path::Path::new("/release/root")
    );
    assert!(release.candidate_manifest_file().is_none());
    assert!(release.query_credential_file().is_none());
    assert!(matches!(
        current.plan_update(&installed),
        Ok(positron_config::ConfigurationPlan::RestartRequired { .. })
    ));
    assert!(!installed.redacted_effective().contains("/release/root"));
    assert_ne!(
        current.audit_binding_digest(),
        installed.audit_binding_digest()
    );
}
#[test]
fn request_environment_cannot_replace_installed_project_trust() {
    let environment = EnvironmentOverrides::try_from_pairs([(
        "POSITRON__RELEASE__INSTALLATION",
        "requester-root",
    )])
    .expect("bounded override");
    let inputs = ConfigurationInputs::try_new(
        Some("schema_version=1\n"),
        environment,
        CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0]).expect("CLI"),
    )
    .expect("inputs");
    assert!(resolve(inputs).is_err());
}
#[test]
fn complete_candidate_inventory_keeps_each_path_bounded_without_the_unrelated_small_array_limit() {
    let files = (0..5)
        .map(|index| format!("'/release/{}/{index}'", "x".repeat(180)))
        .collect::<Vec<_>>()
        .join(",");
    let doc = format!(
        "schema_version=1\n[release.installation]\nproject_trust_root_file='/release/root'\ncurrent_manifest_file='/release/current'\ncandidate_manifest_file='/release/next'\ncandidate_artifact_files=[{files}]\n"
    );
    assert!(configuration(&doc).is_ok());
}
#[test]
fn independently_signed_artifact_records_may_reference_the_same_operator_owned_file() {
    let doc = "schema_version=1\n[release.installation]\nproject_trust_root_file='/release/root'\ncurrent_manifest_file='/release/current'\ncandidate_manifest_file='/release/next'\ncandidate_artifact_files=['/release/shared','/release/shared']\n";
    assert!(configuration(doc).is_ok());
}

#[test]
fn full_release_startup_can_reference_the_current_authenticated_inventory()
-> Result<(), Box<dyn std::error::Error>> {
    let inputs = positron_config::ConfigurationInputs::try_new(
        Some(
            "schema_version=1\n[release.installation]\nproject_trust_root_file='/release/trust.json'\ncurrent_manifest_file='/release/current.manifest'\ncurrent_inventory_file='/release/current.inventory'\n",
        ),
        positron_config::EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])?,
        positron_config::CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
    )?;
    assert_eq!(
        positron_config::resolve(inputs)?
            .installed_release()
            .ok_or("release")?
            .current_inventory_file()
            .ok_or("inventory")?
            .as_path(),
        std::path::Path::new("/release/current.inventory")
    );
    Ok(())
}
#[test]
fn nix_executable_distribution_is_explicit_and_closed() {
    let base = "schema_version=1\n[release.installation]\nproject_trust_root_file='/release/root'\ncurrent_manifest_file='/release/current'\n";
    assert_eq!(
        configuration(base)
            .unwrap()
            .installed_release()
            .unwrap()
            .executable_distribution(),
        positron_config::ExecutableDistribution::Native
    );
    for selected in ["native", "nix"] {
        assert!(configuration(&format!("{base}executable_distribution='{selected}'\n")).is_ok());
    }
    let default = configuration(base).unwrap();
    let native = configuration(&format!("{base}executable_distribution='native'\n")).unwrap();
    let nix = configuration(&format!("{base}executable_distribution='nix'\n")).unwrap();
    assert_eq!(
        default.audit_binding_digest(),
        native.audit_binding_digest()
    );
    assert_ne!(default.audit_binding_digest(), nix.audit_binding_digest());
    for selected in ["", "auto", "Nix", "linux"] {
        assert!(configuration(&format!("{base}executable_distribution='{selected}'\n")).is_err());
    }
}
