use super::*;
use std::path::Path;

#[test]
fn plaintext_bundle_uses_the_canonical_explicit_warning_flag() {
    let parsed = BundleOptions::parse(
        [
            "bundle",
            "create",
            "--config",
            "positron.toml",
            "--output",
            "bundle.tar",
            "--allow-plaintext-bundle",
            "--credential-stdin",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    let Ok(options) = parsed else {
        panic!("canonical plaintext flag must parse");
    };
    assert!(options.plaintext_warning);
    assert!(options.recipients.is_empty());
}

#[test]
fn output_preparation_refuses_a_managed_root_before_descending_to_the_output_parent()
-> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-support-root-output-{nonce}"));
    let secrets = root.join("secrets");
    let external = root.join("external");
    fs::create_dir_all(&secrets)?;
    fs::create_dir_all(&external)?;
    let output = external.join("bundle.age");

    for (data_root, secrets_root) in [
        (Path::new("/"), secrets.as_path()),
        (secrets.as_path(), Path::new("/")),
    ] {
        assert!(matches!(
            super::super::output::prepare_destination(&output, data_root, secrets_root),
            Err(super::super::output::OutputPreparationFailure::InvalidDestination)
        ));
    }
    assert!(!output.exists());
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn online_opaque_artifact_report_never_claims_a_verified_instance_signature() {
    let report = super::super::command::online_bundle_report();
    assert!(report.contains("format=age_encrypted_opaque_bundle"));
    assert!(report.contains("artifact_authentication=unverified_control_response"));
    assert!(report.contains("signature=unverified"));
    assert!(!report.contains("signature=signed"));
}

#[test]
fn typed_bundle_configuration_redaction_hides_paths_and_listener_addresses()
-> Result<(), Box<dyn std::error::Error>> {
    let inputs = positron_config::ConfigurationInputs::try_new(
        Some(
            "schema_version = 1\n\
             [listener]\n\
             control_path = \"/run/customer/control.sock\"\n\
             operations_bind_address = \"10.20.30.40:42001\"\n\
             api_bind_address = \"10.20.30.41:42002\"\n\
             [storage]\n\
             data_directory = \"/srv/customer/data\"\n\
             secrets_directory = \"/srv/customer/data/keys\"\n",
        ),
        positron_config::EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])
            .map_err(|_| "environment overrides")?,
        positron_config::CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])
            .map_err(|_| "command-line overrides")?,
    )
    .map_err(|_| "configuration inputs")?;
    let effective = positron_config::resolve(inputs).map_err(|_| "effective configuration")?;
    let pseudonyms = super::super::privacy::Pseudonymizer::new();
    let rendered = effective
        .redacted_for_support_bundle(|class, value| {
            if class == positron_config::SupportBundleIdentifierClass::DataDirectory {
                Ok::<_, ()>(value.to_owned())
            } else {
                pseudonyms.pseudonymize(value)
            }
        })
        .map_err(|_| "pseudonymize configuration")?;

    for private_identifier in [
        "/run/customer/control.sock",
        "10.20.30.40:42001",
        "10.20.30.41:42002",
        "/srv/customer/data/keys",
    ] {
        assert!(
            !rendered.contains(private_identifier),
            "typed bundle rendering must not leak {private_identifier}"
        );
    }
    assert!(rendered.contains("/srv/customer/data"));
    assert!(rendered.contains("id-"));
    Ok(())
}

#[test]
fn bundle_parser_rejects_elapsed_limits_outside_the_documented_window() {
    for seconds in ["31", "18446744073709551615"] {
        let result = super::super::options::BundleOptions::parse(
            [
                "bundle",
                "create",
                "--config",
                "positron.toml",
                "--output",
                "bundle.age",
                "--recipient",
                "age1example",
                "--credential-stdin",
                "--max-elapsed-seconds",
                seconds,
            ]
            .into_iter()
            .map(str::to_owned),
        );
        assert!(
            matches!(result, Err(super::super::options::BundleFailure::Arguments)),
            "elapsed limit {seconds} must be rejected before credential, source, or output work"
        );
    }
}

#[test]
fn bundle_parser_accepts_only_the_bounded_diagnostic_log_window() {
    for seconds in ["0", "301", "18446744073709551615"] {
        let result = BundleOptions::parse(
            [
                "bundle",
                "create",
                "--config",
                "positron.toml",
                "--output",
                "bundle.age",
                "--recipient",
                "age1example",
                "--credential-stdin",
                "--log-window-seconds",
                seconds,
            ]
            .into_iter()
            .map(str::to_owned),
        );
        assert!(
            matches!(result, Err(super::super::options::BundleFailure::Arguments)),
            "log window {seconds} must be rejected before credential, source, or output work"
        );
    }

    for seconds in ["1", "300"] {
        let result = BundleOptions::parse(
            [
                "bundle",
                "create",
                "--config",
                "positron.toml",
                "--output",
                "bundle.age",
                "--recipient",
                "age1example",
                "--credential-stdin",
                "--log-window-seconds",
                seconds,
            ]
            .into_iter()
            .map(str::to_owned),
        );
        assert!(result.is_ok(), "log window {seconds} must remain accepted");
    }
}

#[test]
fn identifier_retention_is_closed_and_never_available_to_key_unavailable_exports() {
    let retained = BundleOptions::parse(
        [
            "bundle",
            "create",
            "--config",
            "positron.toml",
            "--output",
            "bundle.tar",
            "--recipient",
            "age1example",
            "--credential-stdin",
            "--retain-identifier",
            "data_directory",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    let Ok(retained) = retained else {
        panic!("current authenticated system administration may request data directory retention");
    };
    assert_eq!(
        retained.identifier_retention,
        super::super::privacy::IdentifierRetention::DataDirectory
    );
    assert!(
        BundleOptions::parse(
            [
                "bundle",
                "create",
                "--config",
                "positron.toml",
                "--output",
                "bundle.tar",
                "--recipient",
                "age1example",
                "--offline-key-unavailable",
                "--retain-identifier",
                "data_directory",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .is_err()
    );
    assert!(
        BundleOptions::parse(
            [
                "bundle",
                "create",
                "--config",
                "positron.toml",
                "--output",
                "bundle.tar",
                "--recipient",
                "age1example",
                "--credential-stdin",
                "--retain-identifier",
                "secrets_directory",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .is_err()
    );
}

#[test]
fn output_limit_is_limited_to_the_canonical_live_transport_bound() {
    let arguments = [
        "bundle",
        "create",
        "--config",
        "positron.toml",
        "--output",
        "bundle.age",
        "--recipient",
        "age1example",
        "--credential-stdin",
        "--max-output-bytes",
        &usize::MAX.to_string(),
    ];
    assert!(BundleOptions::parse(arguments.into_iter().map(str::to_owned)).is_err());

    let valid = BundleOptions::parse(
        [
            "bundle",
            "create",
            "--config",
            "positron.toml",
            "--output",
            "bundle.age",
            "--recipient",
            "age1example",
            "--credential-stdin",
            "--max-output-bytes",
            "1048576",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    assert!(
        valid.is_ok(),
        "the canonical bounded live limit remains valid"
    );
}

#[test]
fn explicit_plaintext_export_is_owner_only_and_never_overwrites() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("positron-support-{nonce}"));
    let data = root.join("data");
    let secrets = root.join("secrets");
    let external = root.join("external");
    fs::create_dir_all(&data).expect("data root");
    fs::create_dir_all(&secrets).expect("secrets root");
    fs::create_dir_all(&external).expect("external root");
    let path = external.join("bundle.tar");
    let destination = super::super::output::prepare_destination(&path, &data, &secrets)
        .expect("validated destination");
    let bundle = SupportBundle::build_for_explicit_plaintext(
        [BundleMember::doctor_report(b"safe")],
        BundleLimits::new(1, 12_000).expect("limits"),
    )
    .expect("bundle");
    bundle
        .write_plaintext_explicitly(&destination)
        .expect("new owner-only output");
    assert!(bundle.redaction_report().plaintext_warning());
    assert!(
        bundle
            .archive()
            .windows(b"plaintext_export_warning=true".len())
            .any(|entry| entry == b"plaintext_export_warning=true")
    );
    assert_eq!(fs::read(&path).expect("archive"), bundle.archive());
    assert!(bundle.write_plaintext_explicitly(&destination).is_err());
    #[cfg(unix)]
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(
            &fs::metadata(&path).expect("metadata").permissions()
        ) & 0o777,
        0o600
    );
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn encrypted_external_export_is_owner_only_and_never_overwrites()
-> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-support-encrypted-output-{nonce}"));
    let output_root = root.join("external");
    fs::create_dir_all(&output_root)?;
    let output = output_root.join("bundle.age");
    let data = root.join("data");
    let secrets = root.join("secrets");
    fs::create_dir_all(&data)?;
    fs::create_dir_all(&secrets)?;
    let destination = super::super::output::prepare_destination(&output, &data, &secrets)
        .map_err(|_| "destination")?;
    let bundle = SupportBundle::build_authenticated(
        [BundleMember::doctor_report(b"safe")],
        BundleLimits::new(1, 12_000).map_err(|_| "limits")?,
        super::super::ManifestAuthentication::UnsignedKeyUnavailableOffline,
    )
    .map_err(|_| "bundle")?;
    let identity = age::x25519::Identity::generate();
    let ciphertext = AgeRecipients::parse([identity.to_public().to_string()])
        .map_err(|_| "recipient")?
        .encrypt(bundle.archive())
        .map_err(|_| "encrypt")?;
    bundle
        .write_encrypted(&destination, &ciphertext)
        .map_err(|_| "write")?;
    assert_eq!(fs::read(&output)?, ciphertext);
    assert!(bundle.write_encrypted(&destination, &ciphertext).is_err());
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn bundle_output_refuses_data_and_secrets_roots_through_relative_and_symlink_aliases()
-> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-support-output-root-{nonce}"));
    let data = root.join("data");
    let secrets = root.join("secrets");
    let external = root.join("external");
    fs::create_dir_all(&data)?;
    fs::create_dir_all(data.join("nested"))?;
    fs::create_dir_all(&secrets)?;
    fs::create_dir_all(secrets.join("nested"))?;
    fs::create_dir_all(&external)?;
    assert!(
        super::super::output::prepare_destination(&data.join("bundle.age"), &data, &secrets)
            .is_err()
    );
    assert!(
        super::super::output::prepare_destination(&data.join("nested/bundle.age"), &data, &secrets)
            .is_err()
    );
    assert!(
        super::super::output::prepare_destination(
            &secrets.join("nested/bundle.age"),
            &data,
            &secrets
        )
        .is_err()
    );
    #[cfg(unix)]
    {
        let alias = root.join("data-alias");
        std::os::unix::fs::symlink(&data, &alias)?;
        assert!(
            super::super::output::prepare_destination(&alias.join("bundle.age"), &data, &secrets)
                .is_err()
        );
    }
    assert!(
        super::super::output::prepare_destination(&external.join("bundle.age"), &data, &secrets)
            .is_ok()
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn prepared_destination_cannot_be_redirected_into_a_managed_root_by_parent_swap()
-> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-support-race-{nonce}"));
    let data = root.join("data");
    let secrets = root.join("secrets");
    let external = root.join("external");
    fs::create_dir_all(&data)?;
    fs::create_dir_all(&secrets)?;
    fs::create_dir_all(&external)?;
    let output = external.join("bundle.tar");
    let destination = super::super::output::prepare_destination(&output, &data, &secrets)
        .map_err(|_| "destination")?;
    let original_external = root.join("external-before-swap");
    fs::rename(&external, &original_external)?;
    std::os::unix::fs::symlink(&data, &external)?;

    let bundle = SupportBundle::build_for_explicit_plaintext(
        [BundleMember::doctor_report(b"safe")],
        BundleLimits::new(1, 12_000).map_err(|_| "limits")?,
    )
    .map_err(|_| "bundle")?;
    bundle
        .write_plaintext_explicitly(&destination)
        .map_err(|_| "write through held directory")?;

    assert_eq!(
        fs::read(original_external.join("bundle.tar"))?,
        bundle.archive()
    );
    assert!(fs::symlink_metadata(data.join("bundle.tar")).is_err());
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn output_preflight_rejects_a_directory_replaced_by_the_bound_data_root()
-> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-support-rename-{nonce}"));
    let data = root.join("data");
    let secrets = root.join("secrets");
    let external = root.join("external");
    fs::create_dir_all(&data)?;
    fs::create_dir_all(&secrets)?;
    fs::create_dir_all(&external)?;
    let output = external.join("bundle.tar");
    let parked_data = root.join("data-before-replace");
    let parked_external = root.join("external-before-replace");
    assert!(
        super::super::output::prepare_destination_with_after_managed_root_hook(
            &output,
            &data,
            &secrets,
            || {
                fs::rename(&data, &parked_data).expect("park data");
                fs::rename(&external, &parked_external).expect("park external");
                fs::rename(&parked_data, &external).expect("replace external with data");
                fs::create_dir(&data).expect("replacement data path");
            }
        )
        .is_err()
    );
    assert!(fs::symlink_metadata(external.join("bundle.tar")).is_err());
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn failed_publication_removes_the_plaintext_temporary_archive()
-> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-support-cleanup-{nonce}"));
    let data = root.join("data");
    let secrets = root.join("secrets");
    let external = root.join("external");
    fs::create_dir_all(&data)?;
    fs::create_dir_all(&secrets)?;
    fs::create_dir_all(&external)?;
    let output = external.join("bundle.tar");
    let destination = super::super::output::prepare_destination(&output, &data, &secrets)
        .map_err(|_| "destination")?;
    fs::write(&output, b"existing")?;
    let bundle = SupportBundle::build_for_explicit_plaintext(
        [BundleMember::doctor_report(b"safe")],
        BundleLimits::new(1, 12_000).map_err(|_| "limits")?,
    )
    .map_err(|_| "bundle")?;
    assert!(bundle.write_plaintext_explicitly(&destination).is_err());
    assert!(fs::symlink_metadata(external.join(".bundle.tar.positron-new")).is_err());
    assert_eq!(fs::read(&output)?, b"existing");
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn public_plaintext_export_does_not_publish_a_post_close_temporary_symlink()
-> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-support-swap-{nonce}"));
    let data = root.join("data");
    let secrets = root.join("secrets");
    let external = root.join("external");
    fs::create_dir_all(&data)?;
    fs::create_dir_all(&secrets)?;
    fs::create_dir_all(&external)?;
    let output = external.join("bundle.tar");
    let destination = super::super::output::prepare_destination(&output, &data, &secrets)
        .map_err(|_| "destination")?;
    let attacker = external.join("attacker.tar");
    fs::write(&attacker, b"attacker-controlled")?;
    let bundle = SupportBundle::build_for_explicit_plaintext(
        [BundleMember::doctor_report(b"safe")],
        BundleLimits::new(1, 12_000).map_err(|_| "limits")?,
    )
    .map_err(|_| "bundle")?;

    bundle
        .write_plaintext_explicitly_with_after_close_hook(&destination, || {
            std::os::unix::fs::symlink(&attacker, external.join(".bundle.tar.positron-new"))
                .expect("install former public temporary name after close");
        })
        .map_err(|_| "public export")?;

    assert_eq!(fs::read(&output)?, bundle.archive());
    assert!(!fs::symlink_metadata(&output)?.file_type().is_symlink());
    assert!(
        fs::symlink_metadata(external.join(".bundle.tar.positron-new"))?
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&attacker)?, b"attacker-controlled");
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn elapsed_deadline_prevents_plaintext_output_creation() -> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-support-deadline-{nonce}"));
    let data = root.join("data");
    let secrets = root.join("secrets");
    let external = root.join("external");
    fs::create_dir_all(&data)?;
    fs::create_dir_all(&secrets)?;
    fs::create_dir_all(&external)?;
    let output = external.join("bundle.tar");
    let destination = super::super::output::prepare_destination(&output, &data, &secrets)
        .map_err(|_| "destination")?;
    let bundle = SupportBundle::build_for_explicit_plaintext(
        [BundleMember::doctor_report(b"safe")],
        BundleLimits::new(1, 12_000).map_err(|_| "limits")?,
    )
    .map_err(|_| "bundle")?;
    let options = super::BundleOptions {
        config: std::path::PathBuf::from("unused"),
        output: output.clone(),
        recipients: Vec::new(),
        plaintext_warning: true,
        offline_key_unavailable: true,
        output_limit: 12_000,
        elapsed_limit: std::time::Duration::from_secs(1),
        log_window: std::time::Duration::from_secs(1),
        source_file_limit: 1,
        control_path: None,
        identifier_retention: super::super::privacy::IdentifierRetention::Ephemeral,
    };
    let started = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(2))
        .ok_or("clock")?;
    assert!(matches!(
        super::write_bundle(&bundle, &options, &destination, started),
        Err(super::BundleFailure::DeadlineExceeded)
    ));
    assert!(!output.exists());
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn elapsed_deadline_before_irreversible_publication_leaves_no_output()
-> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-support-publication-deadline-{nonce}"));
    let data = root.join("data");
    let secrets = root.join("secrets");
    let external = root.join("external");
    fs::create_dir_all(&data)?;
    fs::create_dir_all(&secrets)?;
    fs::create_dir_all(&external)?;
    let output = external.join("bundle.tar");
    let destination = super::super::output::prepare_destination(&output, &data, &secrets)
        .map_err(|_| "destination")?;
    let bundle = SupportBundle::build_for_explicit_plaintext(
        [BundleMember::doctor_report(b"safe")],
        BundleLimits::new(1, 12_000).map_err(|_| "limits")?,
    )
    .map_err(|_| "bundle")?;
    let options = super::BundleOptions {
        config: std::path::PathBuf::from("unused"),
        output: output.clone(),
        recipients: Vec::new(),
        plaintext_warning: true,
        offline_key_unavailable: true,
        output_limit: 12_000,
        elapsed_limit: std::time::Duration::from_secs(1),
        log_window: std::time::Duration::from_secs(1),
        source_file_limit: 1,
        control_path: None,
        identifier_retention: super::super::privacy::IdentifierRetention::Ephemeral,
    };

    assert!(matches!(
        super::write_plaintext_bundle_with_after_close_hook(
            &bundle,
            &options,
            &destination,
            std::time::Instant::now(),
            || std::thread::sleep(std::time::Duration::from_secs(2)),
        ),
        Err(super::BundleFailure::DeadlineExceeded)
    ));
    assert!(!output.exists());
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn deadline_crossing_after_publication_succeeds_without_removing_a_replacement_output()
-> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-support-cleanup-race-{nonce}"));
    let data = root.join("data");
    let secrets = root.join("secrets");
    let external = root.join("external");
    fs::create_dir_all(&data)?;
    fs::create_dir_all(&secrets)?;
    fs::create_dir_all(&external)?;
    let output = external.join("bundle.tar");
    let destination = super::super::output::prepare_destination(&output, &data, &secrets)
        .map_err(|_| "destination")?;
    let bundle = SupportBundle::build_for_explicit_plaintext(
        [BundleMember::doctor_report(b"safe")],
        BundleLimits::new(1, 12_000).map_err(|_| "limits")?,
    )
    .map_err(|_| "bundle")?;

    let options = super::BundleOptions {
        config: std::path::PathBuf::from("unused"),
        output: output.clone(),
        recipients: Vec::new(),
        plaintext_warning: true,
        offline_key_unavailable: true,
        output_limit: 12_000,
        elapsed_limit: std::time::Duration::from_secs(1),
        log_window: std::time::Duration::from_secs(1),
        source_file_limit: 1,
        control_path: None,
        identifier_retention: super::super::privacy::IdentifierRetention::Ephemeral,
    };
    super::write_bundle_with_after_publication_hook(
        &bundle,
        &options,
        &destination,
        std::time::Instant::now(),
        || {
            std::thread::sleep(std::time::Duration::from_secs(2));
            fs::remove_file(&output).expect("replace published output");
            fs::write(&output, b"attacker replacement").expect("write replacement");
        },
    )
    .map_err(|_| "post-publication deadline must not revoke successful publication")?;

    assert_eq!(fs::read(&output)?, b"attacker replacement");
    fs::remove_dir_all(root)?;
    Ok(())
}
