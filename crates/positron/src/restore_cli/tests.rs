use super::*;
#[test]
fn restore_requires_exact_public_pins_and_closed_bounded_options()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("positron-restore-cli-{}", std::process::id()));
    std::fs::create_dir(&root)?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    for name in ["data", "secrets", "source-secrets", "repo"] {
        std::fs::create_dir(root.join(name))?;
        std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(0o700))?;
    }
    let config = root.join("positron.toml");
    std::fs::write(
        &config,
        format!(
            "schema_version = 1\n[storage]\ndata_directory = {:?}\nsecrets_directory = {:?}\n",
            root.join("data"),
            root.join("secrets")
        ),
    )?;
    let custody = positron_kernel::BootstrapKeyCustody::initialize(&root.join("source-secrets"))?;
    let instance = positron_kernel::InstanceId::new([2; 16])?;
    let protected = custody.protect(
        instance,
        positron_kernel::BootstrapObjectPurpose::Initialized,
        &[7; 32],
    )?;
    let signer = custody.backup_control_signer(instance, &protected)?;
    let pin = custody.bootstrap_identity();
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let mut arguments = vec!["start".into()];
    for (key, value) in [
        ("--config", config.to_string_lossy().into_owned()),
        (
            "--locator",
            root.join("repo").to_string_lossy().into_owned(),
        ),
        ("--repository-id", hex(&[1; 16])),
        ("--snapshot-id", hex(&[3; 16])),
        ("--expected-manifest-checksum", hex(&[4; 32])),
        ("--idempotency-key", hex(&[5; 16])),
        ("--instance", hex(&instance.to_bytes())),
        ("--root-key-id", hex(&pin.key_id())),
        ("--root-fingerprint", hex(&pin.fingerprint())),
        (
            "--root-created-at",
            pin.created_at_unix_seconds().to_string(),
        ),
        (
            "--integrity-public-key",
            hex(&signer.identity().public_key()),
        ),
        (
            "--integrity-fingerprint",
            hex(&signer.identity().fingerprint()),
        ),
        (
            "--bundle",
            root.join("backup.age").to_string_lossy().into_owned(),
        ),
        (
            "--identity-file",
            root.join("identity.age").to_string_lossy().into_owned(),
        ),
    ] {
        arguments.extend([key.into(), value]);
    }
    assert!(parse(arguments.clone().into_iter()).is_ok());
    let mut json = arguments.clone();
    json.extend(["--output".into(), "json".into()]);
    assert!(
        parse(json.into_iter()).is_ok(),
        "durable restore must accept stable JSON output"
    );
    let mut invalid_output = arguments.clone();
    invalid_output.extend(["--output".into(), "xml".into()]);
    assert!(parse(invalid_output.into_iter()).is_err());

    for index in (1..arguments.len()).step_by(2) {
        let mut missing = arguments.clone();
        missing.drain(index..index + 2);
        assert!(
            parse(missing.into_iter()).is_err(),
            "required option {index}"
        );
    }
    for extra in [
        vec!["--locator", "duplicate"],
        vec!["--secret", "never accepted"],
        vec!["--bundle"],
    ] {
        let mut malformed = arguments.clone();
        malformed.extend(extra.into_iter().map(String::from));
        assert!(parse(malformed.into_iter()).is_err());
    }
    let mut oversized = arguments.clone();
    oversized.extend(["--unknown".into(), "x".repeat(4097)]);
    assert!(parse(oversized.into_iter()).is_err());
    let mut cancel = arguments.clone();
    *cancel.first_mut().ok_or("action")? = "cancel".into();
    assert!(parse(cancel.clone().into_iter()).is_err());
    cancel.extend([
        "--expected-operation-revision".into(),
        "2".into(),
        "--cancellation-key".into(),
        hex(&[6; 16]),
    ]);
    assert!(parse(cancel.into_iter()).is_ok());
    assert_eq!(std::fs::read_dir(root.join("data"))?.count(), 0);
    assert_eq!(std::fs::read_dir(root.join("secrets"))?.count(), 0);
    drop(custody);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn begin_failure_diagnostic_emits_only_the_existing_closed_code() {
    for (code, expected) in [
        (BootstrapFailureCode::CorruptState, "CorruptState"),
        (
            BootstrapFailureCode::ResourceUnavailable,
            "ResourceUnavailable",
        ),
        (
            BootstrapFailureCode::StorageUnavailable,
            "StorageUnavailable",
        ),
        (BootstrapFailureCode::IdentityMismatch, "IdentityMismatch"),
    ] {
        let mut diagnostic = Vec::new();
        assert_eq!(
            report_begin_failure(code, &mut diagnostic),
            "restore unavailable; require a fresh target or the exact accepted restore identity and sufficient admitted resources"
        );
        assert_eq!(
            diagnostic,
            format!("positron: restore begin refused; code={expected}\n").as_bytes()
        );
    }
}

#[test]
fn begin_failure_diagnostic_write_refusal_remains_an_explicit_restore_failure() {
    struct Refused;
    impl Write for Refused {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("private-sink-detail"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let error = report_begin_failure(BootstrapFailureCode::ResourceUnavailable, &mut Refused);
    assert_eq!(
        error,
        "restore unavailable; begin failed and its diagnostic could not be written; inspect the same target before retrying"
    );
    assert!(!error.contains("private-sink-detail"));
}
