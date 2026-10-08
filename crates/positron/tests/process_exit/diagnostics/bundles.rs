//! Focused process-exit diagnostics coverage.

use super::*;

#[cfg(unix)]
#[test]
fn support_bundle_rejects_an_impossible_live_output_limit_before_inspection()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-support-limit-{nonce}"));
    let roots = ChildRoots::new(&root)?;
    let config = root.join("positron.toml");
    fs::write(
        &config,
        process_configuration(
            &root,
            &roots.data,
            &roots.secrets,
            [42_001, 42_002, 42_003, 42_004, 42_005],
        ),
    )?;
    let identity = age::x25519::Identity::generate();
    let output = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["support", "bundle", "create", "--config"])
        .arg(&config)
        .args(["--output"])
        .arg(root.join("bundle.age"))
        .args(["--recipient"])
        .arg(identity.to_public().to_string())
        .args([
            "--credential-stdin",
            "--max-output-bytes",
            &usize::MAX.to_string(),
        ])
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8(output.stdout)?.contains("SUPPORT_BUNDLE_OUTPUT_LIMIT_EXCEEDED"));
    assert!(!root.join("bundle.age").exists());
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn compiled_support_bundle_enforces_the_bounded_log_window_before_inspection()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let (root, _roots, config) = initialized_support_bundle_fixture("log-window")?;

    for seconds in ["0", "301", "18446744073709551615"] {
        let output = Command::new(env!("CARGO_BIN_EXE_positron"))
            .args(["support", "bundle", "create", "--config"])
            .arg(&config)
            .args(["--output"])
            .arg(root.join(format!("rejected-{seconds}.age")))
            .args([
                "--allow-plaintext-bundle",
                "--offline-key-unavailable",
                "--log-window-seconds",
                seconds,
            ])
            .output()?;
        assert_eq!(output.status.code(), Some(2), "log window {seconds}");
        assert!(
            String::from_utf8(output.stdout)?.contains("SUPPORT_BUNDLE_ARGUMENTS_INVALID"),
            "log window {seconds} must be rejected before configuration, credential, source, or output work"
        );
        assert!(!root.join(format!("rejected-{seconds}.age")).exists());
    }

    let accepted = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["support", "bundle", "create", "--config"])
        .arg(&config)
        .args(["--output"])
        .arg(root.join("accepted-boundary.age"))
        .args([
            "--allow-plaintext-bundle",
            "--offline-key-unavailable",
            "--log-window-seconds",
            "300",
        ])
        .output()?;
    assert_ne!(
        accepted.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&accepted.stdout)
    );
    assert!(
        !String::from_utf8(accepted.stdout)?.contains("SUPPORT_BUNDLE_ARGUMENTS_INVALID"),
        "the canonical 300-second window reaches the bounded offline inspection boundary"
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn compiled_support_bundle_rejects_deadlines_above_the_documented_limit_before_configuration()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let root = std::env::temp_dir().join(format!(
        "positron-support-deadline-{}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir(&root)?;
    let output = root.join("must-not-exist.age");
    let recipient = age::x25519::Identity::generate().to_public().to_string();

    for seconds in ["31", "18446744073709551615"] {
        let result = Command::new(env!("CARGO_BIN_EXE_positron"))
            .args(["support", "bundle", "create", "--config"])
            .arg(root.join("missing.toml"))
            .args(["--output"])
            .arg(&output)
            .args([
                "--recipient",
                &recipient,
                "--credential-stdin",
                "--max-elapsed-seconds",
                seconds,
            ])
            .output()?;
        assert_eq!(result.status.code(), Some(2));
        assert_eq!(
            String::from_utf8(result.stdout)?,
            "report_version=1\nstatus=invalid_arguments\nfinding_code=SUPPORT_BUNDLE_ARGUMENTS_INVALID\nseverity=error\n"
        );
        assert!(!output.exists());
    }
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn encrypted_support_bundle_is_signed_decryptable_collision_safe_and_read_only()
-> Result<(), Box<dyn std::error::Error>> {
    use age::{Decryptor, Identity};

    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-support-bundle-{nonce}"));
    let roots = ChildRoots::new(&root)?;
    let paths = BootstrapPaths::new(&roots.data, &roots.secrets, MountQualification::LocalHost)?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = positron_runtime::InstanceBootstrap::claim(&paths)?;
    let config = root.join("positron.toml");
    fs::write(
        &config,
        process_configuration(&root, &roots.data, &roots.secrets, available_ports()?),
    )?;
    let before_data = volume_bytes(&roots.data)?;
    let before_secrets = volume_bytes(&roots.secrets)?;
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public().to_string();
    let output = root.join("support.age");
    let arguments = [
        "support",
        "bundle",
        "create",
        "--config",
        config.to_str().ok_or("utf8 config")?,
        "--output",
        output.to_str().ok_or("utf8 output")?,
        "--recipient",
        &recipient,
        "--credential-stdin",
    ];
    let mut command = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut input = command.stdin.take().ok_or("bundle stdin")?;
    input.write_all(claim.secret().as_bytes())?;
    input.write_all(b"\n")?;
    drop(input);
    let result = command.wait_with_output()?;
    assert!(result.status.success());
    let report = String::from_utf8(result.stdout)?;
    assert!(report.contains("encryption=age_x25519\nsignature=signed"));
    let encrypted = fs::read(&output)?;
    assert!(
        !encrypted
            .windows(claim.secret().len())
            .any(|entry| entry == claim.secret().as_bytes())
    );
    let decryptor = Decryptor::new(&encrypted[..])?;
    let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn Identity))?;
    let mut archive = Vec::new();
    reader.read_to_end(&mut archive)?;
    for member in [
        "effective-configuration.txt",
        "compatibility-manifest.txt",
        "product-identity.txt",
        "health-state.txt",
        "operational-telemetry.txt",
        "operational-logs.txt",
        "catalog-summary.txt",
        "resource-status.txt",
        "maintenance-status.txt",
        "listener-status.txt",
        "backup-repository-status.txt",
        "environment.txt",
        "doctor-report.txt",
        "sanitized-crash-records.txt",
    ] {
        assert!(
            archive
                .windows(member.len())
                .any(|entry| entry == member.as_bytes()),
            "missing required bundle member {member}"
        );
    }
    assert!(
        archive
            .windows(b"manifest-signature.txt".len())
            .any(|entry| entry == b"manifest-signature.txt")
    );
    assert!(
        !archive
            .windows(claim.secret().len())
            .any(|entry| entry == claim.secret().as_bytes())
    );
    assert!(
        archive
            .windows(b"finding_code=DOCTOR_BUNDLE_OWNER_VERIFIED".len())
            .any(|entry| entry == b"finding_code=DOCTOR_BUNDLE_OWNER_VERIFIED"),
        "the signed export must use the already-owned bootstrap inspection"
    );
    for fact in [
        b"key_custody=verified".as_slice(),
        b"catalog_bootstrap=verified".as_slice(),
        b"catalog_generation=".as_slice(),
        b"usable_disk_bytes=".as_slice(),
        b"disk_pressure=".as_slice(),
    ] {
        assert!(
            archive.windows(fact.len()).any(|entry| entry == fact),
            "missing truthful signed Doctor fact: {:?}",
            String::from_utf8_lossy(fact),
        );
    }
    for finding in [
        b"DOCTOR_CONFIGURATION_RESOLVED".as_slice(),
        b"DOCTOR_STORAGE_CAPACITY_OBSERVED".as_slice(),
        b"DOCTOR_GOVERNOR_RUNTIME_UNAVAILABLE_OFFLINE".as_slice(),
        b"DOCTOR_MAINTENANCE_RUNTIME_UNAVAILABLE_OFFLINE".as_slice(),
        b"DOCTOR_OPERATIONS_LEASES_UNAVAILABLE_OFFLINE".as_slice(),
        b"DOCTOR_LISTENERS_UNAVAILABLE_OFFLINE".as_slice(),
        b"DOCTOR_HEALTH_UNAVAILABLE_OFFLINE".as_slice(),
        b"DOCTOR_BACKUP_REPOSITORY_NOT_CONFIGURED".as_slice(),
        b"backup_repository=not_configured".as_slice(),
    ] {
        assert!(archive.windows(finding.len()).any(|entry| entry == finding));
    }
    assert!(
        !archive
            .windows(b"DOCTOR_STORAGE_LOCKED".len())
            .any(|entry| entry == b"DOCTOR_STORAGE_LOCKED"),
        "the bundle must not diagnose its own retained ownership as a lock"
    );
    assert_eq!(before_data, volume_bytes(&roots.data)?);
    assert_eq!(before_secrets, volume_bytes(&roots.secrets)?);

    let mut collision = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut input = collision.stdin.take().ok_or("collision stdin")?;
    input.write_all(claim.secret().as_bytes())?;
    input.write_all(b"\n")?;
    drop(input);
    let collision = collision.wait_with_output()?;
    assert_eq!(collision.status.code(), Some(3));
    assert!(String::from_utf8(collision.stdout)?.contains("SUPPORT_BUNDLE_OUTPUT_UNAVAILABLE"));
    assert_eq!(before_data, volume_bytes(&roots.data)?);
    assert_eq!(before_secrets, volume_bytes(&roots.secrets)?);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn encrypted_signed_bundle_pseudonymizes_configured_control_path_and_listener_address()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let (root, roots, config) = initialized_support_bundle_fixture("identifier-canary")?;
    let configured = fs::read_to_string(&config)?;
    let control_canary = "/run/customer/control.sock";
    let address_canary = "10.20.30.40:42001";
    let control_line = configured
        .lines()
        .find(|line| line.starts_with("control_path = "))
        .ok_or("control path")?;
    let operations_line = configured
        .lines()
        .find(|line| line.starts_with("operations_bind_address = "))
        .ok_or("operations address")?;
    let configured = configured
        .replace(
            control_line,
            &format!("control_path = \"{control_canary}\""),
        )
        .replace(
            operations_line,
            &format!("operations_bind_address = \"{address_canary}\""),
        );
    fs::write(&config, configured)?;
    let paths = BootstrapPaths::new(&roots.data, &roots.secrets, MountQualification::LocalHost)?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let output = root.join("identifier-canary.age");
    let (result, archive) = invoke_support_bundle(
        &config,
        &output,
        SupportBundleOutput::SignedEncrypted,
        Some(claim.secret()),
        [] as [&str; 0],
    )?;
    assert!(result.status.success());
    let effective = archive_member(&archive, "effective-configuration.txt")?;
    let redaction = archive_member(&archive, "redaction-report.txt")?;
    assert!(redaction.contains("identifier_pseudonymization=ephemeral_per_bundle"));
    assert!(redaction.contains("signature=signed"));
    assert!(!effective.contains(control_canary));
    assert!(!effective.contains(address_canary));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn explicit_plaintext_support_bundle_is_signed_owner_only_and_collision_safe()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let (root, roots, config) = initialized_doctor_fixture("support-plaintext")?;
    let paths = BootstrapPaths::new(&roots.data, &roots.secrets, MountQualification::LocalHost)?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let before_data = volume_bytes(&roots.data)?;
    let before_secrets = volume_bytes(&roots.secrets)?;
    let output = root.join("support.tar");
    let arguments = [
        "support",
        "bundle",
        "create",
        "--config",
        config.to_str().ok_or("utf8 config")?,
        "--output",
        output.to_str().ok_or("utf8 output")?,
        "--allow-plaintext-bundle",
        "--credential-stdin",
    ];
    let mut command = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut input = command.stdin.take().ok_or("bundle stdin")?;
    input.write_all(claim.secret().as_bytes())?;
    input.write_all(b"\n")?;
    drop(input);
    let result = command.wait_with_output()?;
    assert!(result.status.success());
    assert!(String::from_utf8(result.stdout)?.contains("plaintext_export_warning=true"));
    assert_eq!(fs::metadata(&output)?.permissions().mode() & 0o777, 0o600);
    let archive = fs::read(&output)?;
    assert!(
        archive
            .windows(b"manifest-signature.txt".len())
            .any(|part| part == b"manifest-signature.txt")
    );
    assert!(
        !archive
            .windows(claim.secret().len())
            .any(|part| part == claim.secret().as_bytes())
    );
    let mut collision = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut input = collision.stdin.take().ok_or("collision stdin")?;
    input.write_all(claim.secret().as_bytes())?;
    input.write_all(b"\n")?;
    drop(input);
    let collision = collision.wait_with_output()?;
    assert_eq!(collision.status.code(), Some(3));
    assert!(String::from_utf8(collision.stdout)?.contains("SUPPORT_BUNDLE_OUTPUT_UNAVAILABLE"));
    assert_eq!(before_data, volume_bytes(&roots.data)?);
    assert_eq!(before_secrets, volume_bytes(&roots.secrets)?);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn offline_key_unavailable_support_bundle_is_unsigned_and_never_auth_fallback()
-> Result<(), Box<dyn std::error::Error>> {
    use age::{Decryptor, Identity};

    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let (root, roots, config) = initialized_doctor_fixture("support-key-unavailable")?;
    fs::remove_file(roots.secrets.join("local-root-key.v1"))?;
    let before_data = volume_bytes(&roots.data)?;
    let before_secrets = volume_bytes(&roots.secrets)?;
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public().to_string();
    let output = root.join("support.age");
    let result = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args([
            "support",
            "bundle",
            "create",
            "--config",
            config.to_str().ok_or("utf8 config")?,
            "--output",
            output.to_str().ok_or("utf8 output")?,
            "--recipient",
            &recipient,
            "--offline-key-unavailable",
        ])
        .output()?;
    let report = String::from_utf8(result.stdout)?;
    assert!(result.status.success(), "{report}");
    assert!(report.contains("signature=unsigned_key_unavailable_offline"));
    let encrypted = fs::read(&output)?;
    let decryptor = Decryptor::new(&encrypted[..])?;
    let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn Identity))?;
    let mut archive = Vec::new();
    reader.read_to_end(&mut archive)?;
    assert!(
        archive
            .windows(b"signature=unsigned_key_unavailable_offline".len())
            .any(|entry| entry == b"signature=unsigned_key_unavailable_offline")
    );
    assert!(
        !archive
            .windows(b"local-root-key".len())
            .any(|entry| entry == b"local-root-key")
    );
    let collision = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args([
            "support",
            "bundle",
            "create",
            "--config",
            config.to_str().ok_or("utf8 config")?,
            "--output",
            output.to_str().ok_or("utf8 output")?,
            "--recipient",
            &recipient,
            "--offline-key-unavailable",
        ])
        .output()?;
    assert_eq!(collision.status.code(), Some(3));
    assert!(
        String::from_utf8(collision.stdout)?.contains("SUPPORT_BUNDLE_OUTPUT_UNAVAILABLE"),
        "the offline unsigned path must not replace a prior export"
    );
    assert_eq!(before_data, volume_bytes(&roots.data)?);
    assert_eq!(before_secrets, volume_bytes(&roots.secrets)?);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn offline_support_bundle_does_not_recreate_missing_catalog_storage()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let (root, roots, config) = initialized_support_bundle_fixture("readonly-catalog")?;
    let credential = InstanceBootstrap::claim(&BootstrapPaths::new(
        &roots.data,
        &roots.secrets,
        MountQualification::LocalHost,
    )?)?
    .secret()
    .to_owned();
    fs::remove_dir_all(roots.data.join("catalog/staging"))?;
    let before_data = volume_bytes(&roots.data)?;
    let before_secrets = volume_bytes(&roots.secrets)?;
    let output = root.join("support.age");
    let (result, _) = invoke_support_bundle(
        &config,
        &output,
        SupportBundleOutput::SignedEncrypted,
        Some(&credential),
        std::iter::empty::<&str>(),
    )?;

    assert_eq!(result.status.code(), Some(3));
    assert_eq!(
        String::from_utf8(result.stdout)?,
        "report_version=1\nstatus=inspection_unavailable\nfinding_code=SUPPORT_BUNDLE_INSPECTION_UNAVAILABLE\nseverity=error\n"
    );
    assert!(!output.exists());
    assert_eq!(volume_bytes(&roots.data)?, before_data);
    assert_eq!(volume_bytes(&roots.secrets)?, before_secrets);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn compiled_support_bundle_declares_collection_bounds_in_every_canonical_output_mode()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;

    for mode in [
        SupportBundleOutput::SignedEncrypted,
        SupportBundleOutput::SignedPlaintext,
        SupportBundleOutput::UnsignedKeyUnavailableEncrypted,
    ] {
        let (root, roots, config) = initialized_support_bundle_fixture(mode.label())?;
        let paths =
            BootstrapPaths::new(&roots.data, &roots.secrets, MountQualification::LocalHost)?;
        persist_sanitized_crash_record(&paths, &roots.data, "runtime_startup_failed")?;
        persist_sanitized_crash_record(&paths, &roots.data, "catalog_unavailable")?;
        let credential = if mode.requires_credential() {
            Some(InstanceBootstrap::claim(&paths)?.secret().to_owned())
        } else {
            fs::remove_file(roots.secrets.join("local-root-key.v1"))?;
            None
        };

        let source_limited = root.join("source-limited.bundle");
        let (result, archive) = invoke_support_bundle(
            &config,
            &source_limited,
            mode,
            credential.as_deref(),
            ["--log-window-seconds", "60", "--max-source-files", "1"],
        )?;
        assert!(
            result.status.success(),
            "{} source-limit invocation failed: {}",
            mode.label(),
            String::from_utf8_lossy(&result.stdout)
        );
        let records = archive_member(&archive, "sanitized-crash-records.txt")?;
        let redaction = archive_member(&archive, "redaction-report.txt")?;
        if mode.requires_credential() {
            assert!(
                records.contains("record_index=0\n") && !records.contains("record_index=1\n"),
                "{} must preserve exactly one bounded source: {records}",
                mode.label()
            );
            assert_eq!(
                usize::from(records.contains("finding_code=runtime_startup_failed"))
                    + usize::from(records.contains("finding_code=catalog_unavailable")),
                1,
                "{} must omit an unread crash source rather than concatenate both: {records}",
                mode.label()
            );
            assert!(
                redaction.contains("crash_record_file_limit"),
                "{} must declare the source-file bound: {redaction}",
                mode.label()
            );
        } else {
            assert_eq!(records, "record_count=0\n");
            assert!(
                redaction.contains("crash_record_key_unavailable"),
                "{} must declare the unavailable-key omission: {redaction}",
                mode.label()
            );
        }
        assert!(source_limited.is_file());

        fs::remove_dir_all(roots.data.join("diagnostics"))?;
        let stale_record = mode
            .requires_credential()
            .then(|| persist_sanitized_crash_record(&paths, &roots.data, "runtime_startup_failed"))
            .transpose()?;
        if let Some(record) = stale_record {
            let stale = SystemTime::now()
                .checked_sub(Duration::from_secs(2))
                .ok_or("system clock before unix epoch")?;
            std::fs::File::open(record)?
                .set_times(std::fs::FileTimes::new().set_modified(stale))?;
        }
        let log_limited = root.join("log-limited.bundle");
        let (result, archive) = invoke_support_bundle(
            &config,
            &log_limited,
            mode,
            credential.as_deref(),
            ["--log-window-seconds", "1", "--max-source-files", "4"],
        )?;
        assert!(
            result.status.success(),
            "{} log-window invocation failed: {}",
            mode.label(),
            String::from_utf8_lossy(&result.stdout)
        );
        let records = archive_member(&archive, "sanitized-crash-records.txt")?;
        let redaction = archive_member(&archive, "redaction-report.txt")?;
        assert_eq!(records, "record_count=0\n");
        if mode.requires_credential() {
            assert!(
                redaction.contains("crash_record_log_window"),
                "{} must declare the input-log-window omission: {redaction}",
                mode.label()
            );
        } else {
            assert!(
                redaction.contains("crash_record_key_unavailable"),
                "{} must declare the unavailable-key omission: {redaction}",
                mode.label()
            );
        }
        assert!(log_limited.is_file());

        let deadline_output = root.join("deadline.bundle");
        let (result, _) = invoke_support_bundle(
            &config,
            &deadline_output,
            mode,
            credential.as_deref(),
            ["--max-elapsed-seconds", "0"],
        )?;
        assert_eq!(result.status.code(), Some(3));
        assert_eq!(
            String::from_utf8(result.stdout)?,
            "report_version=1\nstatus=deadline_exceeded\nfinding_code=SUPPORT_BUNDLE_DEADLINE_EXCEEDED\nseverity=error\n"
        );
        assert!(
            !deadline_output.exists(),
            "{} must not create an artifact after its collection deadline",
            mode.label()
        );
        fs::remove_dir_all(root)?;
    }
    Ok(())
}
