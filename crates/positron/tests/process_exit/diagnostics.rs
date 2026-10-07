//! Native binary exit and secret-safe diagnostics.

use std::process::Command;

#[cfg(unix)]
use positron_kernel::MountQualification;
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::process::Stdio;
#[cfg(unix)]
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[cfg(unix)]
use std::{io::Read, io::Write, net::TcpStream};
#[cfg(unix)]
use std::{
    os::fd::OwnedFd,
    os::unix::net::{UnixListener, UnixStream},
};

#[cfg(unix)]
static PROCESS_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[path = "support.rs"]
pub(super) mod support;
use support::*;

#[test]
fn invalid_configuration_has_a_stable_nonzero_exit_without_echoing_input()
-> Result<(), Box<dyn std::error::Error>> {
    let secret_marker = "must-not-appear";
    let output = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args([
            "serve",
            "--set",
            &format!("storage.data_directory={secret_marker}"),
        ])
        .output()?;

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr)?;
    assert_eq!(stderr, "positron: configuration rejected\n");
    assert!(!stderr.contains(secret_marker));
    Ok(())
}

#[test]
fn unknown_command_has_the_usage_exit() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_positron"))
        .arg("unknown")
        .output()?;

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr)?,
        "positron: invalid command line\n"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn doctor_verify_and_bundle_report_stdout_failure_without_panicking()
-> Result<(), Box<dyn std::error::Error>> {
    for arguments in [
        vec!["doctor", "--offline"],
        vec!["verify", "--offline"],
        vec!["support", "bundle"],
    ] {
        let output = command_with_closed_stdout(&arguments)?;
        assert_eq!(
            output.status.code(),
            Some(3),
            "{} reports the failed locked stdout write as an explicit failure",
            arguments.join(" "),
        );
        let stderr = String::from_utf8(output.stderr)?;
        assert!(
            !stderr.contains("panicked"),
            "{} must not panic when stdout is unavailable: {stderr}",
            arguments.join(" "),
        );
    }
    Ok(())
}

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
fn command_with_closed_stdout(
    arguments: &[&str],
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let (writer, reader) = UnixStream::pair()?;
    drop(reader);
    // The peer is closed before spawn. Ownership transfers exactly one socket
    // descriptor to the child so its fallible locked stdout write sees EPIPE.
    let descriptor: OwnedFd = writer.into();
    let stdout = Stdio::from(descriptor);
    Ok(Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(arguments)
        .stdout(stdout)
        .stderr(Stdio::piped())
        .output()?)
}

#[cfg(unix)]
#[test]
fn offline_doctor_and_verify_inspect_an_initialized_volume_without_changing_its_listing_or_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-doctor-{nonce}"));
    let roots = ChildRoots::new(&root)?;
    fs::set_permissions(&roots.secrets, fs::Permissions::from_mode(0o700))?;
    let paths = BootstrapPaths::new(&roots.data, &roots.secrets, MountQualification::LocalHost)?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let before = volume_bytes(&roots.data)?;
    let config = root.join("positron.toml");
    fs::write(
        &config,
        // Offline Doctor does not bind listeners, so fixed valid port values
        // keep this public binary contract independent of socket permission.
        process_configuration(
            &root,
            &roots.data,
            &roots.secrets,
            [42_001, 42_002, 42_003, 42_004, 42_005],
        ),
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["doctor", "--offline", "--config"])
        .arg(&config)
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("report_version=1\nmode=offline\nstatus=healthy\n"));
    assert!(stdout.contains("finding_code=DOCTOR_INTEGRITY_VERIFIED\nseverity=info\n"));
    for finding in [
        "DOCTOR_CONFIGURATION_RESOLVED",
        "DOCTOR_STORAGE_CAPACITY_OBSERVED",
        "DOCTOR_KEY_ENVELOPES_VERIFIED",
        "DOCTOR_CATALOG_FRONTIERS_VERIFIED",
        "DOCTOR_GOVERNOR_RUNTIME_UNAVAILABLE_OFFLINE",
        "DOCTOR_MAINTENANCE_RUNTIME_UNAVAILABLE_OFFLINE",
        "DOCTOR_OPERATIONS_LEASES_UNAVAILABLE_OFFLINE",
        "DOCTOR_LISTENERS_UNAVAILABLE_OFFLINE",
        "DOCTOR_BACKUP_REPOSITORY_NOT_CONFIGURED",
        "DOCTOR_HEALTH_UNAVAILABLE_OFFLINE",
    ] {
        assert!(
            stdout.contains(finding),
            "missing offline doctor finding {finding}"
        );
    }
    assert!(!stdout.contains("pos_"));
    let verify = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["verify", "--offline", "--config"])
        .arg(&config)
        .output()?;
    let verify_stdout = String::from_utf8(verify.stdout)?;
    assert!(verify.status.success(), "{verify_stdout}");
    assert!(verify_stdout.contains(
        "mode=offline\nstatus=verified\naggregate_outcome=verified\nverification_complete=true\n"
    ));
    assert!(verify_stdout.contains("report_count=2\n"));
    assert_eq!(before, volume_bytes(&roots.data)?);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn compiled_offline_verify_reaches_authentication_for_a_runtime_sized_continuation()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let (root, _roots, config) = initialized_doctor_fixture("runtime-sized-continuation")?;
    let continuation = "ab".repeat(1_038);
    let output = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["verify", "--offline", "--config"])
        .arg(&config)
        .args(["--continuation", &continuation])
        .output()?;
    let stdout = String::from_utf8(output.stdout)?;

    assert_eq!(output.status.code(), Some(3), "{stdout}");
    assert!(
        stdout
            .contains("mode=offline\nstatus=fenced\nverification_complete=false\nreport_count=0\n"),
        "the compiled CLI must authenticate, then reject, an opaque continuation: {stdout}"
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn offline_doctor_refuses_a_volume_owned_by_another_process()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-doctor-lock-{nonce}"));
    let roots = ChildRoots::new(&root)?;
    let paths = BootstrapPaths::new(&roots.data, &roots.secrets, MountQualification::LocalHost)?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let ports = available_ports()?;
    let config = root.join("positron.toml");
    fs::write(
        &config,
        process_configuration(&root, &roots.data, &roots.secrets, ports),
    )?;
    let ownership =
        positron_kernel::PrimaryDataVolume::acquire(&roots.data, MountQualification::LocalHost)?;
    let output = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["doctor", "--offline", "--config"])
        .arg(&config)
        .output()?;
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(
        String::from_utf8(output.stdout)?,
        "report_version=1\nmode=offline\nstatus=storage_locked\nfinding_code=DOCTOR_STORAGE_LOCKED\nseverity=error\nevidence_scope=primary_data_volume\nsafe_command=stop_positron_before_offline_doctor\nreport_count=0\n"
    );
    drop(ownership);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn offline_doctor_reports_missing_key_without_mutating_the_faulted_volume()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let (root, roots, config) = initialized_doctor_fixture("missing-key")?;
    fs::remove_file(roots.secrets.join("local-root-key.v1"))?;
    let before_data = volume_bytes(&roots.data)?;
    let before_secrets = volume_bytes(&roots.secrets)?;
    let output = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["doctor", "--offline", "--config"])
        .arg(&config)
        .output()?;
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8(output.stdout)?;
    assert!(
        stdout.contains(
            "status=key_unavailable\nfinding_code=DOCTOR_KEY_UNAVAILABLE\nseverity=error\n"
        )
    );
    assert!(!stdout.contains("local-root-key"));
    assert_eq!(before_data, volume_bytes(&roots.data)?);
    assert_eq!(before_secrets, volume_bytes(&roots.secrets)?);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn offline_doctor_reports_corrupt_bootstrap_as_fenced_without_repairing_it()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let (root, roots, config) = initialized_doctor_fixture("corrupt-bootstrap")?;
    let initialized = roots.data.join(".positron-bootstrap.initialized");
    let mut bytes = fs::read(&initialized)?;
    let byte = bytes
        .first_mut()
        .ok_or("initialized bootstrap is non-empty")?;
    *byte ^= 0x80;
    fs::write(&initialized, &bytes)?;
    let before = volume_bytes(&roots.data)?;
    let output = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["doctor", "--offline", "--config"])
        .arg(&config)
        .output()?;
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8(output.stdout)?;
    assert!(
        stdout.contains("status=fenced\nfinding_code=DOCTOR_INTEGRITY_FENCED\nseverity=error\n")
    );
    assert!(!stdout.contains("healthy"));
    assert_eq!(before, volume_bytes(&roots.data)?);
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
fn live_control_support_bundle_is_signed_encrypted_and_reports_serving_facts()
-> Result<(), Box<dyn std::error::Error>> {
    use age::{Decryptor, Identity};

    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-live-support-{nonce}"));
    let roots = ChildRoots::new(&root)?;
    let paths = BootstrapPaths::new(&roots.data, &roots.secrets, MountQualification::LocalHost)?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let ports = available_ports()?;
    let config = root.join("positron.toml");
    fs::write(
        &config,
        process_configuration(&root, &roots.data, &roots.secrets, ports),
    )?;
    let control = std::path::Path::new("/tmp")
        .join(root.file_name().ok_or("live support root name")?)
        .with_extension("sock");
    let server = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["serve", "--config"])
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    wait_for_ready(ports[0])?;

    let mut status = TcpStream::connect(("127.0.0.1", ports[0]))?;
    status.write_all(
        format!(
            "GET /status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            claim.secret(),
        )
        .as_bytes(),
    )?;
    let mut status_response = Vec::new();
    status.read_to_end(&mut status_response)?;
    assert!(
        status_response.starts_with(b"HTTP/1.1 200 "),
        "serving status must accept the current system administrator: {}",
        String::from_utf8_lossy(&status_response),
    );

    let identity = age::x25519::Identity::generate();
    let output = root.join("live-support.age");
    let mut command = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["support", "bundle", "create", "--config"])
        .arg(&config)
        .arg("--control-path")
        .arg(&control)
        .arg("--output")
        .arg(&output)
        .arg("--recipient")
        .arg(identity.to_public().to_string())
        .arg("--credential-stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut input = command.stdin.take().ok_or("live bundle stdin")?;
    input.write_all(claim.secret().as_bytes())?;
    input.write_all(b"\n")?;
    drop(input);
    let result = command.wait_with_output()?;

    let _ = Command::new("/bin/kill")
        .args(["-TERM", &server.id().to_string()])
        .status()?;
    let server_output = server.wait_with_output()?;

    assert!(
        result.status.success(),
        "live support command failed: {}; server stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&server_output.stderr),
    );
    let report = String::from_utf8(result.stdout)?;
    assert!(report.contains("artifact_authentication=unverified_control_response\n"));
    assert!(report.contains("signature=unverified\n"));
    let encrypted = fs::read(&output)?;
    let decryptor = Decryptor::new(&encrypted[..])?;
    let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn Identity))?;
    let mut archive = Vec::new();
    reader.read_to_end(&mut archive)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let actor = instance.attribute(
        positron_governance::PresentedCredential::parse(claim.secret())?,
        positron_governance::RequestedIntent::SystemAdministration,
        positron_governance::CompatibilityHints::none(),
    )?;
    let expected_identity = instance.support_bundle_manifest_signer(actor)?.identity();
    verify_authenticated_bundle_archive(&archive, expected_identity)?;
    assert!(
        archive
            .windows(b"manifest-signature.txt".len())
            .any(|bytes| bytes == b"manifest-signature.txt")
    );
    assert!(
        archive
            .windows(b"inspection_mode=online".len())
            .any(|bytes| bytes == b"inspection_mode=online")
    );
    assert!(
        archive
            .windows(b"process_phase=serving".len())
            .any(|bytes| bytes == b"process_phase=serving")
    );
    assert!(
        archive
            .windows(b"inspection_owner=process_lifecycle".len())
            .any(|bytes| bytes == b"inspection_owner=process_lifecycle")
    );
    assert!(
        archive
            .windows(b"process_serving".len())
            .any(|bytes| bytes == b"process_serving")
    );
    assert!(
        !archive
            .windows(b"availability=not_persisted".len())
            .any(|bytes| bytes == b"availability=not_persisted")
    );
    assert!(
        !archive
            .windows(claim.secret().len())
            .any(|bytes| bytes == claim.secret().as_bytes())
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn live_control_support_bundle_does_not_authenticate_an_arbitrary_control_response()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-untrusted-support-{nonce}"));
    let roots = ChildRoots::new(&root)?;
    let paths = BootstrapPaths::new(&roots.data, &roots.secrets, MountQualification::LocalHost)?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
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
    let control =
        std::path::Path::new("/tmp").join(format!("p-us-{}-{nonce}.sock", std::process::id()));
    let listener = UnixListener::bind(&control)?;
    let expected_bearer = claim.secret().as_bytes().to_vec();
    let body = b"arbitrary unsigned control response".to_vec();
    let response_body = body.clone();
    let server = std::thread::spawn(move || -> Result<(), String> {
        let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| error.to_string())?;
        let mut request = [0_u8; 4_096];
        let read = stream
            .read(&mut request)
            .map_err(|error| error.to_string())?;
        let request = &request[..read];
        if !request.starts_with(b"POST /control/support-bundle HTTP/1.1\r\n") {
            return Err("support bundle did not issue the control request".to_owned());
        }
        let authorization = format!(
            "Authorization: Bearer {}\r\n",
            String::from_utf8_lossy(&expected_bearer)
        );
        if !request
            .windows(authorization.len())
            .any(|candidate| candidate == authorization.as_bytes())
        {
            return Err("support bundle did not pass the supplied credential".to_owned());
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response_body.len()
        );
        stream
            .write_all(response.as_bytes())
            .and_then(|()| stream.write_all(&response_body))
            .map_err(|error| error.to_string())
    });

    let output_path = root.join("untrusted-control-response.age");
    let identity = age::x25519::Identity::generate();
    let mut command = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["support", "bundle", "create", "--config"])
        .arg(&config)
        .args(["--control-path"])
        .arg(&control)
        .args(["--output"])
        .arg(&output_path)
        .args(["--recipient"])
        .arg(identity.to_public().to_string())
        .arg("--credential-stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut input = command.stdin.take().ok_or("untrusted bundle stdin")?;
    input.write_all(claim.secret().as_bytes())?;
    input.write_all(b"\n")?;
    drop(input);
    let result = command.wait_with_output()?;
    server
        .join()
        .map_err(|_| "untrusted control server panicked")?
        .map_err(|error| format!("untrusted control server failed: {error}"))?;

    assert!(
        result.status.success(),
        "support bundle command failed: {}",
        String::from_utf8_lossy(&result.stdout),
    );
    let report = String::from_utf8(result.stdout)?;
    assert!(
        !report.contains("signature=signed\n"),
        "an arbitrary control response cannot be reported as signed instance evidence: {report}"
    );
    assert!(
        !report.contains("artifact_authentication=authenticated_instance_evidence\n"),
        "an arbitrary control response cannot be reported as authenticated instance evidence: {report}"
    );
    assert!(report.contains("artifact_authentication=unverified_control_response\n"));
    assert!(report.contains("signature=unverified\n"));
    assert_eq!(fs::read(&output_path)?, body);
    fs::remove_file(&control)?;
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
        let credential = if mode.requires_credential() {
            Some(
                InstanceBootstrap::claim(&BootstrapPaths::new(
                    &roots.data,
                    &roots.secrets,
                    MountQualification::LocalHost,
                )?)?
                .secret()
                .to_owned(),
            )
        } else {
            fs::remove_file(roots.secrets.join("local-root-key.v1"))?;
            None
        };

        write_sanitized_crash_record(
            &roots.data,
            "record-00000000000000000001.txt",
            "source_one_canary",
            SystemTime::now(),
        )?;
        write_sanitized_crash_record(
            &roots.data,
            "record-00000000000000000002.txt",
            "source_two_canary",
            SystemTime::now(),
        )?;
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
        assert!(
            records.contains("record_index=0\n") && !records.contains("record_index=1\n"),
            "{} must preserve exactly one bounded source: {records}",
            mode.label()
        );
        assert_eq!(
            usize::from(records.contains("source_one_canary"))
                + usize::from(records.contains("source_two_canary")),
            1,
            "{} must omit an unread crash source rather than concatenate both: {records}",
            mode.label()
        );
        assert!(
            redaction.contains("crash_record_file_limit"),
            "{} must declare the source-file bound: {redaction}",
            mode.label()
        );
        assert!(source_limited.is_file());

        fs::remove_dir_all(roots.data.join("diagnostics"))?;
        let stale = SystemTime::now()
            .checked_sub(Duration::from_secs(2))
            .ok_or("system clock before unix epoch")?;
        write_sanitized_crash_record(
            &roots.data,
            "record-00000000000000000003.txt",
            "stale_source_canary",
            stale,
        )?;
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
        assert!(!records.contains("stale_source_canary"));
        assert!(
            redaction.contains("crash_record_log_window"),
            "{} must declare the input-log-window omission: {redaction}",
            mode.label()
        );
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

#[cfg(unix)]
#[derive(Clone, Copy)]
enum SupportBundleOutput {
    SignedEncrypted,
    SignedPlaintext,
    UnsignedKeyUnavailableEncrypted,
}

#[cfg(unix)]
impl SupportBundleOutput {
    const fn label(self) -> &'static str {
        match self {
            Self::SignedEncrypted => "support-bounds-signed-encrypted",
            Self::SignedPlaintext => "support-bounds-signed-plaintext",
            Self::UnsignedKeyUnavailableEncrypted => "support-bounds-unsigned-encrypted",
        }
    }

    const fn requires_credential(self) -> bool {
        matches!(self, Self::SignedEncrypted | Self::SignedPlaintext)
    }

    const fn encrypts(self) -> bool {
        matches!(
            self,
            Self::SignedEncrypted | Self::UnsignedKeyUnavailableEncrypted
        )
    }
}

#[cfg(unix)]
fn write_sanitized_crash_record(
    data_directory: &std::path::Path,
    name: &str,
    finding: &str,
    modified: SystemTime,
) -> Result<(), Box<dyn std::error::Error>> {
    let records = data_directory.join("diagnostics/crash-records");
    fs::create_dir_all(&records)?;
    let path = records.join(name);
    fs::write(
        &path,
        format!(
            "record_version=1\nproduct=positron\nbuild_identity={finding}\nphase=serving\ncomponent=runtime\nfinding_code=runtime_startup_failed\nbacktrace_identity=sha256-0123456789abcdef\ncatalog_generation=7\noperation_generation=unavailable\n"
        ),
    )?;
    std::fs::File::open(&path)?.set_times(std::fs::FileTimes::new().set_modified(modified))?;
    Ok(())
}

#[cfg(unix)]
fn invoke_support_bundle<I, S>(
    config: &std::path::Path,
    output: &std::path::Path,
    mode: SupportBundleOutput,
    credential: Option<&str>,
    extra: I,
) -> Result<(std::process::Output, Vec<u8>), Box<dyn std::error::Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    use age::{Decryptor, Identity};

    let mut command = Command::new(env!("CARGO_BIN_EXE_positron"));
    command
        .args(["support", "bundle", "create", "--config"])
        .arg(config)
        .args(["--output"])
        .arg(output);
    let identity = mode.encrypts().then(age::x25519::Identity::generate);
    if let Some(identity) = identity.as_ref() {
        command
            .arg("--recipient")
            .arg(identity.to_public().to_string());
    } else {
        command.arg("--allow-plaintext-bundle");
    }
    if mode.requires_credential() {
        command.arg("--credential-stdin").stdin(Stdio::piped());
    } else {
        command.arg("--offline-key-unavailable");
    }
    command.args(extra).stdout(Stdio::piped());
    let output_result = if let Some(credential) = credential {
        let mut child = command.spawn()?;
        let mut input = child.stdin.take().ok_or("support bundle stdin")?;
        input.write_all(credential.as_bytes())?;
        input.write_all(b"\n")?;
        drop(input);
        child.wait_with_output()?
    } else {
        command.output()?
    };
    let archive = if output_result.status.success() {
        match identity {
            Some(identity) => {
                let encrypted = fs::read(output)?;
                let decryptor = Decryptor::new(&encrypted[..])?;
                let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn Identity))?;
                let mut archive = Vec::new();
                reader.read_to_end(&mut archive)?;
                archive
            },
            None => fs::read(output)?,
        }
    } else {
        Vec::new()
    };
    if output_result.status.success() && archive.is_empty() {
        return Err(format!(
            "empty support archive mode={} path={} on-disk-bytes={} stdout={}",
            mode.label(),
            output.display(),
            fs::metadata(output)?.len(),
            String::from_utf8_lossy(&output_result.stdout),
        )
        .into());
    }
    Ok((output_result, archive))
}

#[cfg(unix)]
fn archive_member(archive: &[u8], wanted: &str) -> Result<String, Box<dyn std::error::Error>> {
    let archive_bytes = archive.len();
    let mut archive = tar::Archive::new(archive);
    let mut observed = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if path.as_os_str() == std::ffi::OsStr::new(wanted) {
            let mut bytes = String::new();
            entry.read_to_string(&mut bytes)?;
            return Ok(bytes);
        }
        observed.push(path.display().to_string());
    }
    Err(format!(
        "missing archive member {wanted}; archive_bytes={}; saw {observed:?}",
        archive_bytes
    )
    .into())
}

#[cfg(unix)]
fn verify_authenticated_bundle_archive(
    archive: &[u8],
    expected: positron_kernel::BootstrapIntegrityIdentity,
) -> Result<(), Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};

    let mut entries = tar::Archive::new(archive);
    let mut members = std::collections::BTreeMap::new();
    for entry in entries.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let path = path.to_str().ok_or("non-utf8 bundle member")?.to_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        if members.insert(path, bytes).is_some() {
            return Err("duplicate bundle member".into());
        }
    }
    let manifest = members.remove("manifest.txt").ok_or("missing manifest")?;
    let signature = members
        .remove("manifest-signature.txt")
        .ok_or("missing manifest signature")?;
    let signature = std::str::from_utf8(&signature)?;
    let mut signature_fields = signature.lines();
    let public_key = signature_fields
        .next()
        .and_then(|line| line.strip_prefix("integrity_identity="))
        .ok_or("missing signature identity")?;
    let signature_bytes = signature_fields
        .next()
        .and_then(|line| line.strip_prefix("signature="))
        .ok_or("missing signature bytes")?;
    if signature_fields.next().is_some() || public_key != hex_bytes(&expected.public_key()) {
        return Err("signature identity differs from current instance identity".into());
    }
    let signature = positron_kernel::ExportManifestSignature::new(
        expected,
        decode_fixed_hex::<64>(signature_bytes)?,
    )?;
    signature.verify(expected, &manifest)?;

    let manifest = std::str::from_utf8(&manifest)?;
    let mut expected_members = std::collections::BTreeSet::new();
    let mut redaction_digest = None;
    for line in manifest.lines() {
        if let Some(record) = line.strip_prefix("member=") {
            let mut fields = record.split_whitespace();
            let path = fields.next().ok_or("manifest member path")?;
            let byte_count = fields
                .next()
                .and_then(|field| field.strip_prefix("bytes="))
                .ok_or("manifest member size")?
                .parse::<usize>()?;
            let digest = fields
                .next()
                .and_then(|field| field.strip_prefix("sha256="))
                .ok_or("manifest member digest")?;
            if fields.next().is_some() || !expected_members.insert(path.to_owned()) {
                return Err("malformed or duplicate manifest member".into());
            }
            let actual = members
                .get(path)
                .ok_or("manifest member absent from archive")?;
            if actual.len() != byte_count || hex_bytes(&Sha256::digest(actual)) != digest {
                return Err("manifest member digest mismatch".into());
            }
        } else if let Some(digest) = line.strip_prefix("redaction_report_sha256=") {
            redaction_digest = Some(digest);
        }
    }
    let redaction = members
        .get("redaction-report.txt")
        .ok_or("missing redaction report")?;
    let actual_redaction_digest = hex_bytes(&Sha256::digest(redaction));
    if redaction_digest != Some(actual_redaction_digest.as_str()) {
        return Err("redaction report digest mismatch".into());
    }
    if members
        .keys()
        .any(|path| path != "redaction-report.txt" && !expected_members.contains(path))
    {
        return Err("archive member omitted from signed manifest".into());
    }
    Ok(())
}

#[cfg(unix)]
fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(unix)]
fn decode_fixed_hex<const N: usize>(encoded: &str) -> Result<[u8; N], Box<dyn std::error::Error>> {
    if encoded.len() != N.saturating_mul(2) {
        return Err("invalid hex length".into());
    }
    let mut bytes = [0_u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let offset = index.checked_mul(2).ok_or("hex offset")?;
        *byte = u8::from_str_radix(encoded.get(offset..offset + 2).ok_or("hex slice")?, 16)?;
    }
    Ok(bytes)
}

#[cfg(unix)]
fn initialized_doctor_fixture(
    label: &str,
) -> Result<(std::path::PathBuf, ChildRoots, std::path::PathBuf), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-doctor-{label}-{nonce}"));
    let roots = ChildRoots::new(&root)?;
    let paths = BootstrapPaths::new(&roots.data, &roots.secrets, MountQualification::LocalHost)?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let config = root.join("positron.toml");
    fs::write(
        &config,
        process_configuration(&root, &roots.data, &roots.secrets, available_ports()?),
    )?;
    Ok((root, roots, config))
}

#[cfg(unix)]
fn initialized_support_bundle_fixture(
    label: &str,
) -> Result<(std::path::PathBuf, ChildRoots, std::path::PathBuf), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-support-{label}-{nonce}"));
    let roots = ChildRoots::new(&root)?;
    let paths = BootstrapPaths::new(&roots.data, &roots.secrets, MountQualification::LocalHost)?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
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
    Ok((root, roots, config))
}

#[cfg(unix)]
fn volume_bytes(
    root: &std::path::Path,
) -> Result<Vec<(std::path::PathBuf, Vec<u8>)>, std::io::Error> {
    fn walk(
        root: &std::path::Path,
        current: &std::path::Path,
        output: &mut Vec<(std::path::PathBuf, Vec<u8>)>,
    ) -> Result<(), std::io::Error> {
        let mut entries = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .map_err(std::io::Error::other)?
                .to_path_buf();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                output.push((relative.clone(), Vec::new()));
                walk(root, &path, output)?;
            } else if kind.is_file() {
                output.push((relative, fs::read(path)?));
            }
        }
        Ok(())
    }
    let mut output = Vec::new();
    walk(root, root, &mut output)?;
    Ok(output)
}
