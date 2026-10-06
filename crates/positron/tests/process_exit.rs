//! Native binary exit and secret-safe diagnostics.

use std::process::Command;

#[cfg(unix)]
use positron_kernel::MountQualification;
#[cfg(unix)]
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::process::Stdio;
#[cfg(unix)]
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[cfg(unix)]
use std::{io::BufRead, io::BufReader, io::Read, io::Write, net::TcpStream};

#[cfg(unix)]
static PROCESS_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[path = "process_exit/support.rs"]
mod support;
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
fn offline_doctor_inspects_an_initialized_volume_without_changing_its_listing_or_bytes()
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
    let ports = available_ports()?;
    let config = root.join("positron.toml");
    fs::write(
        &config,
        process_configuration(&root, &roots.data, &roots.secrets, ports),
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
    assert_eq!(before, volume_bytes(&roots.data)?);
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
            "record_version=1\nproduct=positron\nbuild_identity=0.0.0\nphase=serving\ncomponent=runtime\nfinding_code={finding}\nbacktrace_identity=sha256-0123456789abcdef\ncatalog_generation=7\noperation_generation=unavailable\n"
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

#[cfg(unix)]
#[test]
fn first_os_signal_drains_and_exits_successfully() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root =
        std::env::temp_dir().join(format!("positron-process-{}-{nonce}", std::process::id()));
    let data = root.join("data");
    let secrets = root.join("secrets");
    fs::create_dir_all(&data).map_err(|error| format!("create data: {error}"))?;
    fs::create_dir_all(&secrets).map_err(|error| format!("create secrets: {error}"))?;
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("protect secrets: {error}"))?;
    let [
        operations_port,
        api_port,
        otlp_grpc_port,
        otlp_http_port,
        loki_push_port,
    ] = available_ports()?;
    let configuration = process_configuration(
        &root,
        &data,
        &secrets,
        [
            operations_port,
            api_port,
            otlp_grpc_port,
            otlp_http_port,
            loki_push_port,
        ],
    );
    let config_path = root.join("positron.toml");
    fs::write(&config_path, configuration)
        .map_err(|error| format!("write configuration: {error}"))?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["serve", "--init-if-empty", "--config"])
        .arg(&config_path)
        .spawn()
        .map_err(|error| format!("spawn positron: {error}"))?;
    wait_for_ready(operations_port)?;
    std::thread::sleep(Duration::from_millis(50));
    let signal = Command::new("/bin/kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .map_err(|error| format!("signal positron: {error}"))?;
    assert!(signal.success());
    let status = child.wait()?;
    assert_eq!(status.code(), Some(0));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn sighup_reloads_a_valid_candidate_and_keeps_serving_after_a_rejected_candidate()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-reload-{}-{nonce}", std::process::id()));
    let data = root.join("data");
    let secrets = root.join("secrets");
    fs::create_dir_all(&data)?;
    fs::create_dir_all(&secrets)?;
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))?;
    let [
        operations_port,
        api_port,
        otlp_grpc_port,
        otlp_http_port,
        loki_push_port,
    ] = available_ports()?;
    let config_path = root.join("positron.toml");
    let base_configuration = process_configuration(
        &root,
        &data,
        &secrets,
        [
            operations_port,
            api_port,
            otlp_grpc_port,
            otlp_http_port,
            loki_push_port,
        ],
    );
    fs::write(&config_path, &base_configuration)?;
    let bootstrap_paths = BootstrapPaths::new(&data, &secrets, MountQualification::LocalHost)?;
    drop(InstanceBootstrap::initialize(
        &bootstrap_paths,
        InitializationPlan::non_interactive(),
    )?);
    let authorization = format!(
        "Bearer {}",
        InstanceBootstrap::claim(&bootstrap_paths)?.secret()
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["serve", "--config"])
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    wait_for_ready(operations_port)?;

    fs::write(
        &config_path,
        format!("{base_configuration}\n[diagnostics]\nlog_level = \"debug\"\n"),
    )?;
    assert!(
        Command::new("/bin/kill")
            .args(["-HUP", &child.id().to_string()])
            .status()?
            .success()
    );
    std::thread::sleep(Duration::from_millis(100));
    assert!(child.try_wait()?.is_none());
    wait_for_ready(operations_port)?;

    let restart_required_configuration = base_configuration.replacen(
        "shutdown_grace_seconds = 2",
        "shutdown_grace_seconds = 60",
        1,
    );
    fs::write(&config_path, restart_required_configuration)?;
    assert!(
        Command::new("/bin/kill")
            .args(["-HUP", &child.id().to_string()])
            .status()?
            .success()
    );
    let pending_status = wait_for_configuration_status(
        operations_port,
        &authorization,
        &[
            "\"pending_restart\":true",
            "\"drift_disposition\":\"reconcile\"",
        ],
    )?;
    let pending = ConfigurationStatus::from_response(&pending_status)?;
    assert_eq!(pending.phase, "serving");
    assert!(pending.pending_restart);
    assert_eq!(pending.drift_disposition, "reconcile");
    assert_ne!(pending.effective_digest, pending.desired_digest);

    fs::write(&config_path, &base_configuration)?;
    let mut send_reload = || -> Result<(), Box<dyn std::error::Error>> {
        let status = Command::new("/bin/kill")
            .args(["-HUP", &child.id().to_string()])
            .status()?;
        status
            .success()
            .then_some(())
            .ok_or_else(|| format!("reload signal failed with {status}").into())
    };
    let (restored_status, _) = match restore_configuration_with_at_most_one_retry(
        &pending,
        &mut send_reload,
        || configuration_status(operations_port, &authorization),
        &authorization,
        CONFIGURATION_RESTORE_PROBE_TIMEOUT,
    ) {
        Ok(status) => status,
        Err(error) => {
            return Err(format!(
                "configuration did not restore after reload: {error}; {}",
                terminate_and_describe_child(&mut child, &authorization)
            )
            .into());
        },
    };
    let restored = ConfigurationStatus::from_response(&restored_status)?;
    assert_eq!(restored.observed_generation, pending.observed_generation);
    assert!(restored.is_restored());

    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &child.id().to_string()])
            .status()?
            .success()
    );
    assert_eq!(child.wait_with_output()?.status.code(), Some(0));

    // A reload signal reads its source when the owner consumes it. Keep the
    // rejected-source scenario in a fresh child so the one permitted restore
    // retry cannot still be pending when this fixture replaces the document.
    fs::write(&config_path, &base_configuration)?;
    let mut rejected_child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["serve", "--config"])
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    wait_for_ready(operations_port)?;
    fs::write(
        &config_path,
        "schema_version = 1\n[diagnostics]\nlog_level = \"invalid\"\n",
    )?;
    assert!(
        Command::new("/bin/kill")
            .args(["-HUP", &rejected_child.id().to_string()])
            .status()?
            .success()
    );
    let stderr = rejected_child.stderr.take().ok_or("child stderr")?;
    let mut stderr = BufReader::new(stderr);
    let mut observed = String::new();
    stderr.read_line(&mut observed)?;
    stderr.read_line(&mut observed)?;
    assert_eq!(
        observed,
        "positron: warning: operations transport is plaintext\npositron: configuration reload rejected category=source_rejected\n"
    );
    assert!(rejected_child.try_wait()?.is_none());
    wait_for_ready(operations_port)?;
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &rejected_child.id().to_string()])
            .status()?
            .success()
    );
    assert_eq!(rejected_child.wait()?.code(), Some(0));
    let mut tail = String::new();
    stderr.read_to_string(&mut tail)?;
    assert!(tail.is_empty(), "unexpected child stderr: {tail}");
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
fn status_value<'response>(
    response: &'response str,
    field: &str,
) -> Result<&'response str, Box<dyn std::error::Error>> {
    let prefix = format!("\"{field}\":");
    let value = response
        .split_once(&prefix)
        .map(|(_, value)| value)
        .ok_or_else(|| format!("status field {field} missing"))?;
    value
        .split([',', '}'])
        .next()
        .map(|value| value.trim_matches('"'))
        .ok_or_else(|| format!("status field {field} missing value").into())
}

#[cfg(unix)]
const CONFIGURATION_RESTORE_PROBE_TIMEOUT: Duration = Duration::from_millis(2_500);

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ConfigurationStatus {
    phase: String,
    observed_generation: String,
    effective_digest: String,
    desired_digest: String,
    drift_disposition: String,
    pending_restart: bool,
}

#[cfg(unix)]
impl ConfigurationStatus {
    fn from_response(response: &str) -> Result<Self, Box<dyn std::error::Error>> {
        if !response.starts_with("HTTP/1.1 200 ") {
            return Err("configuration status did not return HTTP 200".into());
        }
        let pending_restart = match status_value(response, "pending_restart")? {
            "true" => true,
            "false" => false,
            value => {
                return Err(format!("configuration pending_restart was invalid: {value}").into());
            },
        };
        Ok(Self {
            phase: status_value(response, "phase")?.to_owned(),
            observed_generation: status_value(response, "observed_generation")?.to_owned(),
            effective_digest: status_value(response, "effective_digest")?.to_owned(),
            desired_digest: status_value(response, "desired_digest")?.to_owned(),
            drift_disposition: status_value(response, "drift_disposition")?.to_owned(),
            pending_restart,
        })
    }

    fn is_restored(&self) -> bool {
        self.phase == "serving"
            && !self.pending_restart
            && self.drift_disposition == "none"
            && self.effective_digest == self.desired_digest
    }

    fn is_unchanged_pending_reconciliation_of(&self, pending: &Self) -> bool {
        self.phase == "serving"
            && self.pending_restart
            && self.drift_disposition == "reconcile"
            && self.observed_generation == pending.observed_generation
            && self.effective_digest == pending.effective_digest
            && self.desired_digest == pending.desired_digest
    }
}

#[cfg(unix)]
fn restore_configuration_with_at_most_one_retry(
    pending: &ConfigurationStatus,
    send_reload: &mut impl FnMut() -> Result<(), Box<dyn std::error::Error>>,
    mut observe: impl FnMut() -> Result<String, Box<dyn std::error::Error>>,
    authorization: &str,
    probe_timeout: Duration,
) -> Result<(String, bool), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + probe_timeout;
    send_reload()?;
    let mut second_reload_sent = false;

    loop {
        let last_observation = match observe() {
            Ok(response) => match ConfigurationStatus::from_response(&response) {
                Ok(status) if status.is_restored() => return Ok((response, second_reload_sent)),
                Ok(status)
                    if !second_reload_sent
                        && status.is_unchanged_pending_reconciliation_of(pending) =>
                {
                    second_reload_sent = true;
                    send_reload()?;
                    "unchanged_pending_reconciliation".to_owned()
                },
                Ok(status) => {
                    format!(
                        "phase={} pending_restart={} drift_disposition={} effective_digest={} desired_digest={}",
                        status.phase,
                        status.pending_restart,
                        status.drift_disposition,
                        status.effective_digest,
                        status.desired_digest,
                    )
                },
                Err(error) => {
                    format!(
                        "parse={error} response={:?}",
                        bounded_redacted_observation(&response, authorization)
                    )
                },
            },
            Err(error) => format!("request={error}"),
        };
        if Instant::now() >= deadline {
            return Err(format!(
                "configuration did not restore within the original bounded reload probe: {}",
                last_observation
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(unix)]
#[test]
fn configuration_restore_probe_accepts_immediate_serving_convergence()
-> Result<(), Box<dyn std::error::Error>> {
    let pending = ConfigurationStatus::from_response(&configuration_status_response(
        "serving",
        "12",
        "old",
        "new",
        "reconcile",
        true,
    )?)?;
    let restored = configuration_status_response("serving", "12", "base", "base", "none", false)?;
    let mut signals = 0;
    let (response, retried) = restore_configuration_with_at_most_one_retry(
        &pending,
        &mut || {
            signals += 1;
            Ok(())
        },
        || Ok(restored.clone()),
        "Bearer test-token",
        Duration::ZERO,
    )?;
    assert_eq!(signals, 1);
    assert!(!retried);
    assert_eq!(
        ConfigurationStatus::from_response(&response)?.observed_generation,
        "12"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn configuration_restore_probe_retries_once_for_unchanged_pending_reconciliation()
-> Result<(), Box<dyn std::error::Error>> {
    let pending_response =
        configuration_status_response("serving", "12", "old", "new", "reconcile", true)?;
    let pending = ConfigurationStatus::from_response(&pending_response)?;
    let restored = configuration_status_response("serving", "12", "base", "base", "none", false)?;
    let mut observations = [pending_response, restored].into_iter();
    let mut signals = 0;
    let (response, retried) = restore_configuration_with_at_most_one_retry(
        &pending,
        &mut || {
            signals += 1;
            Ok(())
        },
        || {
            observations
                .next()
                .ok_or_else(|| "configuration status observations exhausted".into())
        },
        "Bearer test-token",
        Duration::from_secs(1),
    )?;
    assert_eq!(signals, 2);
    assert!(retried);
    assert!(ConfigurationStatus::from_response(&response)?.is_restored());
    Ok(())
}

#[cfg(unix)]
#[test]
fn configuration_restore_probe_never_retries_a_changed_pending_status()
-> Result<(), Box<dyn std::error::Error>> {
    let pending = ConfigurationStatus::from_response(&configuration_status_response(
        "serving",
        "12",
        "old",
        "new",
        "reconcile",
        true,
    )?)?;
    let changed =
        configuration_status_response("serving", "12", "old", "other", "reconcile", true)?;
    let mut signals = 0;
    let error = restore_configuration_with_at_most_one_retry(
        &pending,
        &mut || {
            signals += 1;
            Ok(())
        },
        || Ok(changed.clone()),
        "Bearer test-token",
        Duration::ZERO,
    )
    .expect_err("a changed pending status must not trigger a second reload");
    assert_eq!(signals, 1);
    assert!(error.to_string().contains("original bounded reload probe"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn configuration_restore_probe_never_retries_a_generation_changed_pending_status()
-> Result<(), Box<dyn std::error::Error>> {
    let pending = ConfigurationStatus::from_response(&configuration_status_response(
        "serving",
        "12",
        "old",
        "new",
        "reconcile",
        true,
    )?)?;
    let changed = configuration_status_response("serving", "13", "old", "new", "reconcile", true)?;
    let mut signals = 0;
    let error = restore_configuration_with_at_most_one_retry(
        &pending,
        &mut || {
            signals += 1;
            Ok(())
        },
        || Ok(changed.clone()),
        "Bearer test-token",
        Duration::ZERO,
    )
    .expect_err("a changed generation must not trigger a second reload");
    assert_eq!(signals, 1);
    assert!(error.to_string().contains("original bounded reload probe"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn configuration_restore_probe_never_sends_a_third_reload_for_unresolved_pending_status()
-> Result<(), Box<dyn std::error::Error>> {
    let pending_response =
        configuration_status_response("serving", "12", "old", "new", "reconcile", true)?;
    let pending = ConfigurationStatus::from_response(&pending_response)?;
    let mut signals = 0;
    let error = restore_configuration_with_at_most_one_retry(
        &pending,
        &mut || {
            signals += 1;
            Ok(())
        },
        || Ok(pending_response.clone()),
        "Bearer test-token",
        Duration::ZERO,
    )
    .expect_err("an unresolved pending status must fail after the single permitted retry");
    assert_eq!(signals, 2);
    assert!(error.to_string().contains("original bounded reload probe"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn reconciliation_stderr_accepts_only_the_bounded_retry_variants() {
    let baseline = "positron: warning: operations transport is plaintext\npositron: configuration reload rejected category=source_rejected\n";
    let publication_before_source = "positron: warning: operations transport is plaintext\npositron: configuration reload rejected category=publication_unavailable\npositron: configuration reload rejected category=source_rejected\n";
    let duplicate_publication = "positron: warning: operations transport is plaintext\npositron: configuration reload rejected category=publication_unavailable\npositron: configuration reload rejected category=publication_unavailable\npositron: configuration reload rejected category=source_rejected\n";

    assert!(reconciliation_stderr_is_exact(false, baseline));
    assert!(!reconciliation_stderr_is_exact(
        false,
        publication_before_source
    ));
    assert!(reconciliation_stderr_is_exact(true, baseline));
    assert!(reconciliation_stderr_is_exact(
        true,
        publication_before_source
    ));
    assert!(!reconciliation_stderr_is_exact(true, duplicate_publication));
}

#[cfg(unix)]
fn reconciliation_stderr_is_exact(retried: bool, stderr: &str) -> bool {
    let baseline = "positron: warning: operations transport is plaintext\npositron: configuration reload rejected category=source_rejected\n";
    let publication_before_source = "positron: warning: operations transport is plaintext\npositron: configuration reload rejected category=publication_unavailable\npositron: configuration reload rejected category=source_rejected\n";
    stderr == baseline || (retried && stderr == publication_before_source)
}

#[cfg(unix)]
fn configuration_status_response(
    phase: &str,
    generation: &str,
    effective_digest: &str,
    desired_digest: &str,
    disposition: &str,
    pending_restart: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(format!(
        "HTTP/1.1 200 OK\r\n\r\n{{\"phase\":\"{phase}\",\"observed_generation\":{generation},\"effective_digest\":\"{effective_digest}\",\"desired_digest\":\"{desired_digest}\",\"drift_disposition\":\"{disposition}\",\"pending_restart\":{pending_restart}}}"
    ))
}

#[cfg(unix)]
fn terminate_and_describe_child(child: &mut std::process::Child, authorization: &str) -> String {
    const MAX_CHILD_STDERR_BYTES: u64 = 4 * 1024;

    let termination = match Command::new("/bin/kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
    {
        Ok(status) if status.success() => "term=sent".to_owned(),
        Ok(status) => format!("term=exit_{status}"),
        Err(error) => format!("term_error={error}"),
    };
    let exit = match wait_for_child(child) {
        Ok(status) => format!("exit={status}"),
        Err(error) => format!("exit_error={error}"),
    };
    let stderr = child
        .stderr
        .take()
        .map(|mut stderr| {
            let mut bytes = Vec::with_capacity((MAX_CHILD_STDERR_BYTES + 1) as usize);
            match stderr
                .by_ref()
                .take(MAX_CHILD_STDERR_BYTES + 1)
                .read_to_end(&mut bytes)
            {
                Ok(_) => {
                    let truncated = bytes.len() > MAX_CHILD_STDERR_BYTES as usize;
                    bytes.truncate(MAX_CHILD_STDERR_BYTES as usize);
                    let observation = bounded_redacted_observation(
                        &String::from_utf8_lossy(&bytes),
                        authorization,
                    );
                    truncated
                        .then_some(format!("{observation}…<truncated>"))
                        .unwrap_or(observation)
                },
                Err(error) => format!("stderr_read_error={error}"),
            }
        })
        .unwrap_or_else(|| "stderr_unavailable".to_owned());
    format!("child_cleanup {termination} {exit} stderr={stderr:?}")
}

#[cfg(unix)]
#[test]
fn sighup_during_recovery_does_not_interrupt_native_startup()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "positron-recovery-sighup-{}-{nonce}",
        std::process::id()
    ));
    let data = root.join("data");
    let secrets = root.join("secrets");
    fs::create_dir_all(&data)?;
    fs::create_dir_all(&secrets)?;
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))?;
    let [
        operations_port,
        api_port,
        otlp_grpc_port,
        otlp_http_port,
        loki_push_port,
    ] = available_ports()?;
    let config_path = root.join("positron.toml");
    fs::write(
        &config_path,
        process_configuration(
            &root,
            &data,
            &secrets,
            [
                operations_port,
                api_port,
                otlp_grpc_port,
                otlp_http_port,
                loki_push_port,
            ],
        ),
    )?;
    let ownership = positron_kernel::PrimaryDataVolume::acquire(
        &data,
        positron_kernel::MountQualification::LocalHost,
    )?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["serve", "--init-if-empty", "--config"])
        .arg(&config_path)
        .spawn()?;

    wait_for_readiness(operations_port, "HTTP/1.1 503 ")?;
    assert!(
        Command::new("/bin/kill")
            .args(["-HUP", &child.id().to_string()])
            .status()?
            .success()
    );
    assert!(child.try_wait()?.is_none());

    drop(ownership);
    wait_for_ready(operations_port)?;
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &child.id().to_string()])
            .status()?
            .success()
    );
    assert_eq!(child.wait()?.code(), Some(0));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn fenced_native_process_stays_alive_until_signal_and_retains_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-fenced-{}-{nonce}", std::process::id()));
    let roots = ChildRoots::new(&root)?;
    fs::write(roots.data.join("foreign"), b"ambiguous")?;
    let [
        operations_port,
        api_port,
        otlp_grpc_port,
        otlp_http_port,
        loki_push_port,
    ] = available_ports()?;
    let configuration = process_configuration(
        &root,
        &roots.data,
        &roots.secrets,
        [
            operations_port,
            api_port,
            otlp_grpc_port,
            otlp_http_port,
            loki_push_port,
        ],
    );
    let config_path = root.join("positron.toml");
    fs::write(&config_path, configuration)?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["serve", "--init-if-empty", "--config"])
        .arg(&config_path)
        .spawn()?;

    wait_for_readiness(operations_port, "HTTP/1.1 503 ")?;
    assert!(child.try_wait()?.is_none());
    assert!(
        positron_kernel::PrimaryDataVolume::acquire(
            &roots.data,
            positron_kernel::MountQualification::LocalHost,
        )
        .is_err()
    );
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &child.id().to_string()])
            .status()?
            .success()
    );
    assert_eq!(wait_for_child(&mut child)?.code(), Some(0));
    assert!(
        positron_kernel::PrimaryDataVolume::acquire(
            &roots.data,
            positron_kernel::MountQualification::LocalHost,
        )
        .is_ok()
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn second_os_signal_escalates_to_forced_exit() -> Result<(), Box<dyn std::error::Error>> {
    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-force-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&root)?;
    let ready = root.join("ready");
    let draining = root.join("draining");
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "blocked_shutdown_child_fixture",
            "--nocapture",
        ])
        .env("POSITRON_BLOCKED_CHILD", &root)
        .spawn()?;
    wait_for_file(&ready)?;
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &child.id().to_string()])
            .status()?
            .success()
    );
    wait_for_file(&draining)?;
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &child.id().to_string()])
            .status()?
            .success()
    );
    assert_eq!(child.wait()?.code(), Some(4));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
#[ignore = "owned subprocess fixture"]
fn blocked_shutdown_child_fixture() -> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::MountQualification;
    use positron_runtime::{
        ApplicationRuntime, BootstrapPaths, HostInputs, InitializationMode, ServeConfiguration,
        ShutdownTrigger,
    };

    let Some(root) = std::env::var_os("POSITRON_BLOCKED_CHILD").map(std::path::PathBuf::from)
    else {
        return Ok(());
    };
    let roots = ChildRoots::new(&root)?;
    let host = BlockedHost;
    let paths = BootstrapPaths::new(&roots.data, &roots.secrets, MountQualification::LocalHost)?;
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::InitializeIfEmpty),
        HostInputs::new(&host, &host),
    )?;
    let mut signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::signal::SIGINT,
        signal_hook::consts::signal::SIGTERM,
    ])?;
    fs::write(root.join("ready"), b"ready")?;
    let Some(_) = signals.forever().next() else {
        return Err("signal stream ended".into());
    };
    let mut draining = process.begin_shutdown();
    fs::write(root.join("draining"), b"draining")?;
    loop {
        if signals.pending().next().is_some() {
            let outcome = draining.finish(ShutdownTrigger::SecondSignal);
            std::process::exit(if outcome == positron_runtime::ExitOutcome::Forced {
                4
            } else {
                3
            });
        }
        assert!(!draining.poll()?);
        std::thread::yield_now();
    }
}
