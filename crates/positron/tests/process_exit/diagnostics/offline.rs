//! Focused process-exit diagnostics coverage.

use super::*;

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
    let selected = verify_stdout
        .lines()
        .find(|line| line.starts_with("report_scope_tenant="))
        .ok_or("global offline verify omitted its first report scope")?;
    let selected_field = |name| {
        selected
            .split_whitespace()
            .find_map(|field| field.strip_prefix(name))
            .ok_or("global offline verify omitted a report scope field")
    };
    let tenant = selected_field("report_scope_tenant=")?;
    let signal = selected_field("report_scope_signal=")?;
    let shard = selected_field("report_scope_shard=")?;
    let scoped_verify = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["verify", "--offline", "--config"])
        .arg(&config)
        .args(["--tenant", tenant, "--signal", signal, "--shard", shard])
        .output()?;
    let scoped_stdout = String::from_utf8(scoped_verify.stdout)?;
    assert_eq!(scoped_verify.status.code(), Some(3), "{scoped_stdout}");
    assert!(scoped_stdout.contains("status=incomplete\n"));
    assert!(
        scoped_stdout.contains("aggregate_scope=selected_scope\n"),
        "a one-scope command must not claim all reachable scopes: {scoped_stdout}"
    );
    assert!(scoped_stdout.contains("report_count=1\n"));
    assert!(scoped_stdout.contains("aggregate_reachable_scopes=2\n"));
    assert!(scoped_stdout.contains(&format!("report_scope_signal={signal}")));
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
