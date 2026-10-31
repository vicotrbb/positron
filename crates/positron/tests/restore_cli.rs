//! Real backup owner and separate offline restore command processes.
#![cfg(unix)]
#[path = "support/native_binary.rs"]
mod native_binary;
use age::secrecy::ExposeSecret;
use positron_api::{
    backup::{BackupRequest, BackupServiceClient, BackupTransport},
    repository::{RepositoryRequest, RepositoryServiceClient, RepositoryTransport},
};
use positron_runtime::{
    ApplicationRuntime, BootstrapPaths, HostInputs, InitializationMode, InitializationPlan,
    InstanceBootstrap, ListenerRole, NativeBindings, NativeHost, ServeConfiguration,
    ShutdownTrigger,
};
use std::{
    fs,
    io::Write,
    net::{Ipv4Addr, SocketAddr},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn directory(path: &Path) -> Result {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn host(root: &Path, suffix: &str) -> Result<NativeHost> {
    let endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    Ok(NativeHost::new(NativeBindings::new(
        root.join(format!("{suffix}.sock")),
        endpoint,
        endpoint,
        endpoint,
        endpoint,
        endpoint,
    )?))
}
fn command(action: &str, arguments: &[String], private: &[&str]) -> Result<Output> {
    let mut child = Command::new(native_binary::executable());
    child.args(["backup", "restore", action]).args(arguments);
    command_output(child, private)
}
fn command_output(mut child: Command, private: &[&str]) -> Result<Output> {
    let output = child.output()?;
    for secret in private {
        for bytes in [&output.stdout, &output.stderr] {
            assert!(
                !bytes
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes()),
                "restore output must not disclose secret inputs"
            );
        }
    }
    Ok(output)
}
fn field(output: &Output, key: &str) -> Result<String> {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
        assert_eq!(value["kind"], "backup_restore");
        assert!(value["operation_revision"].is_u64());
        assert!(
            value["operation"]["lookup_expires_at_unix_seconds"].is_null()
                || value["operation"]["lookup_expires_at_unix_seconds"].is_u64()
        );
        let field = match key {
            "operation_id" => &value["operation"]["id"],
            "status" => &value["operation"]["status"],
            "operation_revision" => &value["operation_revision"],
            _ => &value[key],
        };
        return field
            .as_str()
            .map(String::from)
            .or_else(|| field.as_u64().map(|value| value.to_string()))
            .ok_or_else(|| format!("missing public JSON {key}").into());
    }
    let prefix = format!("{key}=");
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .find_map(|field| field.strip_prefix(&prefix))
        .map(String::from)
        .ok_or_else(|| format!("missing public {key}").into())
}
#[test]
fn native_restore_commands_own_durable_start_status_wait_cancel_and_reopen() -> Result {
    let root = fs::canonicalize(std::env::temp_dir())?
        .join(format!("positron-restore-process-{}", std::process::id()));
    directory(&root)?;
    for name in ["data", "secrets", "export", "repository"] {
        directory(&root.join(name))?;
    }
    let paths = BootstrapPaths::new(
        &root.join("data"),
        &root.join("secrets"),
        positron_kernel::MountQualification::LocalHost,
    )?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let source = InstanceBootstrap::reopen(&paths)?;
    let pin = source.recovery_identity()?;
    let identity = age::x25519::Identity::generate();
    let private = identity.to_string();
    let identity_path = root.join("export/identity.age");
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&identity_path)?
        .write_all(private.expose_secret().as_bytes())?;
    let bundle = root.join("export/source.age");
    source.create_recovery_bundle(
        &bundle,
        &positron_kernel::RecoveryRecipients::parse(&[identity.to_public().to_string()])?,
    )?;
    source.verify_recovery_bundle(
        &bundle,
        positron_kernel::RecoveryUnlock::IdentityFile(&identity_path),
    )?;
    drop(source);
    let repository_id = "11111111-1111-4111-8111-111111111111";
    let mut repository_bytes = [0x11; 16];
    *repository_bytes.get_mut(6).ok_or("repository UUID")? = 0x41;
    *repository_bytes.get_mut(8).ok_or("repository UUID")? = 0x81;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let repository_identity = positron_backup::RepositoryIdentity::local(
        repository_bytes,
        pin.instance().to_bytes(),
        pin.integrity().fingerprint(),
        &root.join("repository"),
    )?;
    drop(
        runtime.block_on(positron_backup::LocalRepository::initialize(
            &root.join("repository"),
            repository_identity,
        ))?,
    );
    let source_host = host(&root, "source")?;
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&source_host, &source_host),
    )?;
    let endpoint = process
        .bound_endpoints()
        .into_iter()
        .find(|endpoint| endpoint.role() == ListenerRole::Api)
        .and_then(|endpoint| endpoint.socket_address())
        .ok_or("source API")?;
    let repository_client =
        RepositoryServiceClient::new(RepositoryTransport::PlaintextOptOut { endpoint })?;
    let backup_client = BackupServiceClient::new(BackupTransport::PlaintextOptOut { endpoint })?;
    // The Intel hosted runner exceeded 30 seconds while backup verification
    // still advanced. Keep one bounded setup deadline and one accepted
    // operation through the canonical public wait.
    let deadline = Instant::now() + Duration::from_secs(60);
    let accepted = loop {
        let status = match repository_client.manage(
            claim.secret(),
            &RepositoryRequest::decode(br#"{"action":"status"}"#)?,
        ) {
            Ok(status) => status,
            Err(positron_api::repository::RepositoryServiceClientFailure::CapacityUnavailable)
                if Instant::now() < deadline =>
            {
                std::thread::sleep(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(5)),
                );
                if Instant::now() >= deadline {
                    return Err(
                        "source repository status exhausted the original admission deadline".into(),
                    );
                }
                continue;
            },
            Err(error) => return Err(format!("source repository status read: {error:?}").into()),
        };
        let request = BackupRequest::decode(&serde_json::to_vec(&serde_json::json!({
            "action":"create", "expected_catalog_generation":status.catalog_generation,
            "idempotency_key":"22222222-2222-4222-8222-222222222222", "repository_id":repository_id,
            "locator":root.join("repository").to_string_lossy(), "retention_seconds":3600
        }))?)?;
        match backup_client.manage(claim.secret(), &request) {
            Ok(accepted) => break accepted,
            Err(positron_api::backup::BackupServiceClientFailure::StaleGeneration)
                if Instant::now() < deadline => {},
            Err(error) => return Err(format!("source backup admission: {error:?}").into()),
        }
    };
    // The canonical CLI wait uses its existing 100ms read cadence. Its own
    // whole-second budget is rounded down; the original fixture deadline also
    // bounds process initialization and every output wait.
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or("source backup original deadline expired before public wait")?;
    let mut wait = Command::new(native_binary::executable())
        .args([
            "backup",
            "wait",
            "--endpoint",
            &endpoint.to_string(),
            "--allow-plaintext",
            "--credential-stdin",
            "--operation-id",
            &accepted.operation.id,
            "--wait-seconds",
            &remaining.as_secs().to_string(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let supervision = (|| -> Result {
        wait.stdin
            .take()
            .ok_or("source backup credential pipe")?
            .write_all(claim.secret().as_bytes())?;
        Ok(())
    })();
    if let Err(primary) = supervision {
        if let Err(cleanup) = wait.kill()
            && !matches!(
                cleanup.kind(),
                std::io::ErrorKind::InvalidInput | std::io::ErrorKind::NotFound
            )
        {
            eprintln!("source backup wait kill cleanup: {cleanup}");
        }
        if let Err(cleanup) = wait.wait() {
            eprintln!("source backup wait reap cleanup: {cleanup}");
        }
        return Err(primary);
    }
    let published = collect_source_backup(wait, deadline)?;
    if Instant::now() >= deadline {
        return Err(format!("source backup public wait completed after its original deadline: status={:?} phase={:?} terminal_error_code={:?}", field(&published, "status"), field(&published, "phase"), field(&published, "terminal_error_code")).into());
    }
    for bytes in [&published.stdout, &published.stderr] {
        assert!(!String::from_utf8_lossy(bytes).contains(claim.secret()));
    }
    assert!(
        published.status.success(),
        "source backup public wait refused: {}; status={:?} phase={:?} terminal_error_code={:?}",
        String::from_utf8_lossy(&published.stderr),
        field(&published, "status"),
        field(&published, "phase"),
        field(&published, "terminal_error_code")
    );
    assert_eq!(field(&published, "operation_id")?, accepted.operation.id);
    assert_eq!(field(&published, "status")?, "succeeded");
    let manifest_checksum = field(&published, "manifest_checksum")?;
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    for cancelled in [true, false] {
        let target = root.join(if cancelled { "cancelled" } else { "restored" });
        directory(&target)?;
        directory(&target.join("data"))?;
        directory(&target.join("secrets"))?;
        let configuration = target.join("positron.toml");
        fs::write(
            &configuration,
            format!(
                "schema_version = 1\n[storage]\ndata_directory = {:?}\nsecrets_directory = {:?}\n",
                target.join("data"),
                target.join("secrets")
            ),
        )?;
        let mut arguments = Vec::new();
        for (key, value) in [
            ("--output", "json".into()),
            ("--config", configuration.to_string_lossy().into_owned()),
            (
                "--locator",
                root.join("repository").to_string_lossy().into_owned(),
            ),
            ("--repository-id", repository_id.into()),
            ("--snapshot-id", accepted.operation.id.clone()),
            ("--expected-manifest-checksum", manifest_checksum.clone()),
            (
                "--idempotency-key",
                "33333333-3333-4333-8333-333333333333".into(),
            ),
            ("--instance", hex(&pin.instance().to_bytes())),
            ("--root-key-id", hex(&pin.root().key_id())),
            (
                "--root-created-at",
                pin.root().created_at_unix_seconds().to_string(),
            ),
            ("--root-fingerprint", hex(&pin.root().fingerprint())),
            ("--integrity-public-key", hex(&pin.integrity().public_key())),
            (
                "--integrity-fingerprint",
                hex(&pin.integrity().fingerprint()),
            ),
            ("--bundle", bundle.to_string_lossy().into_owned()),
            (
                "--identity-file",
                identity_path.to_string_lossy().into_owned(),
            ),
        ] {
            arguments.extend([key.into(), value]);
        }
        let secrets = [private.expose_secret(), claim.secret()];
        if cancelled {
            // Refuse a separate target once; never replay an ambiguous start.
            let refused_target = root.join("refused");
            directory(&refused_target)?;
            directory(&refused_target.join("data"))?;
            directory(&refused_target.join("secrets"))?;
            let refused_repository = root.join("private-empty-repository");
            directory(&refused_repository)?;
            let refused_config = refused_target.join("private-request-config.toml");
            fs::write(
                &refused_config,
                format!(
                    "schema_version = 1\n[storage]\ndata_directory = {:?}\nsecrets_directory = {:?}\n",
                    refused_target.join("data"),
                    refused_target.join("secrets")
                ),
            )?;
            let mut refused_arguments = arguments.clone();
            for (flag, value) in [
                ("--config", refused_config.to_string_lossy().into_owned()),
                (
                    "--locator",
                    refused_repository.to_string_lossy().into_owned(),
                ),
                (
                    "--idempotency-key",
                    "88888888-8888-4888-8888-888888888888".into(),
                ),
            ] {
                let position = refused_arguments
                    .iter()
                    .position(|item| item == flag)
                    .ok_or("restore option")?;
                *refused_arguments
                    .get_mut(position + 1)
                    .ok_or("restore value")? = value;
            }
            let refused = command("start", &refused_arguments, &secrets)?;
            assert_eq!(refused.status.code(), Some(2));
            assert!(
                refused.stdout.is_empty(),
                "a refused start must not render an accepted receipt"
            );
            let error = std::str::from_utf8(&refused.stderr)?;
            assert!(error.contains("restore unavailable; require a fresh target or the exact accepted restore identity and sufficient admitted resources"), "refusal must reach runtime begin");
            let code = error
                .lines()
                .find_map(|line| line.strip_prefix("positron: restore begin refused; code="))
                .ok_or("closed restore begin code missing")?;
            assert!(
                !code.is_empty()
                    && code.len() <= 64
                    && code.bytes().all(|byte| byte.is_ascii_alphanumeric())
            );
            assert!(!error.contains(root.to_str().ok_or("private root")?));
            assert!(!error.contains("BootstrapFailure {"));
            assert!(!error.contains("positron: restore resource refusal;"));
            // A separate child-only limit forces real observation/admission refusal;
            // no shared process limit or already attempted restore target is changed.
            let denied = root.join("resource-denied");
            directory(&denied)?;
            directory(&denied.join("data"))?;
            directory(&denied.join("secrets"))?;
            let denied_config = denied.join("positron.toml");
            fs::write(
                &denied_config,
                format!(
                    "schema_version = 1\n[storage]\ndata_directory = {:?}\nsecrets_directory = {:?}\n",
                    denied.join("data"),
                    denied.join("secrets")
                ),
            )?;
            let mut denied_arguments = arguments.clone();
            for (flag, value) in [
                ("--config", denied_config.to_string_lossy().into_owned()),
                (
                    "--idempotency-key",
                    "99999999-9999-4999-8999-999999999999".into(),
                ),
            ] {
                let index = denied_arguments
                    .iter()
                    .position(|item| item == flag)
                    .ok_or("restore option")?;
                *denied_arguments.get_mut(index + 1).ok_or("restore value")? = value;
            }
            let mut child = Command::new("/bin/sh");
            child
                .args([
                    "-c",
                    "ulimit -n 32 || exit 125; exec \"$@\"",
                    "restore-resource-fixture",
                ])
                .arg(native_binary::executable())
                .args(["backup", "restore", "start"])
                .args(&denied_arguments);
            let refused = command_output(child, &secrets)?;
            assert_eq!(refused.status.code(), Some(2));
            assert!(refused.stdout.is_empty());
            let error = std::str::from_utf8(&refused.stderr)?;
            assert!(error.contains("restore unavailable; require a fresh target or the exact accepted restore identity and sufficient admitted resources"), "denial must reach runtime begin");
            assert!(error.lines().any(|line| line == "positron: restore begin refused; code=ResourceUnavailable"), "fixture must produce real ResourceUnavailable before checking new diagnostic fields");
            let context = error
                .lines()
                .find_map(|line| line.strip_prefix("positron: restore resource refusal; "))
                .ok_or("closed restore resource context missing")?;
            let context: serde_json::Value = serde_json::from_str(context)?;
            assert!(matches!(
                context["resource_stage"].as_str(),
                Some("observation" | "governor" | "restore_initial_grant")
            ));
            assert!(context["resource_reason"].is_string());
            assert!(!error.contains(root.to_str().ok_or("private root")?));
            assert!(!error.contains("BootstrapFailure {"));
        }
        assert!(!command("status", &arguments, &secrets)?.status.success());
        assert!(!target.join("data/catalog").exists());
        let started = command("start", &arguments, &secrets)?;
        assert!(
            started.status.success(),
            "{}",
            String::from_utf8_lossy(&started.stderr)
        );
        assert_eq!(field(&started, "status")?, "pending");
        let status = command("status", &arguments, &secrets)?;
        assert!(status.status.success());
        assert_eq!(status.stdout, started.stdout);
        arguments.extend(["--operation-id".into(), field(&started, "operation_id")?]);
        if cancelled {
            let mut cancel = arguments.clone();
            cancel.extend([
                "--cancellation-key".into(),
                "44444444-4444-4444-8444-444444444444".into(),
                "--expected-operation-revision".into(),
                "0".into(),
            ]);
            let refused = command("cancel", &cancel, &secrets)?;
            assert!(!refused.status.success());
            assert_eq!(field(&refused, "status")?, "pending");
            assert_eq!(
                command("status", &arguments, &secrets)?.stdout,
                started.stdout
            );
            *cancel.last_mut().ok_or("revision")? = field(&started, "operation_revision")?;
            let cancelled = command("cancel", &cancel, &secrets)?;
            assert!(cancelled.status.success());
            assert_eq!(field(&cancelled, "status")?, "cancelled");
            let cancelled_wait = command("wait", &arguments, &secrets)?;
            assert!(!cancelled_wait.status.success());
            assert_eq!(field(&cancelled_wait, "status")?, "cancelled");
            assert!(!target.join("data/.positron-bootstrap.initialized").exists());
        } else {
            let completed = command("wait", &arguments, &secrets)?;
            assert!(
                completed.status.success(),
                "{}",
                String::from_utf8_lossy(&completed.stderr)
            );
            assert_eq!(field(&completed, "status")?, "succeeded");
            assert!(field(&completed, "verification_report").is_ok());
            assert_eq!(
                command("wait", &arguments, &secrets)?.stdout,
                completed.stdout
            );
            let restored_paths = BootstrapPaths::new(
                &target.join("data"),
                &target.join("secrets"),
                positron_kernel::MountQualification::LocalHost,
            )?;
            let restored_host = host(&root, "restored")?;
            let restored = ApplicationRuntime::start(
                ServeConfiguration::new(restored_paths, InitializationMode::ExistingOnly),
                HostInputs::new(&restored_host, &restored_host),
            )?;
            assert!(
                restored
                    .services()
                    .ok_or("restored query services")?
                    .query_log_bodies(
                        claim.query_secret().ok_or("query credential")?,
                        "logs | range query_time 0 100 | limit 10",
                        positron_query::QueryBudget::new(
                            1_000_000, 100, 100, 1_000_000, 1_000_000, 60
                        )?
                        .with_cpu_work_units(16)?
                    )?
                    .is_empty()
            );
            assert_eq!(
                restored.shutdown(ShutdownTrigger::FirstSignal),
                positron_runtime::ExitOutcome::Graceful
            );
        }
    }
    drop(claim);
    drop(runtime);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[path = "support/bounded_child_output.rs"]
mod child_output;

fn collect_source_backup(child: std::process::Child, deadline: Instant) -> Result<Output> {
    Ok(child_output::wait_before(
        child,
        deadline,
        Duration::from_millis(5),
        "source backup public wait exceeded its original deadline",
    )?)
}

#[path = "support/output_pressure.rs"]
mod output_pressure;

#[test]
fn source_backup_capture_drains_both_streams_before_waiting_for_exit() -> Result {
    let output = collect_source_backup(
        output_pressure::child()?,
        Instant::now() + Duration::from_secs(5),
    )?;
    assert!(output.status.success());
    assert!(
        output.stdout == vec![b'x'; 256 * 1024],
        "stdout capture changed"
    );
    assert!(
        output.stderr == vec![b'x'; 256 * 1024],
        "stderr capture changed"
    );
    Ok(())
}
