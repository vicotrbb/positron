//! Real backup owner and separate offline restore command processes.
#![cfg(unix)]
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
    process::{Command, Output},
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
    let output = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["backup", "restore", action])
        .args(arguments)
        .output()?;
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
    let deadline = Instant::now() + Duration::from_secs(30);
    let accepted = loop {
        let status = repository_client.manage(
            claim.secret(),
            &RepositoryRequest::decode(br#"{"action":"status"}"#)?,
        )?;
        let request = BackupRequest::decode(&serde_json::to_vec(&serde_json::json!({
            "action":"create", "expected_catalog_generation":status.catalog_generation,
            "idempotency_key":"22222222-2222-4222-8222-222222222222", "repository_id":repository_id,
            "locator":root.join("repository").to_string_lossy(), "retention_seconds":3600
        }))?)?;
        match backup_client.manage(claim.secret(), &request) {
            Ok(accepted) => break accepted,
            Err(positron_api::backup::BackupServiceClientFailure::PreconditionFailed)
                if Instant::now() < deadline => {},
            Err(error) => return Err(format!("source backup admission: {error:?}").into()),
        }
    };
    let lookup = BackupRequest::decode(&serde_json::to_vec(
        &serde_json::json!({"action":"status", "operation_id":accepted.operation.id}),
    )?)?;
    let published = loop {
        let status = backup_client.manage(claim.secret(), &lookup)?;
        if status.operation.status == "succeeded" {
            break status;
        }
        if status.operation.status == "failed" || Instant::now() >= deadline {
            return Err(format!("source backup did not complete: {status:?}").into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let receipt = published.receipt.ok_or("snapshot receipt")?;
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
            ("--config", configuration.to_string_lossy().into_owned()),
            (
                "--locator",
                root.join("repository").to_string_lossy().into_owned(),
            ),
            ("--repository-id", repository_id.into()),
            ("--snapshot-id", accepted.operation.id.clone()),
            (
                "--expected-manifest-checksum",
                receipt.manifest_checksum.clone(),
            ),
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
            assert!(!command("cancel", &cancel, &secrets)?.status.success());
            assert_eq!(
                command("status", &arguments, &secrets)?.stdout,
                started.stdout
            );
            *cancel.last_mut().ok_or("revision")? = field(&started, "operation_revision")?;
            let cancelled = command("cancel", &cancel, &secrets)?;
            assert!(cancelled.status.success());
            assert_eq!(field(&cancelled, "status")?, "cancelled");
            assert!(!command("wait", &arguments, &secrets)?.status.success());
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
