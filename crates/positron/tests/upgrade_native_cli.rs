//! Real CLI admission and Process Drain; candidate metadata is synthetic, not two-build qualification.
#![cfg(unix)]
#[path = "support/native_binary.rs"]
mod native_binary;
use positron_api::{
    backup::{BackupRequest, BackupServiceClient, BackupServiceClientFailure, BackupTransport},
    repository::{
        RepositoryRequest, RepositoryServiceClient, RepositoryServiceClientFailure,
        RepositoryTransport,
    },
};
use positron_kernel::MountQualification;
use positron_runtime::*;
use std::{
    fs,
    io::Write,
    net::{Ipv4Addr, SocketAddr},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const REPOSITORY: &str = "11111111-1111-4111-8111-111111111111";
const KEY: &str = "77777777-7777-4777-8777-777777777777";
fn fixture_id() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn directory(path: &Path) -> Result {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn host(name: &str) -> Result<NativeHost> {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    Ok(NativeHost::new(NativeBindings::new(
        std::env::temp_dir().join(format!(
            "p-uc-{}-{}-{name}.sock",
            std::process::id(),
            fixture_id()
        )),
        address,
        address,
        address,
        address,
        address,
    )?))
}
fn endpoint(process: &RunningProcess) -> Result<SocketAddr> {
    process
        .bound_endpoints()
        .into_iter()
        .find(|e| e.role() == ListenerRole::Api)
        .and_then(|e| e.socket_address())
        .ok_or_else(|| "native API endpoint".into())
}
fn generation(client: &RepositoryServiceClient, bearer: &str) -> Result<u64> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match client.manage(
            bearer,
            &RepositoryRequest::decode(br#"{"action":"status"}"#)?,
        ) {
            Ok(status) => return Ok(status.catalog_generation),
            Err(RepositoryServiceClientFailure::AdministrationUnavailable)
                if Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(100))
            },
            Err(error) => return Err(error.into()),
        }
    }
}
fn register_repository(paths: &BootstrapPaths, root: &Path, bearer: &str) -> Result {
    let instance = InstanceBootstrap::reopen(paths)?;
    let identity = age::x25519::Identity::generate();
    let bundle = root.join("export/recovery.age");
    instance.create_recovery_bundle(
        &bundle,
        &positron_kernel::RecoveryRecipients::parse(&[identity.to_public().to_string()])?,
    )?;
    instance.verify_recovery_bundle(
        &bundle,
        positron_kernel::RecoveryUnlock::Identity(&identity),
    )?;
    let pin = instance.recovery_identity()?;
    let mut repository = [0x11; 16];
    *repository.get_mut(6).ok_or("UUID")? = 0x41;
    *repository.get_mut(8).ok_or("UUID")? = 0x81;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    drop(
        runtime.block_on(positron_backup::LocalRepository::initialize(
            &root.join("repository"),
            positron_backup::RepositoryIdentity::local(
                repository,
                pin.instance().to_bytes(),
                pin.integrity().fingerprint(),
                &root.join("repository"),
            )?,
        ))?,
    );
    drop(instance);
    let host = host("register")?;
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let address = endpoint(&process)?;
    let repositories =
        RepositoryServiceClient::new(RepositoryTransport::PlaintextOptOut { endpoint: address })?;
    let backups = BackupServiceClient::new(BackupTransport::PlaintextOptOut { endpoint: address })?;
    let deadline = Instant::now() + Duration::from_secs(120);
    let accepted = loop {
        let request =
            BackupRequest::decode(&serde_json::to_vec(&serde_json::json!({"action":"create",
            "expected_catalog_generation":generation(&repositories,bearer)?,
            "idempotency_key":"22222222-2222-4222-8222-222222222222","repository_id":REPOSITORY,
            "locator":root.join("repository"),"retention_seconds":3600}))?)?;
        match backups.manage(bearer, &request) {
            Ok(accepted) => break accepted,
            Err(
                BackupServiceClientFailure::PreconditionFailed
                | BackupServiceClientFailure::AdministrationUnavailable,
            ) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            Err(error) => return Err(error.into()),
        }
    };
    let lookup =
        BackupRequest::decode(&serde_json::to_vec(&serde_json::json!({"action":"status",
        "operation_id":accepted.operation.id}))?)?;
    loop {
        let status = backups.manage(bearer, &lookup)?;
        if status.operation.status == "succeeded" {
            assert!(status.receipt.is_some());
            break;
        }
        assert_ne!(status.operation.status, "failed", "{status:?}");
        assert!(
            Instant::now() < deadline,
            "registration backup deadline: {status:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        ExitOutcome::Graceful
    );
    Ok(())
}
#[path = "upgrade_native_cli/release.rs"]
mod release;
use release::configuration;

// Existing foreground-task fixture pattern: real network/control tasks, no autonomous Catalog writer.
struct ForegroundTasks<'a>(&'a NativeHost);
impl TaskRegistrar for ForegroundTasks<'_> {
    fn register(
        &self,
        role: TaskRole,
    ) -> std::result::Result<Box<dyn RegisteredTask>, TaskFailure> {
        if role == TaskRole::Maintenance {
            Ok(Box::new(IdleMaintenance))
        } else {
            self.0.register(role)
        }
    }
}
struct IdleMaintenance;
impl RegisteredTask for IdleMaintenance {
    fn spawn(
        self: Box<Self>,
        _: TaskCancellation,
        _: HealthState,
        _: Option<ServiceHandle>,
    ) -> std::result::Result<Box<dyn RunningTask>, TaskFailure> {
        Ok(self)
    }
}
impl RunningTask for IdleMaintenance {
    fn poll_join(&mut self) -> std::result::Result<Option<TaskJoinOutcome>, TaskFailure> {
        Ok(None)
    }
    fn join_within(&mut self, _: Duration) -> std::result::Result<TaskJoinOutcome, TaskFailure> {
        Ok(TaskJoinOutcome::Joined)
    }
    fn abort(&mut self) -> std::result::Result<(), TaskFailure> {
        Ok(())
    }
}
#[test]
fn real_upgrade_cli_accepts_native_intent_and_completes_the_same_process_drain() -> Result {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let root = fs::canonicalize(std::env::temp_dir())?.join(format!(
        "p-upgrade-cli-{}-{}-{nonce}",
        std::process::id(),
        fixture_id()
    ));
    directory(&root)?;
    for name in ["data", "secrets", "export", "repository"] {
        directory(&root.join(name))?;
    }
    let paths = BootstrapPaths::new(
        &root.join("data"),
        &root.join("secrets"),
        MountQualification::LocalHost,
    )?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    register_repository(&paths, &root, claim.secret())?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let epoch = instance
        .catalog_format_epoch()?
        .ok_or("Catalog epoch")?
        .value();
    drop(instance);
    let (effective, candidate) = configuration(
        &root,
        epoch,
        claim.query_secret().ok_or("query credential")?,
    )?;
    let host = host("upgrade")?;
    let foreground = ForegroundTasks(&host);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::ExistingOnly)
            .with_effective_configuration(Arc::new(effective.clone())),
        HostInputs::new(&host, &foreground),
    )?;
    let address = endpoint(&process)?;
    let client =
        RepositoryServiceClient::new(RepositoryTransport::PlaintextOptOut { endpoint: address })?;
    let generation = generation(&client, claim.secret())?;
    let admission_deadline = Instant::now()
        + effective
            .network_listener_profile(positron_config::NetworkListenerRole::Api)
            .ok_or("API profile")?
            .connection_protection()
            .request_deadline();
    let mut child = Command::new(native_binary::executable())
        .args([
            "upgrade",
            "start",
            "--endpoint",
            &address.to_string(),
            "--allow-plaintext",
            "--credential-stdin",
            "--candidate-manifest",
            &hex(&candidate),
            "--repository-id",
            REPOSITORY,
            "--retention-seconds",
            "3600",
            "--expected-generation",
            &generation.to_string(),
            "--idempotency-key",
            KEY,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    writeln!(
        child.stdin.take().ok_or("credential stdin")?,
        "{}",
        claim.secret()
    )?;
    let mut output = child.wait_with_output()?;
    if !output.status.success() && String::from_utf8_lossy(&output.stderr).contains(
        "transport outcome unknown; inspect the same operation or idempotency key before retrying"
    ) {
        // Resolve the ambiguous start through the actual CLI's same-key lookup.
        // Never resend start or choose a different intent/key.
        loop {
            if Instant::now() >= admission_deadline {
                return Err("ambiguous native acceptance exceeded original API budget".into());
            }
            let mut lookup = Command::new(native_binary::executable())
                .args(["upgrade", "lookup", "--endpoint", &address.to_string(),
                    "--allow-plaintext", "--credential-stdin", "--idempotency-key", KEY])
                .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
            writeln!(lookup.stdin.take().ok_or("lookup stdin")?, "{}", claim.secret())?;
            output = lookup.wait_with_output()?;
            if output.status.success() { break; }
            let error = String::from_utf8_lossy(&output.stderr);
            if !error.contains("upgrade operation unavailable")
                && !error.contains("transport outcome unknown")
                && !error.contains("capacity unavailable; retry the same idempotent request") {
                return Err(format!("native acceptance lookup refused: {error}").into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    assert!(
        output.status.success(),
        "CLI refused native Upgrade: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    assert!(!stdout.contains(claim.secret()));
    let pending = process
        .pending_upgrade_operation()?
        .ok_or("accepted intent")?;
    assert!(
        stdout.contains(&format!(
            "operation_id={}",
            hex(&pending.operation_id().to_bytes())
        )),
        "{stdout}"
    );
    assert_eq!(
        pending
            .upgrade_parameters()
            .ok_or("parameters")?
            .target()
            .manifest_digest(),
        candidate
    );
    let parameters = pending.upgrade_parameters().ok_or("accepted parameters")?;
    assert_eq!(
        parameters.backup().repository().repository_id(),
        positron_domain::identity::TenantId::parse_canonical(REPOSITORY)?.to_bytes()
    );
    assert_eq!(parameters.backup().retention_seconds(), 3600);
    let accepted = process
        .resume_configured_upgrade_drain(&effective)?
        .ok_or("native Drain handoff")?;
    assert_eq!(accepted.operation(), pending);
    let id = process
        .begin_upgrade(accepted)?
        .finish(ShutdownTrigger::FirstSignal)?;
    assert_eq!(id, pending.operation_id());
    let instance = InstanceBootstrap::reopen_configured(&paths, &effective)?;
    let marker = instance
        .graceful_shutdown_record()?
        .ok_or("actual completed Drain marker")?;
    assert!(marker.catalog_generation() > pending.request().accepted_generation());
    drop(instance);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[path = "upgrade_native_cli/offline_recovery.rs"]
mod offline_recovery;
