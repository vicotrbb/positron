//! Installed executable recovery proof; no in-process bootstrap or task owner.
use super::*;
use age::secrecy::ExposeSecret;
use std::{
    collections::BTreeMap,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process::{Output, Stdio},
};

#[derive(Clone, Copy)]
pub(super) struct Installed<'a> {
    pub binary: &'a Path,
    pub config: &'a Path,
    pub endpoint: std::net::SocketAddr,
    pub operations: u16,
    pub admin: &'a str,
    pub query: &'a str,
}
pub(super) struct RecoveryFiles {
    bundle: PathBuf,
    identity: PathBuf,
    pin: BTreeMap<String, String>,
}
fn fields(output: &Output) -> TestResult<BTreeMap<String, String>> {
    Ok(String::from_utf8(output.stdout.clone())?
        .split_whitespace()
        .filter_map(|field| {
            field
                .split_once('=')
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
        })
        .collect())
}
pub(super) fn invoke(
    binary: &Path,
    arguments: &[String],
    credential: Option<&str>,
) -> TestResult<Output> {
    let mut command = Command::new(binary);
    command
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if credential.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn()?;
    if let Some(credential) = credential {
        child
            .stdin
            .take()
            .ok_or("credential pipe")?
            .write_all(credential.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if let Some(credential) = credential {
        assert!(!String::from_utf8_lossy(&output.stdout).contains(credential));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(credential));
    }
    Ok(output)
}
pub(super) fn execute(
    binary: &Path,
    arguments: &[String],
    credential: Option<&str>,
) -> TestResult<Output> {
    let output = invoke(binary, arguments, credential)?;
    assert!(
        output.status.success(),
        "installed command {arguments:?}: {}; public state: {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    Ok(output)
}
pub(super) fn plain(arguments: &[&str]) -> Vec<String> {
    arguments.iter().map(|s| (*s).to_owned()).collect()
}
fn directory(path: &Path) -> TestResult {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
impl RecoveryFiles {
    pub(super) fn create(binary: &Path, root: &Path) -> TestResult<Self> {
        directory(&root.join("export"))?;
        let age = age::x25519::Identity::generate();
        let identity = root.join("export/recovery.identity");
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&identity)?
            .write_all(age.to_string().expose_secret().as_bytes())?;
        let bundle = root.join("export/recovery.age");
        let mut arguments = plain(&["keys", "recovery", "create", "--data-dir"]);
        arguments.extend([
            root.join("data").display().to_string(),
            "--secrets-dir".into(),
            root.join("secrets").display().to_string(),
            "--bundle".into(),
            bundle.display().to_string(),
            "--recipient".into(),
            age.to_public().to_string(),
        ]);
        let pin = fields(&execute(binary, &arguments, None)?)?;
        arguments = plain(&["keys", "recovery", "verify", "--data-dir"]);
        arguments.extend([
            root.join("data").display().to_string(),
            "--secrets-dir".into(),
            root.join("secrets").display().to_string(),
            "--bundle".into(),
            bundle.display().to_string(),
            "--identity-file".into(),
            identity.display().to_string(),
        ]);
        execute(binary, &arguments, None)?;
        Ok(Self {
            bundle,
            identity,
            pin,
        })
    }
}
pub(super) fn online(family: &str, action: &str, endpoint: std::net::SocketAddr) -> Vec<String> {
    let mut arguments = plain(&[family, action, "--endpoint"]);
    arguments.extend([
        endpoint.to_string(),
        "--credential-stdin".into(),
        "--allow-plaintext".into(),
    ]);
    arguments
}
pub(super) fn field(output: &Output, name: &str) -> TestResult<String> {
    fields(output)?
        .remove(name)
        .ok_or_else(|| format!("missing public {name}").into())
}
pub(super) fn mutate(
    family: &str,
    mut request: serde_json::Value,
    endpoint: std::net::SocketAddr,
    admin: &str,
) -> TestResult<String> {
    use positron_api::{
        backup::BackupServiceClient,
        maintenance::MaintenanceServiceClientFailure as F,
        repository::{RepositoryServiceClient, RepositoryTransport},
        upgrade::UpgradeServiceClient,
    };
    let transport = RepositoryTransport::PlaintextOptOut { endpoint };
    let repository =
        RepositoryServiceClient::new(transport.clone()).map_err(|_| "repository client")?;
    let backup = BackupServiceClient::new(transport.clone()).map_err(|_| "backup client")?;
    let upgrade = UpgradeServiceClient::new(transport).map_err(|_| "upgrade client")?;
    let deadline = Instant::now() + Duration::from_secs(30);
    'fresh_status: loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("public mutation generation watchdog expired".into());
        }
        let status = match repository.manage_with_timeout(
            admin,
            &positron_api::repository::RepositoryRequest::decode(br#"{"action":"status"}"#)?,
            remaining,
        ) {
            Ok(status) => status,
            Err(F::CapacityUnavailable) if Instant::now() < deadline => {
                std::thread::sleep(
                    Duration::from_millis(10)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
                continue;
            },
            Err(failure) => {
                return Err(format!("public repository status refused: {failure:?}").into());
            },
        };
        // Generated mutation clients have the canonical five-second request bound.
        if deadline.saturating_duration_since(Instant::now()) < Duration::from_secs(5) {
            return Err("public mutation generation watchdog expired".into());
        }
        request["expected_catalog_generation"] = status.catalog_generation.into();
        let bytes = serde_json::to_vec(&request)?;
        loop {
            if deadline.saturating_duration_since(Instant::now()) < Duration::from_secs(5) {
                return Err("public mutation generation watchdog expired".into());
            }
            let result = match family {
                "repository" => repository
                    .manage(
                        admin,
                        &positron_api::repository::RepositoryRequest::decode(&bytes)?,
                    )
                    .map(|response| response.operation.map(|operation| operation.id)),
                "backup" => backup
                    .manage(admin, &positron_api::backup::BackupRequest::decode(&bytes)?)
                    .map(|response| Some(response.operation.id)),
                "upgrade" => upgrade
                    .manage(
                        admin,
                        &positron_api::upgrade::UpgradeRequest::decode(&bytes)?,
                    )
                    .map(|response| response.operation.map(|operation| operation.id)),
                _ => return Err("unknown public mutation family".into()),
            };
            match result {
                Ok(operation) => return Ok(operation.ok_or("accepted operation missing")?),
                Err(F::StaleGeneration) if Instant::now() < deadline => continue 'fresh_status,
                Err(F::CapacityUnavailable) if Instant::now() < deadline => {
                    std::thread::sleep(
                        Duration::from_millis(10)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                },
                Err(failure) => {
                    return Err(format!("public {family} mutation refused: {failure:?}").into());
                },
            }
        }
    }
}

fn wait(
    binary: &Path,
    family: &str,
    endpoint: std::net::SocketAddr,
    admin: &str,
    operation: &str,
) -> TestResult<Output> {
    eprintln!("installed CLI wait family={family} operation={operation}");
    let mut arguments = online(family, "wait", endpoint);
    arguments.extend([
        "--operation-id".into(),
        operation.into(),
        "--wait-seconds".into(),
        "30".into(),
    ]);
    // Public waits are bounded turns, not a total Backup product SLO.
    // Protected metadata verification advances bounded volatile work without
    // rewriting its already complete remote checkpoint on every turn.
    let watchdog = Instant::now() + Duration::from_secs(300);
    loop {
        let output = invoke(binary, &arguments, Some(admin))?;
        if output.status.success() {
            let state = fields(&output)?;
            assert_eq!(
                field(&output, "status")?,
                "succeeded",
                "public terminal outcome family={family} kind={:?} phase={:?} terminal_error_code={:?}",
                state.get("kind"),
                state.get("phase"),
                state.get("terminal_error_code")
            );
            return Ok(output);
        }
        let error = String::from_utf8_lossy(&output.stderr);
        // Both unknown outcomes require inspecting this same retained ID. This
        // command reads status only; it never resubmits the original mutation.
        let unknown = error.contains("operation outcome remains unknown")
            || error.contains("transport outcome unknown");
        if !unknown || Instant::now() >= watchdog {
            let maintenance = invoke(
                binary,
                &online("maintenance", "status", endpoint),
                Some(admin),
            )?;
            return Err(format!(
                "public {family} wait refused for {operation}: {error}; {}; maintenance: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&maintenance.stdout),
                String::from_utf8_lossy(&maintenance.stderr),
            )
            .into());
        }
    }
}
pub(super) fn roundtrip(
    fixture: &mut Fixture,
    installed: Installed<'_>,
    recovery: &RecoveryFiles,
    expected: &[u8],
) -> TestResult<PathBuf> {
    let Installed {
        binary,
        config,
        endpoint,
        operations,
        admin,
        query,
    } = installed;
    const REPOSITORY: &str = "11111111-1111-4111-8111-111111111111";
    let root = &fixture.root;
    let repository = root.join("repository");
    directory(&repository)?;
    let initialized = mutate(
        "repository",
        serde_json::json!({
            "action": "init", "locator": repository.display().to_string(), "repository_id": REPOSITORY,
            "idempotency_key": "22222222-2222-4222-8222-222222222222"
        }),
        endpoint,
        admin,
    )?;
    wait(binary, "repository", endpoint, admin, &initialized)?;
    let snapshot = mutate(
        "backup",
        serde_json::json!({
            "action": "create", "locator": repository.display().to_string(), "repository_id": REPOSITORY,
            "retention_seconds": 3600, "idempotency_key": "33333333-3333-4333-8333-333333333333"
        }),
        endpoint,
        admin,
    )?;
    let backed_up = wait(binary, "backup", endpoint, admin, &snapshot)?;
    let checksum = field(&backed_up, "manifest_checksum")?;
    let accepted = mutate(
        "backup",
        serde_json::json!({
            "action": "verify", "repository_id": REPOSITORY, "snapshot_id": snapshot,
            "expected_manifest_checksum": checksum, "idempotency_key": "44444444-4444-4444-8444-444444444444"
        }),
        endpoint,
        admin,
    )?;
    let verified = wait(binary, "backup", endpoint, admin, &accepted)?;
    assert!(fields(&verified)?.contains_key("verification_report"));
    archive::stop(&mut fixture.child)?;
    let target = root.join("restored");
    directory(&target)?;
    directory(&target.join("data"))?;
    directory(&target.join("secrets"))?;
    let target_config = target.join("positron.toml");
    let text = fs::read_to_string(config)?
        .replace(
            &root.join("data").display().to_string(),
            &target.join("data").display().to_string(),
        )
        .replace(
            &root.join("secrets").display().to_string(),
            &target.join("secrets").display().to_string(),
        );
    fs::write(&target_config, text)?;
    let mut arguments = plain(&["backup", "restore", "start", "--output", "json", "--config"]);
    arguments.extend([
        target_config.display().to_string(),
        "--locator".into(),
        repository.display().to_string(),
        "--repository-id".into(),
        REPOSITORY.into(),
        "--snapshot-id".into(),
        snapshot.clone(),
        "--expected-manifest-checksum".into(),
        checksum.clone(),
        "--idempotency-key".into(),
        "55555555-5555-4555-8555-555555555555".into(),
        "--bundle".into(),
        recovery.bundle.display().to_string(),
        "--identity-file".into(),
        recovery.identity.display().to_string(),
    ]);
    for (argument, key) in [
        ("--instance", "instance"),
        ("--root-key-id", "root_key_id"),
        ("--root-created-at", "root_created_at"),
        ("--root-fingerprint", "root_fingerprint"),
        ("--integrity-public-key", "integrity_public_key"),
        ("--integrity-fingerprint", "integrity_fingerprint"),
    ] {
        arguments.extend([
            argument.into(),
            recovery.pin.get(key).ok_or("missing recovery pin")?.clone(),
        ]);
    }
    let started = execute(binary, &arguments, None)?;
    let started: serde_json::Value = serde_json::from_slice(&started.stdout)?;
    let operation = started["operation"]["id"]
        .as_str()
        .ok_or("restore operation")?;
    *arguments.get_mut(2).ok_or("restore action")? = "wait".into();
    arguments.extend([
        "--operation-id".into(),
        operation.into(),
        "--wait-seconds".into(),
        "30".into(),
    ]);
    let restored = execute(binary, &arguments, None)?;
    let restored: serde_json::Value = serde_json::from_slice(&restored.stdout)?;
    assert_eq!(restored["operation"]["status"], "succeeded");
    fixture.child = Some(
        Command::new(binary)
            .args(["serve", "--config"])
            .arg(&target_config)
            .spawn()?,
    );
    ready(operations)?;
    assert_eq!(
        archive::query_log(binary, root, endpoint, query, None)?,
        expected
    );
    let mut inspection = online("backup", "status", endpoint);
    inspection.extend(["--operation-id".into(), snapshot]);
    let inherited = execute(binary, &inspection, Some(admin))?;
    assert_eq!(field(&inherited, "status")?, "succeeded");
    assert_eq!(field(&inherited, "restored_publication")?, "true");
    assert_eq!(field(&inherited, "manifest_checksum")?, checksum);
    assert_eq!(
        field(&inherited, "source_catalog_identity")?,
        field(&backed_up, "catalog_identity")?
    );
    assert_eq!(
        field(&inherited, "source_catalog_generation")?,
        field(&backed_up, "catalog_generation")?
    );
    assert!(!fields(&inherited)?.contains_key("uploaded_bytes"));
    assert!(!fields(&inherited)?.contains_key("reused_bytes"));
    // Fresh-root Restore and source Upgrade are independent supported journeys.
    let candidate = super::upgrade::run(fixture, installed, &fixture.root.clone(), expected)?;
    fixture.child = Some(
        Command::new(&candidate)
            .args(["serve", "--config"])
            .arg(config)
            .spawn()?,
    );
    ready(operations)?;
    Ok(candidate)
}

#[path = "recovery_mutation_tests.rs"]
mod mutation_tests;
