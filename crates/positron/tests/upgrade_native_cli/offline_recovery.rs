//! Real offline commands preserve cancellation and read-only recovery access.
use super::*;
use positron_governance::UpgradeStage;
use std::process::Output;

struct Case {
    root: std::path::PathBuf,
    paths: BootstrapPaths,
    effective: positron_config::EffectiveConfiguration,
}
impl Drop for Case {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
struct Source {
    process: RunningProcess,
    host: NativeHost,
    accepted: AcceptedUpgrade,
    case: Case,
}
#[inline(never)]
fn source() -> Result<Source> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let root = fs::canonicalize(std::env::temp_dir())?
        .join(format!("p-upgrade-offline-{}-{nonce}", std::process::id()));
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
    let (_, candidate) = configuration(
        &root,
        epoch,
        claim.query_secret().ok_or("Query credential")?,
    )?;
    // Unlike the serving fixture's explicit BootstrapPaths, the real offline
    // command derives every root from this canonical document.
    let mut text = fs::read_to_string(root.join("positron.toml"))?;
    text.push_str(&format!(
        "\n[security]\nlocal_key_file={:?}\n",
        root.join("secrets/local-root-key.v1")
    ));
    fs::write(root.join("positron.toml"), text)?;
    let effective = positron_config::resolve(
        positron_config::ConfigurationInputs::try_from_sources(
            Some(&root.join("positron.toml")),
            [] as [(&str, &str); 0],
            [] as [(&str, &str); 0],
        )
        .map_err(|_| "offline canonical roots")?,
    )?;
    let host = host("offline-recovery")?;
    let foreground = ForegroundTasks(&host);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::ExistingOnly)
            .with_effective_configuration(Arc::new(effective.clone())),
        HostInputs::new(&host, &foreground),
    )?;
    ingest_before_upgrade(&process, claim.ingest_secret().ok_or("Ingest credential")?)?;
    let client = RepositoryServiceClient::new(RepositoryTransport::PlaintextOptOut {
        endpoint: endpoint(&process)?,
    })?;
    let basis = generation(&client, claim.secret())?;
    let client = positron_api::upgrade::UpgradeServiceClient::new(
        positron_api::upgrade::UpgradeTransport::PlaintextOptOut {
            endpoint: endpoint(&process)?,
        },
    )?;
    let input = positron_api::upgrade::UpgradeRequest {
        action: "start".into(),
        candidate_manifest: Some(hex(&candidate)),
        repository_id: Some(REPOSITORY.into()),
        retention_seconds: Some(3600),
        expected_catalog_generation: Some(basis),
        idempotency_key: Some("81818181-8181-8181-8181-818181818181".into()),
        operation_id: None,
    };
    client.manage(claim.secret(), &input)?;
    let accepted = process
        .resume_configured_upgrade_drain(&effective)?
        .ok_or("source Drain token")?;
    Ok(Source {
        process,
        host,
        accepted,
        case: Case {
            root,
            paths,
            effective,
        },
    })
}
fn command(
    case: &Case,
    action: &str,
    id: positron_governance::OperationId,
    revision: Option<u64>,
) -> Result<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_positron"));
    command
        .args(["upgrade", "offline", action, "--config"])
        .arg(case.root.join("positron.toml"))
        .args(["--operation-id", &hex(&id.to_bytes())]);
    if let Some(revision) = revision {
        command.args([
            "--expected-operation-revision",
            &revision.to_string(),
            "--idempotency-key",
            &"82".repeat(16),
        ]);
    }
    Ok(command.output()?)
}
fn binding(case: &Case) -> Result<(u64, Option<GracefulShutdownRecord>)> {
    let instance = InstanceBootstrap::reopen_configured(&case.paths, &case.effective)?;
    Ok((
        instance.catalog_generation(),
        instance.graceful_shutdown_record()?,
    ))
}

#[test]
fn offline_pending_preflight_cancel_uses_real_cli_before_any_drain() -> Result {
    let Source {
        process,
        host,
        accepted,
        case,
    } = source()?;
    let pending = accepted.operation();
    assert_eq!(
        pending.status(),
        positron_governance::DurableOperationStatus::Pending
    );
    assert_eq!(pending.upgrade_stage(), Some(UpgradeStage::Preflight));
    drop(process);
    drop(host);
    let marker = binding(&case)?.1;
    let output = command(
        &case,
        "cancel",
        pending.operation_id(),
        Some(pending.revision()),
    )?;
    assert!(
        output.status.success(),
        "Pending preflight CLI cancellation refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8(output.stdout)?.contains("status=Cancelled"));
    assert_eq!(
        binding(&case)?.1,
        marker,
        "cancellation must not fabricate a Drain marker"
    );
    let host = super::host("cancelled")?;
    let foreground = ForegroundTasks(&host);
    let reopened = ApplicationRuntime::start(
        ServeConfiguration::new(case.paths.clone(), InitializationMode::ExistingOnly)
            .with_effective_configuration(Arc::new(case.effective.clone())),
        HostInputs::new(&host, &foreground),
    )?;
    assert_eq!(reopened.health().phase(), ProcessPhase::Serving);
    assert!(reopened.pending_upgrade_operation()?.is_none());
    assert_eq!(
        reopened.shutdown(ShutdownTrigger::FirstSignal),
        ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn offline_restore_reference_survives_frontiers_that_refuse_continuation() -> Result {
    let Source {
        process,
        host,
        accepted,
        case,
    } = source()?;
    let id = process
        .begin_upgrade(accepted)?
        .finish(ShutdownTrigger::FirstSignal)?;
    drop(host);
    let reference = verified_snapshot(&case, id)?;
    let before = binding(&case)?;
    // Existing startup-recovery fault convention: damage acknowledged native
    // storage after releasing the offline owner, leaving Catalog evidence intact.
    let segments = fs::read_dir(case.root.join("data/segments/sealed"))?
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "segment")
        })
        .collect::<Vec<_>>();
    assert!(!segments.is_empty(), "acknowledged sealed native segments");
    for segment in segments {
        fs::write(segment, b"corrupt acknowledged frontier")?;
    }
    let refusal = match OfflineUpgradeSession::begin(&case.paths, &case.effective, id) {
        Ok(_) => return Err("damaged native storage admitted writable continuation".into()),
        Err(error) => error,
    };
    eprintln!("native corruption continuation refusal: {refusal:?}");
    assert!(matches!(
        refusal,
        UpgradeFailure::DrainIncomplete | UpgradeFailure::UnsafeState
    ));
    assert_eq!(
        binding(&case)?,
        before,
        "fault must preserve authenticated Catalog receipt"
    );
    let before = binding(&case)?;
    let output = command(&case, "restore-reference", id, None)?;
    assert!(
        output.status.success(),
        "read-only restore reference refused after frontier change: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("fresh_target_required=true"));
    assert!(stdout.contains(&format!("snapshot_id={}", hex(&reference.snapshot_id()))));
    assert!(stdout.contains(&format!(
        "manifest_checksum={}",
        hex(&reference.manifest_checksum())
    )));
    assert_eq!(
        binding(&case)?,
        before,
        "reference inspection must preserve Catalog and historical marker"
    );
    reference_refuses_other_bindings(&case, id, before)?;
    Ok(())
}
fn reference_refuses_other_bindings(
    case: &Case,
    id: positron_governance::OperationId,
    before: (u64, Option<GracefulShutdownRecord>),
) -> Result {
    let wrong = positron_governance::OperationId::from_bytes([0x93; 16])?;
    assert_ne!(wrong, id);
    assert!(
        !command(case, "restore-reference", wrong, None)?
            .status
            .success()
    );
    assert_eq!(binding(case)?, before);
    let path = case.root.join("positron.toml");
    let original = fs::read_to_string(&path)?;
    let old = case.root.join("export/query.credential");
    let other = case.root.join("export/other-query.credential");
    fs::copy(&old, &other)?;
    fs::set_permissions(&other, fs::Permissions::from_mode(0o600))?;
    let changed = original.replace(
        old.to_str().ok_or("credential path")?,
        other.to_str().ok_or("alternate credential path")?,
    );
    assert_ne!(changed, original);
    fs::write(&path, changed)?;
    let changed_configuration = positron_config::resolve(
        positron_config::ConfigurationInputs::try_from_sources(
            Some(&path),
            [] as [(&str, &str); 0],
            [] as [(&str, &str); 0],
        )
        .map_err(|_| "changed valid configuration")?,
    )?;
    assert_ne!(
        changed_configuration.audit_binding_digest(),
        case.effective.audit_binding_digest()
    );
    let result = command(case, "restore-reference", id, None);
    fs::write(&path, original)?;
    assert!(
        !result?.status.success(),
        "different configuration must refuse receipt"
    );
    assert_eq!(binding(case)?, before);
    Ok(())
}
#[inline(never)]
fn verified_snapshot(
    case: &Case,
    id: positron_governance::OperationId,
) -> Result<positron_governance::BackupVerificationParameters> {
    let begin_deadline = Instant::now() + Duration::from_secs(12);
    let mut session = loop {
        match OfflineUpgradeSession::begin(&case.paths, &case.effective, id) {
            Ok(session) => break session,
            Err(UpgradeFailure::SnapshotUnavailable) if Instant::now() < begin_deadline => {
                std::thread::sleep(Duration::from_millis(50))
            },
            Err(error) => return Err(format!("offline snapshot admission {error:?}").into()),
        }
    };
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let operation = session.advance(deadline)?;
        if operation.upgrade_stage() == Some(UpgradeStage::Publishing) {
            break;
        }
        assert!(!operation.status().is_terminal(), "{operation:?}");
        assert!(Instant::now() < deadline, "snapshot deadline {operation:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
    session
        .rollback_snapshot()?
        .ok_or_else(|| "verified receipt".into())
}

fn ingest_before_upgrade(process: &RunningProcess, credential: &str) -> Result {
    use std::io::Read;
    let address = process
        .bound_endpoints()
        .into_iter()
        .find(|endpoint| endpoint.role() == ListenerRole::OtlpHttp)
        .and_then(|endpoint| endpoint.socket_address())
        .ok_or("OTLP endpoint")?;
    let body = br#"{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"timeUnixNano":"42","body":{"stringValue":"pre-upgrade-acknowledged-log"}}]}]}]}"#;
    let mut stream = std::net::TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    write!(
        stream,
        "POST /v1/logs HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {credential}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    let mut response = String::new();
    stream.take(65_537).read_to_string(&mut response)?;
    assert!(response.len() <= 65_536);
    assert!(
        response.starts_with("HTTP/1.1 200 "),
        "native Log ingestion refused"
    );
    Ok(())
}
