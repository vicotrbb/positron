//! The real command uses the authenticated running administrative listener.
#![cfg(unix)]
use positron_api::provider_migration::{
    ProviderMigrationRequest, ProviderMigrationResponse, ProviderMigrationServiceClient,
    ProviderMigrationTransport,
};
use positron_kernel::MountQualification;
use positron_runtime::{
    ApplicationRuntime, BootstrapPaths, HostInputs, InitializationMode, InitializationPlan,
    InstanceBootstrap, ListenerRole, NativeBindings, NativeHost, ServeConfiguration,
    ShutdownTrigger,
};
use std::{
    fs,
    io::Write,
    net::{Ipv4Addr, SocketAddr},
    os::unix::fs::PermissionsExt,
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn maintenance_failure_context(endpoint: SocketAddr, bearer: &str) -> String {
    use positron_api::maintenance::{
        MaintenanceServiceClient, MaintenanceStatusRequest, MaintenanceTransport,
    };
    let status = MaintenanceServiceClient::new(MaintenanceTransport::PlaintextOptOut { endpoint })
        .and_then(|client| client.status(bearer, &MaintenanceStatusRequest::default()));
    format!(
        "{:?}",
        status.map(|status| status
            .tasks
            .into_iter()
            .map(|task| (
                task.class,
                task.phase,
                task.checkpoint_sequence,
                task.terminal_failure_class,
                task.blocked_precondition,
            ))
            .collect::<Vec<_>>())
    )
}

fn command(
    endpoint: SocketAddr,
    bearer: &str,
    action: &str,
    arguments: &[String],
) -> TestResult<Output> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args([
            "keys",
            "migrate",
            action,
            "--endpoint",
            &endpoint.to_string(),
            "--credential-stdin",
            "--allow-plaintext",
        ])
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut input = child.stdin.take().ok_or("credential input")?;
    writeln!(input, "{bearer}")?;
    drop(input);
    Ok(child.wait_with_output()?)
}
fn status(
    client: &ProviderMigrationServiceClient,
    bearer: &str,
    operation: Option<String>,
    deadline: Instant,
    stage: &'static str,
) -> TestResult<ProviderMigrationResponse> {
    let started = Instant::now();
    let mut attempt = 0_u64;
    loop {
        let request = ProviderMigrationRequest {
            action: "status".into(),
            expected_catalog_generation: None,
            idempotency_key: None,
            configuration_reference: None,
            operation_id: operation.clone(),
        };
        attempt += 1;
        let call_started = Instant::now();
        let result = client.manage(bearer, &request);
        let call_ms = call_started.elapsed().as_millis();
        match result {
            Ok(response) => return Ok(response),
            Err(positron_api::provider_migration::ProviderMigrationServiceClientFailure::CapacityUnavailable) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                let elapsed_ms = started.elapsed().as_millis();
                let remaining_ms = deadline.saturating_duration_since(Instant::now()).as_millis();
                let operation_present = operation.is_some();
                return Err(format!(
                    "provider migration status read: {error:?}; stage={stage} action=status operation_present={operation_present} attempt={attempt} elapsed_ms={elapsed_ms} call_ms={call_ms} remaining_ms={remaining_ms}"
                ).into());
            },
        }
    }
}

fn scripted_provider_status_peer(
    listener: std::net::TcpListener,
    responses: Vec<Option<(u16, &'static str)>>,
    deadline: Instant,
) -> (Vec<ProviderMigrationRequest>, std::io::Result<()>) {
    use std::io::Read;
    let mut requests = Vec::new();
    let outcome = (|| -> std::io::Result<()> {
        listener.set_nonblocking(true)?;
        for response in responses {
            let mut stream = loop {
                if Instant::now() >= deadline {
                    return Err(std::io::ErrorKind::TimedOut.into());
                }
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(
                            Duration::from_millis(1)
                                .min(deadline.saturating_duration_since(Instant::now())),
                        );
                    },
                    Err(error) => return Err(error),
                }
            };
            stream.set_nonblocking(true)?;
            let mut bytes = Vec::new();
            let request = loop {
                if Instant::now() >= deadline {
                    return Err(std::io::ErrorKind::TimedOut.into());
                }
                let mut buffer = [0; 512];
                match stream.read(&mut buffer) {
                    Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
                    Ok(read) => bytes.extend_from_slice(&buffer[..read]),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(
                            Duration::from_millis(1)
                                .min(deadline.saturating_duration_since(Instant::now())),
                        );
                        continue;
                    },
                    Err(error) => return Err(error),
                }
                if bytes.len() > 4096 + positron_api::provider_migration::MAX_REQUEST_BYTES {
                    return Err(std::io::Error::other(
                        "provider request exceeds existing bound",
                    ));
                }
                let Some(header_end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") else {
                    if bytes.len() > 4096 {
                        return Err(std::io::Error::other(
                            "provider request headers exceed bound",
                        ));
                    }
                    continue;
                };
                let headers =
                    std::str::from_utf8(&bytes[..header_end]).map_err(std::io::Error::other)?;
                if !headers.starts_with("POST /v1/key-provider-migrations:manage HTTP/1.1\r\n") {
                    return Err(std::io::Error::other("unexpected provider request route"));
                }
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then_some(value.trim())
                    })
                    .ok_or_else(|| std::io::Error::other("provider request length missing"))?
                    .parse::<usize>()
                    .map_err(std::io::Error::other)?;
                if length > positron_api::provider_migration::MAX_REQUEST_BYTES {
                    return Err(std::io::Error::other(
                        "provider request exceeds existing bound",
                    ));
                }
                let body = &bytes[header_end + 4..];
                if body.len() < length {
                    continue;
                }
                break ProviderMigrationRequest::decode(body)
                    .map_err(|_| std::io::Error::other("invalid provider request"))?;
            };
            requests.push(request);
            if let Some((code, body)) = response {
                let response = format!(
                    "HTTP/1.1 {code} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let mut remaining = response.as_bytes();
                while !remaining.is_empty() {
                    if Instant::now() >= deadline {
                        return Err(std::io::ErrorKind::TimedOut.into());
                    }
                    match stream.write(remaining) {
                        Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
                        Ok(written) => remaining = &remaining[written..],
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(
                                Duration::from_millis(1)
                                    .min(deadline.saturating_duration_since(Instant::now())),
                            );
                        },
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        Ok(())
    })();
    (requests, outcome)
}

fn assert_provider_status_diagnostic(responses: &[Option<(u16, &'static str)>]) -> TestResult {
    use std::net::TcpListener;

    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let endpoint = listener.local_addr()?;
    let responses = responses.to_vec();
    let expected_attempts = responses.len();
    let deadline = Instant::now() + Duration::from_secs(10);
    let server =
        std::thread::spawn(move || scripted_provider_status_peer(listener, responses, deadline));
    let client =
        ProviderMigrationServiceClient::new(ProviderMigrationTransport::PlaintextOptOut {
            endpoint,
        })?;
    let outcome = status(
        &client,
        "provider-status-secret-canary",
        None,
        deadline,
        "transport_regression",
    );
    let (requests, peer_outcome) = server.join().map_err(|_| "provider server panicked")?;
    peer_outcome?;
    assert_eq!(requests.len(), expected_attempts);
    for request in requests {
        assert_eq!(request.action, "status");
        assert!(request.operation_id.is_none());
        assert!(request.idempotency_key.is_none());
        assert!(request.configuration_reference.is_none());
        assert!(request.expected_catalog_generation.is_none());
    }
    let failure = outcome
        .expect_err("closed response must remain a Transport failure")
        .to_string();
    assert!(failure.starts_with("provider migration status read: Transport"));
    assert!(!failure.contains("provider-status-secret-canary"));
    assert!(failure.contains("action=status"));
    assert!(failure.contains("operation_present=false"));
    assert!(failure.contains("stage=transport_regression"));
    assert!(failure.contains(&format!("attempt={expected_attempts}")));
    for field in ["call_ms=", "elapsed_ms=", "remaining_ms="] {
        let value = failure
            .split_whitespace()
            .find_map(|part| part.strip_prefix(field))
            .ok_or("diagnostic duration missing")?
            .parse::<u128>()?;
        assert!(
            value <= 10_000,
            "fixture diagnostic duration exceeded original deadline"
        );
    }
    assert!(failure.len() < 1024);
    Ok(())
}

#[test]
fn provider_status_peer_finishes_when_no_second_request_arrives() -> TestResult {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    let endpoint = listener.local_addr()?;
    let peer_deadline = Instant::now() + Duration::from_millis(100);
    let (finished, completion) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let result = scripted_provider_status_peer(
            listener,
            vec![Some((503, r#"{"code":"capacity_unavailable"}"#)), None],
            peer_deadline,
        );
        let _ = finished.send(());
        result
    });
    let client =
        ProviderMigrationServiceClient::new(ProviderMigrationTransport::PlaintextOptOut {
            endpoint,
        })?;
    // An expired caller budget permits the existing first request but forbids a capacity retry.
    let outcome = status(
        &client,
        "peer-secret-canary",
        None,
        Instant::now(),
        "no_second_request",
    );
    let finished_before_fallback = completion.recv_timeout(Duration::from_millis(250)).is_ok();
    // Always unblock the old peer and join before assertions, including a failing baseline.
    if !finished_before_fallback {
        drop(std::net::TcpStream::connect(endpoint)?);
    }
    let (requests, peer_outcome) = server.join().map_err(|_| "provider peer panicked")?;
    let failure = outcome
        .expect_err("expired capacity must remain refused")
        .to_string();
    assert!(failure.starts_with("provider migration status read: CapacityUnavailable"));
    assert!(!failure.contains("peer-secret-canary"));
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests.first().map(|request| request.action.as_str()),
        Some("status")
    );
    assert!(
        finished_before_fallback,
        "peer did not finish after its absolute deadline"
    );
    assert_eq!(
        peer_outcome
            .expect_err("missing request must time out")
            .kind(),
        std::io::ErrorKind::TimedOut
    );
    Ok(())
}

#[test]
fn provider_status_transport_failure_retains_safe_call_context() -> TestResult {
    assert_provider_status_diagnostic(&[None])
}

#[test]
fn provider_status_malformed_success_retains_safe_call_context() -> TestResult {
    assert_provider_status_diagnostic(&[Some((200, "provider-status-secret-canary"))])
}

#[test]
fn provider_status_unknown_failure_retains_safe_call_context() -> TestResult {
    assert_provider_status_diagnostic(&[Some((599, r#"{"code":"provider-status-secret-canary"}"#))])
}

#[test]
fn provider_status_capacity_then_transport_retains_safe_call_context() -> TestResult {
    assert_provider_status_diagnostic(&[Some((503, r#"{"code":"capacity_unavailable"}"#)), None])
}

// Startup/reopen can discover a finite scrub -> retention -> scrub cascade.
// Wait for those existing owners before taking a command's CAS snapshot. A
// future scheduled task stays queued; blocked safety work is never forced.
fn wait_for_maintenance(
    endpoint: SocketAddr,
    client: &ProviderMigrationServiceClient,
    bearer: &str,
) -> TestResult<Vec<positron_api::maintenance::MaintenanceTaskStatus>> {
    use positron_api::maintenance::{
        MaintenanceServiceClient, MaintenanceStatusRequest, MaintenanceTransport,
    };
    let maintenance =
        MaintenanceServiceClient::new(MaintenanceTransport::PlaintextOptOut { endpoint })?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last_generation = None;
    let mut stable_since = Instant::now();
    'inspection: loop {
        let mut tasks = Vec::new();
        let mut request = MaintenanceStatusRequest::default();
        loop {
            let page = match maintenance.status(bearer, &request) {
                Ok(page) => page,
                Err(
                    positron_api::maintenance::MaintenanceServiceClientFailure::CapacityUnavailable,
                ) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                    continue 'inspection;
                },
                Err(error) => {
                    return Err(format!("maintenance quiescence status read: {error:?}").into());
                },
            };
            tasks.extend(page.tasks);
            match page.next_cursor {
                Some(cursor) => {
                    request = MaintenanceStatusRequest::page_after(
                        cursor,
                        positron_api::maintenance::MAX_STATUS_PAGE_TASKS as u32,
                    )
                },
                None => break,
            }
        }
        if let Some(task) = tasks.iter().find(|task| {
            matches!(task.phase.as_str(), "queued" | "running" | "deferred")
                && task.blocked_precondition.as_deref().is_some_and(|blocker| {
                    !matches!(blocker, "scheduled_start_time" | "conflict_owner_active")
                })
        }) {
            return Err(format!(
                "maintenance fixture blocked: class={} phase={} blocker={:?}",
                task.class, task.phase, task.blocked_precondition,
            )
            .into());
        }
        let generation =
            status(client, bearer, None, deadline, "maintenance_quiescence")?.catalog_generation;
        let pending = tasks.iter().any(|task| {
            matches!(task.phase.as_str(), "queued" | "running" | "deferred")
                && task.blocked_precondition.as_deref() != Some("scheduled_start_time")
        });
        if pending || last_generation != Some(generation) {
            stable_since = Instant::now();
        } else if stable_since.elapsed() >= Duration::from_secs(1) {
            // Cover one full 500..749ms idle-discovery cadence, including the
            // gap between a terminal publication and its follow-up discovery.
            return Ok(tasks);
        }
        last_generation = Some(generation);
        if Instant::now() >= deadline {
            return Err(format!(
                "maintenance fixture did not quiesce: {}",
                maintenance_failure_context(endpoint, bearer),
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn phase(
    endpoint: SocketAddr,
    client: &ProviderMigrationServiceClient,
    bearer: &str,
    config: &std::path::Path,
    action: &str,
    index: usize,
) -> TestResult<ProviderMigrationResponse> {
    wait_for_maintenance(endpoint, client, bearer)?;
    let admission_deadline = Instant::now() + Duration::from_secs(10);
    let (rendered, completion_deadline) = loop {
        let current = status(
            client,
            bearer,
            None,
            admission_deadline,
            "admission_generation",
        )?;
        let mut arguments = vec![
            "--expected-generation".into(),
            current.catalog_generation.to_string(),
            "--idempotency-key".into(),
            format!("21212121-2121-4121-8121-{:012}", index + 1),
        ];
        if matches!(action, "prepare" | "activate" | "verify" | "retire") {
            arguments.extend([
                "--target-config".into(),
                config.to_string_lossy().into_owned(),
            ]);
        }
        let output = command(endpoint, bearer, action, &arguments)?;
        if output.status.success() {
            break (
                String::from_utf8(output.stdout)?,
                Instant::now() + Duration::from_secs(10),
            );
        }
        let error = String::from_utf8(output.stderr)?;
        if Instant::now() >= admission_deadline || !error.contains("stale resource generation") {
            return Err(format!("{action} admission: {error}").into());
        }
    };
    assert!(!rendered.contains(bearer));
    assert!(rendered.contains("retry="));
    assert!(rendered.contains("lookup_expires_at_unix_seconds="));
    assert!(
        !rendered.contains(
            &config
                .parent()
                .ok_or("configuration parent")?
                .join("secrets")
                .display()
                .to_string()
        )
    );
    let operation = rendered
        .split_whitespace()
        .find_map(|field| field.strip_prefix("operation_id="))
        .ok_or("operation ID")?
        .to_owned();
    let terminal = loop {
        let current = status(
            client,
            bearer,
            Some(operation.clone()),
            completion_deadline,
            "accepted_operation_poll",
        )?;
        if current
            .operation
            .as_ref()
            .is_some_and(|operation| !matches!(operation.status.as_str(), "pending" | "running"))
        {
            break current;
        }
        if Instant::now() >= completion_deadline {
            let last = current.operation.as_ref();
            return Err(format!(
                    "CLI operation completion deadline: action={action} status={:?} phase={:?} progress={:?}",
                    last.map(|operation| operation.status.as_str()),
                    last.map(|operation| operation.phase.as_str()),
                    last.map(|operation| operation.progress_percent),
                )
                .into());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    Ok(terminal)
}

#[test]
fn canonical_owner_commands_preserve_cancelled_routes_and_verify_before_retirement() -> TestResult {
    let root = fs::canonicalize(std::env::temp_dir())?.join(format!(
        "positron-provider-migration-cli-{}",
        std::process::id()
    ));
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let data = root.join("data");
    let secrets = root.join("secrets");
    for directory in [&data, &secrets] {
        fs::create_dir(directory)?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    let paths = BootstrapPaths::new(&data, &secrets, MountQualification::LocalHost)?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let config = root.join("owner.toml");
    fs::write(
        &config,
        format!(
            "schema_version = 1\n[storage]\ndata_directory = '{}'\nsecrets_directory = '{}'\n[security]\nlocal_key_file = '{}'\n",
            data.display(),
            secrets.display(),
            secrets.join("local-root-key.v1").display()
        ),
    )?;
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600))?;
    // This is an actual canonical checkpoint with its normal durable owner,
    // queued while offline so the stale snapshot is deterministic.
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let stale_generation = initialized.catalog_generation();
    let checkpoint = initialized.queue_governance_audit_checkpoint_for_test()?;
    assert_eq!(
        initialized.governance_audit_checkpoint_phase_for_test(checkpoint)?,
        positron_kernel::MaintenanceTaskPhase::Queued,
    );
    drop(initialized);
    let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let host = NativeHost::new(NativeBindings::new(
        std::env::temp_dir().join(format!("p-kpm-{}.sock", std::process::id())),
        loopback,
        loopback,
        loopback,
        loopback,
        loopback,
    )?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let endpoint = process
        .bound_endpoints()
        .into_iter()
        .find(|endpoint| endpoint.role() == ListenerRole::Api)
        .and_then(|endpoint| endpoint.socket_address())
        .ok_or("API endpoint")?;
    let client =
        ProviderMigrationServiceClient::new(ProviderMigrationTransport::PlaintextOptOut {
            endpoint,
        })?;
    assert!(
        !command(
            endpoint,
            claim.ingest_secret().ok_or("ingest credential")?,
            "status",
            &[]
        )?
        .status
        .success()
    );
    let stale = command(
        endpoint,
        claim.secret(),
        "prepare",
        &[
            "--expected-generation".into(),
            stale_generation.to_string(),
            "--idempotency-key".into(),
            "21212121-2121-4121-8121-000000000001".into(),
            "--target-config".into(),
            config.to_string_lossy().into_owned(),
        ],
    )?;
    assert!(!stale.status.success());
    let stale_error = String::from_utf8(stale.stderr)?;
    for secret in [
        Some(claim.secret()),
        claim.ingest_secret(),
        claim.query_secret(),
    ]
    .into_iter()
    .flatten()
    {
        assert!(!stale_error.contains(secret));
    }
    assert!(!stale_error.contains(&secrets.display().to_string()));
    assert!(
        stale_error.contains("stale resource generation"),
        "stale-generation migration CLI failure: {stale_error}"
    );
    let drained = wait_for_maintenance(endpoint, &client, claim.secret())?;
    let checkpoint_id: String = checkpoint
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert!(
        drained
            .iter()
            .any(|task| { task.identity == checkpoint_id && task.phase == "succeeded" })
    );
    for (index, action) in [
        "prepare", "cancel", "resume", "activate", "verify", "retire",
    ]
    .into_iter()
    .enumerate()
    {
        let terminal = phase(endpoint, &client, claim.secret(), &config, action, index)?;
        let expected = if matches!(action, "verify" | "retire") {
            "failed"
        } else {
            "succeeded"
        };
        assert_eq!(
            terminal
                .operation
                .as_ref()
                .map(|operation| operation.status.as_str()),
            Some(expected)
        );
        if action == "cancel" {
            assert_eq!(terminal.active_epoch, 1);
            assert_eq!(terminal.root_phase, "cancelled");
        }
    }
    let final_status = status(
        &client,
        claim.secret(),
        None,
        Instant::now() + Duration::from_secs(10),
        "final_verification",
    )?;
    assert_eq!(final_status.active_epoch, 2);
    assert_eq!(final_status.predecessor_epoch, Some(1));
    assert!(secrets.join("local-root-key.v1").exists());
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    let instance = InstanceBootstrap::reopen(&paths)?;
    assert_eq!(instance.local_key_rotation_status()?.active_epoch(), 2);
    let recovery = root.join("recovery");
    fs::create_dir(&recovery)?;
    fs::set_permissions(&recovery, fs::Permissions::from_mode(0o700))?;
    let unlock = age::x25519::Identity::generate();
    let bundle = recovery.join("successor.age");
    instance.create_recovery_bundle(
        &bundle,
        &positron_kernel::RecoveryRecipients::parse(&[unlock.to_public().to_string()])?,
    )?;
    instance.verify_recovery_bundle(&bundle, positron_kernel::RecoveryUnlock::Identity(&unlock))?;
    assert_eq!(
        instance.backup_key_recovery_readiness()?,
        positron_runtime::RecoveryReadiness::Verified
    );
    drop(instance);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let endpoint = process
        .bound_endpoints()
        .into_iter()
        .find(|endpoint| endpoint.role() == ListenerRole::Api)
        .and_then(|endpoint| endpoint.socket_address())
        .ok_or("restarted API endpoint")?;
    let client =
        ProviderMigrationServiceClient::new(ProviderMigrationTransport::PlaintextOptOut {
            endpoint,
        })?;
    for (index, action) in ["verify", "retire"].into_iter().enumerate() {
        let terminal = phase(
            endpoint,
            &client,
            claim.secret(),
            &config,
            action,
            index + 6,
        )?;
        assert_eq!(
            terminal
                .operation
                .as_ref()
                .map(|operation| operation.status.as_str()),
            Some("succeeded"),
            "restarted {action}: operation={:?}, maintenance={}",
            terminal.operation,
            maintenance_failure_context(endpoint, claim.secret()),
        );
    }
    assert_eq!(
        status(
            &client,
            claim.secret(),
            None,
            Instant::now() + Duration::from_secs(10),
            "restart_verification",
        )?
        .predecessor_epoch,
        None
    );
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    assert!(!secrets.join("local-root-key.v1").exists());
    let reopened = InstanceBootstrap::reopen(&paths)?;
    assert_eq!(reopened.local_key_rotation_status()?.active_epoch(), 2);
    let actor = reopened.attribute(
        positron_governance::PresentedCredential::parse(claim.secret())?,
        positron_governance::RequestedIntent::SystemAdministration,
        positron_governance::CompatibilityHints::none(),
    )?;
    reopened.verify_governance_audit_history(actor, None)?;
    drop(reopened);
    fs::remove_dir_all(root)?;
    Ok(())
}
