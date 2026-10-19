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
) -> TestResult<ProviderMigrationResponse> {
    loop {
        let request = ProviderMigrationRequest {
            action: "status".into(),
            expected_catalog_generation: None,
            idempotency_key: None,
            configuration_reference: None,
            operation_id: operation.clone(),
        };
        match client.manage(bearer, &request) {
            Ok(response) => return Ok(response),
            Err(positron_api::provider_migration::ProviderMigrationServiceClientFailure::CapacityUnavailable) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => return Err(format!("provider migration status read: {error:?}").into()),
        }
    }
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
        let generation = status(client, bearer, None, deadline)?.catalog_generation;
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
        let current = status(client, bearer, None, admission_deadline)?;
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
        let current = status(client, bearer, Some(operation.clone()), completion_deadline)?;
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
    assert!(String::from_utf8(stale.stderr)?.contains("stale resource generation"));
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
