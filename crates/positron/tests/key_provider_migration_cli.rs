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
) -> TestResult<ProviderMigrationResponse> {
    let deadline = Instant::now() + Duration::from_secs(10);
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
            Err(positron_api::provider_migration::ProviderMigrationServiceClientFailure::AdministrationUnavailable) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => return Err(error.into()),
        }
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
    let deadline = Instant::now() + Duration::from_secs(10);
    let rendered = loop {
        let current = status(client, bearer, None)?;
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
            break String::from_utf8(output.stdout)?;
        }
        let error = String::from_utf8(output.stderr)?;
        if Instant::now() >= deadline || !error.contains("stale Catalog generation") {
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
    let terminal =
        loop {
            let current = status(client, bearer, Some(operation.clone()))?;
            if current.operation.as_ref().is_some_and(|operation| {
                !matches!(operation.status.as_str(), "pending" | "running")
            }) {
                break current;
            }
            if Instant::now() >= deadline {
                return Err("CLI operation completion deadline".into());
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
    let final_status = status(&client, claim.secret(), None)?;
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
            "restarted {action}"
        );
    }
    assert_eq!(
        status(&client, claim.secret(), None)?.predecessor_epoch,
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
