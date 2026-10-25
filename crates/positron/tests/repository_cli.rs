//! The real command uses the authenticated running administrative listener.
#![cfg(unix)]
use positron_api::repository::{RepositoryRequest, RepositoryServiceClient, RepositoryTransport};
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
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn after_capacity(
    deadline: std::time::Instant,
    mut invoke: impl FnMut() -> TestResult<Output>,
) -> TestResult<Output> {
    loop {
        let output = invoke()?;
        if output.status.success()
            || output.stderr
                != b"positron: capacity unavailable; retry the same idempotent request\n"
            || std::time::Instant::now() >= deadline
        {
            return Ok(output);
        }
        std::thread::sleep(
            std::time::Duration::from_millis(10)
                .min(deadline.saturating_duration_since(std::time::Instant::now())),
        );
    }
}

#[test]
fn scope_check_retries_only_exact_capacity_within_its_admission_deadline() -> TestResult {
    use std::os::unix::process::ExitStatusExt;
    let capacity = "positron: capacity unavailable; retry the same idempotent request\n";
    let scope = "positron: system administration authentication rejected\n";
    let mut calls = 0;
    let output = after_capacity(
        std::time::Instant::now() + std::time::Duration::from_secs(10),
        || {
            calls += 1;
            Ok(Output {
                status: std::process::ExitStatus::from_raw(256),
                stdout: Vec::new(),
                stderr: if calls == 1 { capacity } else { scope }
                    .as_bytes()
                    .to_vec(),
            })
        },
    )?;
    assert_eq!(calls, 2);
    assert_eq!(output.stderr, scope.as_bytes());
    for failure in [scope, "positron: administration unavailable\n", capacity] {
        let mut calls = 0;
        let output = after_capacity(std::time::Instant::now(), || {
            calls += 1;
            Ok(Output {
                status: std::process::ExitStatus::from_raw(256),
                stdout: Vec::new(),
                stderr: failure.as_bytes().to_vec(),
            })
        })?;
        assert_eq!(calls, 1);
        assert_eq!(output.stderr, failure.as_bytes());
    }
    Ok(())
}

fn command(
    endpoint: SocketAddr,
    bearer: &str,
    action: &str,
    arguments: &[String],
) -> TestResult<Output> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args([
            "repository",
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
#[test]
fn repository_command_uses_the_authenticated_serving_owner() -> TestResult {
    let root = fs::canonicalize(std::env::temp_dir())?
        .join(format!("positron-repository-cli-{}", std::process::id()));
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
    let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let host = NativeHost::new(NativeBindings::new(
        std::env::temp_dir().join(format!("p-repo-{}.sock", std::process::id())),
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
    let client = RepositoryServiceClient::new(RepositoryTransport::PlaintextOptOut { endpoint })?;
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
    let output = command(endpoint, claim.secret(), "status", &[])?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("catalog_generation="));
    assert!(!text.contains(claim.secret()));
    let native = [
        "--expected-generation".into(),
        "1".into(),
        "--idempotency-key".into(),
        "74747474-7474-4474-8474-747474747474".into(),
        "--repository-id".into(),
        "75757575-7575-4575-8575-757575757575".into(),
        "--aws-bucket".into(),
        "positron-example".into(),
        "--aws-region".into(),
        "us-east-1".into(),
        "--aws-endpoint".into(),
        "https://s3.us-east-1.amazonaws.com".into(),
        "--aws-expected-owner".into(),
        "123456789012".into(),
        "--aws-prefix".into(),
        "diagnostic/".into(),
    ];
    let rejected = after_capacity(
        std::time::Instant::now() + std::time::Duration::from_secs(10),
        || {
            command(
                endpoint,
                claim.ingest_secret().ok_or("ingest credential")?,
                "doctor",
                &native,
            )
        },
    )?;
    assert!(!rejected.status.success());
    let rejected_error = String::from_utf8(rejected.stderr)?;
    for secret in [
        Some(claim.secret()),
        claim.ingest_secret(),
        claim.query_secret(),
    ]
    .into_iter()
    .flatten()
    {
        assert!(!rejected_error.contains(secret));
    }
    assert!(!rejected_error.contains("123456789012"));
    assert!(
        rejected_error.contains("system administration authentication rejected"),
        "repository ingest-credential CLI refusal: {rejected_error}"
    );
    let mut invalid = native;
    for value in &mut invalid {
        if value == "us-east-1" {
            *value = "unsupported-region".into();
        }
    }
    let rejected = command(endpoint, claim.secret(), "doctor", &invalid)?;
    assert!(!rejected.status.success());
    let error = String::from_utf8(rejected.stderr)?;
    assert!(!error.contains(claim.secret()));
    assert!(!error.contains("123456789012"));
    assert!(
        error.contains("invalid repository request"),
        "invalid-target repository CLI failure: {error}"
    );
    let repository = root.join("repository");
    fs::create_dir(&repository)?;
    fs::set_permissions(&repository, fs::Permissions::from_mode(0o700))?;
    for (index, action) in ["init", "verify", "doctor"].into_iter().enumerate() {
        let admission_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let operation = loop {
            let current = match client.manage(
                claim.secret(),
                &RepositoryRequest {
                    action: "status".into(),
                    expected_catalog_generation: None,
                    idempotency_key: None,
                    aws_s3: None,
                    google_cloud_storage: None,
                    azure_blob: None,
                    locator: None,
                    repository_id: None,
                    operation_id: None,
                },
            ) {
                Ok(current) => current,
                Err(
                    positron_api::repository::RepositoryServiceClientFailure::CapacityUnavailable,
                ) if std::time::Instant::now() < admission_deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                },
                Err(error) => return Err(error.into()),
            };
            let output = after_capacity(admission_deadline, || {
                command(
                    endpoint,
                    claim.secret(),
                    action,
                    &[
                        "--expected-generation".into(),
                        current.catalog_generation.to_string(),
                        "--idempotency-key".into(),
                        format!("71717171-7171-4171-8171-{:012}", index + 1),
                        "--repository-id".into(),
                        "72727272-7272-4272-8272-727272727272".into(),
                        "--locator".into(),
                        repository.to_string_lossy().into_owned(),
                    ],
                )
            })?;
            if output.status.success() {
                let text = String::from_utf8(output.stdout)?;
                assert!(!text.contains(repository.to_string_lossy().as_ref()));
                break text
                    .split_whitespace()
                    .find_map(|field| field.strip_prefix("operation_id="))
                    .ok_or("CLI operation receipt")?
                    .to_owned();
            }
            let error = String::from_utf8(output.stderr)?;
            if std::time::Instant::now() >= admission_deadline
                || !(error.contains("stale resource generation")
                    || error.contains("administration unavailable"))
            {
                return Err(format!("repository {action} admission refused: {error}").into());
            }
        };
        let output = command(
            endpoint,
            claim.secret(),
            "wait",
            &[
                "--operation-id".into(),
                operation,
                "--wait-seconds".into(),
                "10".into(),
            ],
        )?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout)?;
        assert!(text.contains("status=succeeded"), "{text}");
        assert!(text.contains("versioning_state=unobservable"));
        assert!(text.contains("object_lock_state=unobservable"));
        assert!(text.contains("lifecycle_state=unobservable"));
        assert!(text.contains("policy_observed_at_unix_seconds="));
        assert!(text.contains("retry="));
        assert!(text.contains("lookup_expires_at_unix_seconds="));
        if action == "doctor" {
            assert!(text.contains("owned_probes_deleted=true"));
            for name in ["retention", "legal_hold", "event_hold"] {
                assert!(text.contains(&format!("doctor_probe_{name}_state=unobservable")));
            }
        }
    }
    assert_eq!(fs::read_dir(repository)?.count(), 1);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[path = "repository_cli/transport_deadline.rs"]
mod transport_deadline;
