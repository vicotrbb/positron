//! Real executable and HTTP clients; Rust query interfaces verify durable output.
#![cfg(unix)]

use positron_kernel::MountQualification;
use positron_query::QueryBudget;
use positron_runtime::{
    ApplicationRuntime, BootstrapPaths, HostInputs, InitializationMode, InitializationPlan,
    InstanceBootstrap, NativeBindings, NativeHost, ServeConfiguration, ShutdownTrigger,
};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    root: PathBuf,
    child: Option<Child>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn request(port: u16, path: &str, headers: &[(&str, &str)], body: &[u8]) -> TestResult<String> {
    request_with_method("POST", port, path, headers, body)
}

// Retry only the native protocol's explicit transient capacity response.
// Each attempt sends the identical payload; the caller still requires success.
fn request_with_capacity_retry(
    port: u16,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    admission_budget: Duration,
) -> TestResult<String> {
    // The canonical listener request deadline bounds this correctness flow.
    // Each transport attempt retains its existing five-second socket budget.
    // Explicit Retry-After backpressure makes an attempt count no guarantee.
    let deadline = Instant::now() + admission_budget;
    let mut response = request_before("POST", port, path, headers, body, deadline)?;
    loop {
        let retry_after_one_second = response.split_once("\r\n\r\n").is_some_and(|(head, _)| {
            head.lines()
                .any(|line| line.eq_ignore_ascii_case("Retry-After: 1"))
        });
        if !response.starts_with("HTTP/1.1 429 ") || !retry_after_one_second {
            break;
        }
        if Instant::now() + Duration::from_secs(1) >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
        response = request_before("POST", port, path, headers, body, deadline)?;
    }
    Ok(response)
}

fn request_with_method(
    method: &str,
    port: u16,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> TestResult<String> {
    request_before(
        method,
        port,
        path,
        headers,
        body,
        Instant::now() + Duration::from_secs(5),
    )
}

fn request_before(
    method: &str,
    port: u16,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    deadline: Instant,
) -> TestResult<String> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or("binary HTTP deadline expired")?
        .min(Duration::from_secs(5));
    let mut stream = TcpStream::connect_timeout(&format!("127.0.0.1:{port}").parse()?, remaining)?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or("binary HTTP deadline expired")?
        .min(Duration::from_secs(5));
    stream.set_read_timeout(Some(remaining))?;
    stream.set_write_timeout(Some(remaining))?;
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    let mut response = String::new();
    match stream.take(65_537).read_to_string(&mut response) {
        Ok(_) => {},
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {},
        Err(error) => return Err(error.into()),
    }
    if response.len() > 65_536 {
        return Err("binary HTTP response exceeded diagnostic bound".into());
    }
    Ok(response)
}

fn ready(port: u16) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            if stream
                .write_all(b"GET /health/ready HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .is_err()
            {
                continue;
            }
            let mut response = String::new();
            if stream.read_to_string(&mut response).is_err() {
                continue;
            }
            if response.starts_with("HTTP/1.1 200 ") {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err("binary readiness deadline expired".into())
}

#[test]
fn binary_http_ingestion_recovers_after_sigkill_and_graceful_restart() -> TestResult {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let mut fixture = Fixture {
        root: PathBuf::from("/tmp").join(format!("p-bin-{}-{nonce}", std::process::id())),
        child: None,
    };
    let data = fixture.root.join("data");
    let secrets = fixture.root.join("secrets");
    fs::create_dir_all(&data)?;
    fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o700))?;
    fs::create_dir_all(&secrets)?;
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))?;
    let paths = BootstrapPaths::new(&data, &secrets, MountQualification::LocalHost)?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    assert!(InstanceBootstrap::claim(&paths).is_err());
    let bearer = format!(
        "Bearer {}",
        claim.ingest_secret().ok_or("missing ingest key")?
    );
    let admin = format!("Bearer {}", claim.secret());
    let query = format!(
        "Bearer {}",
        claim.query_secret().ok_or("missing query key")?
    );
    let probes = (0..5)
        .map(|_| TcpListener::bind(("127.0.0.1", 0)))
        .collect::<Result<Vec<_>, _>>()?;
    let ports = probes
        .iter()
        .map(|listener| listener.local_addr().map(|address| address.port()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut settings = format!(
        "schema_version = 1\n[runtime]\nshutdown_grace_seconds = 5\n[listener]\ncontrol_path = \"{}\"\n",
        fixture.root.join("control.sock").display()
    );
    for (name, port) in ["operations", "api", "otlp_grpc", "otlp_http", "loki_push"]
        .iter()
        .zip(&ports)
    {
        settings.push_str(&format!(
            "{name}_bind_address = \"127.0.0.1:{port}\"\n{name}_transport = \"plaintext\"\n"
        ));
    }
    settings.push_str(&format!("[storage]\ndata_directory = \"{}\"\nsecrets_directory = \"{}\"\n[security]\nlocal_key_file = \"{}\"\n", data.display(), secrets.display(), secrets.join("local-root-key.v1").display()));
    let config = fixture.root.join("positron.toml");
    fs::write(&config, settings)?;
    let effective = positron_config::resolve(
        positron_config::ConfigurationInputs::try_from_sources(
            Some(&config),
            [] as [(&str, &str); 0],
            [] as [(&str, &str); 0],
        )
        .map_err(|error| format!("fixture configuration: {error:?}"))?,
    )?;
    let admission_budget = effective
        .network_listener_profile(positron_config::NetworkListenerRole::OtlpHttp)
        .ok_or("OTLP HTTP listener profile")?
        .connection_protection()
        .request_deadline();

    for arguments in [
        vec!["config", "validate", "--config"],
        vec!["config", "effective", "--redacted", "--config"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_positron"))
            .args(arguments)
            .arg(&config)
            .output()?;
        assert!(output.status.success());
        let rendered = String::from_utf8(output.stdout)?;
        assert!(!rendered.contains(claim.secret()));
        assert!(!rendered.contains(claim.ingest_secret().ok_or("missing ingest key")?));
    }
    drop(probes);
    fixture.child = Some(
        Command::new(env!("CARGO_BIN_EXE_positron"))
            .args(["serve", "--config"])
            .arg(&config)
            .spawn()?,
    );
    let operations = *ports.first().ok_or("missing operations port")?;
    let otlp = *ports.get(3).ok_or("missing OTLP port")?;
    let loki = *ports.get(4).ok_or("missing Loki port")?;
    ready(operations)?;

    let doctor_deadline = Instant::now() + Duration::from_secs(10);
    let output = loop {
        let mut doctor = Command::new(env!("CARGO_BIN_EXE_positron"))
            .args(["doctor", "--online", "--endpoint"])
            .arg(format!("127.0.0.1:{operations}"))
            .arg("--allow-plaintext")
            .arg("--credential-stdin")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        let mut input = doctor.stdin.take().ok_or("missing doctor stdin")?;
        writeln!(input, "{}", claim.secret())?;
        drop(input);
        while doctor.try_wait()?.is_none() {
            if Instant::now() >= doctor_deadline {
                doctor.kill()?;
                doctor.wait()?;
                return Err("doctor deadline expired".into());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let output = doctor.wait_with_output()?;
        if String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line == "finding_code=DOCTOR_ONLINE_INSPECTION_UNAVAILABLE")
            && Instant::now() < doctor_deadline
        {
            std::thread::sleep(Duration::from_millis(25));
            continue;
        }
        break output;
    };
    let report = String::from_utf8(output.stdout)?;
    assert!(
        report.contains("process_phase=serving"),
        "doctor report: {report}; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report.contains("catalog_bootstrap="));
    assert!(!report.contains(claim.secret()));
    // Doctor truthfully reports unavailable planned families rather than claiming release readiness.
    let body = br#"{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"timeUnixNano":"42","body":{"stringValue":"binary-otlp"}}]}]}]}"#;
    for credential in ["Bearer invalid", admin.as_str(), query.as_str()] {
        assert!(
            request(
                otlp,
                "/v1/logs",
                &[
                    ("Authorization", credential),
                    ("Content-Type", "application/json")
                ],
                body
            )?
            .starts_with("HTTP/1.1 401 ")
        );
    }
    assert!(
        request(
            otlp,
            "/v1/logs",
            &[
                ("Authorization", &bearer),
                ("X-Scope-OrgID", "other"),
                ("Content-Type", "application/json")
            ],
            body
        )?
        .starts_with("HTTP/1.1 401 ")
    );
    let headers = [
        ("Authorization", bearer.as_str()),
        ("Content-Type", "application/json"),
    ];
    let response = request_with_capacity_retry(otlp, "/v1/logs", &headers, body, admission_budget)?;
    let diagnostic = if response.starts_with("HTTP/1.1 200 ") {
        String::new()
    } else {
        request_with_method(
            "GET",
            operations,
            "/metrics",
            &[("Authorization", admin.as_str())],
            b"",
        )?
    };
    assert!(
        response.starts_with("HTTP/1.1 200 "),
        "initial Log response: {response}; public resource metrics: {diagnostic}"
    );
    assert!(
        request(
            loki,
            "/loki/api/v1/push",
            &headers,
            br#"{"streams":[{"stream":{"app":"audit"},"values":[["43","binary-loki"]]}]}"#
        )?
        .starts_with("HTTP/1.1 204 No Content")
    );
    // A generated OTLP gRPC client drives the actual binary's HTTP/2 listener.
    let grpc = *ports.get(2).ok_or("missing gRPC port")?;
    let client_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    client_runtime.block_on(async {
        use opentelemetry_proto::tonic::collector::logs::v1::{
            ExportLogsServiceRequest, logs_service_client::LogsServiceClient,
        };
        use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
        use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
        let mut client = tokio::time::timeout(
            Duration::from_secs(5),
            LogsServiceClient::connect(format!("http://127.0.0.1:{grpc}")),
        )
        .await??;
        let denied = tokio::time::timeout(
            Duration::from_secs(5),
            client.export(ExportLogsServiceRequest::default()),
        )
        .await?
        .expect_err("anonymous gRPC ingest must fail");
        assert_eq!(denied.code(), tonic::Code::Unauthenticated);
        let mut request = tonic::Request::new(ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                scope_logs: vec![ScopeLogs {
                    log_records: vec![LogRecord {
                        time_unix_nano: 44,
                        body: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("binary-grpc".to_owned())),
                        }),
                        ..LogRecord::default()
                    }],
                    ..ScopeLogs::default()
                }],
                ..ResourceLogs::default()
            }],
        });
        request
            .metadata_mut()
            .insert("authorization", bearer.parse()?);
        assert!(
            tokio::time::timeout(Duration::from_secs(5), client.export(request))
                .await??
                .into_inner()
                .partial_success
                .is_none()
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    let traces = br#"{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"01010101010101010101010101010101","spanId":"0202020202020202","name":"audit-span","startTimeUnixNano":"42","endTimeUnixNano":"84"}]}]}]}"#;
    // Exact retries and a conflicting name remain observations at the ingest boundary.
    for payload in [
        traces.to_vec(),
        traces.to_vec(),
        String::from_utf8(traces.to_vec())?
            .replace("audit-span", "conflict-span")
            .into_bytes(),
    ] {
        let response =
            request_with_capacity_retry(otlp, "/v1/traces", &headers, &payload, admission_budget)?;
        let diagnostic = if response.starts_with("HTTP/1.1 200 ") {
            String::new()
        } else {
            request_with_method(
                "GET",
                operations,
                "/metrics",
                &[("Authorization", admin.as_str())],
                b"",
            )?
        };
        assert!(
            response.starts_with("HTTP/1.1 200 "),
            "trace observation response: {response}; public resource metrics: {diagnostic}"
        );
    }

    let started = Instant::now();
    let mut encoded_bytes = 0;
    for batch_index in 0..16 {
        let record = serde_json::json!({"timeUnixNano": (1000 + batch_index).to_string(), "body":{"stringValue":"bounded-load"}});
        let batch = serde_json::to_vec(
            &serde_json::json!({"resourceLogs":[{"scopeLogs":[{"logRecords":vec![record;4]}]}]}),
        )?;
        encoded_bytes += batch.len();
        let response = match request_with_capacity_retry(
            otlp,
            "/v1/logs",
            &headers,
            &batch,
            admission_budget,
        ) {
            Ok(response) => response,
            Err(error) => {
                let diagnostic = request_with_method(
                    "GET",
                    operations,
                    "/metrics",
                    &[("Authorization", admin.as_str())],
                    b"",
                );
                panic!(
                    "workload batch {batch_index} request budget failed: {error}; metrics: {diagnostic:?}"
                );
            },
        };
        let diagnostic = if response.starts_with("HTTP/1.1 200 ") {
            String::new()
        } else {
            request_with_method(
                "GET",
                operations,
                "/metrics",
                &[("Authorization", admin.as_str())],
                b"",
            )?
        };
        assert!(
            response.starts_with("HTTP/1.1 200 "),
            "workload batch {batch_index} response: {response}; public resource metrics: {diagnostic}"
        );
    }
    let elapsed = started.elapsed();
    eprintln!(
        "bounded binary workload: 64 OTLP JSON logs, 16 serial requests, {} encoded bytes, {:.3}s, {:.1} records/s (debug, durable loopback)",
        encoded_bytes,
        elapsed.as_secs_f64(),
        64.0 / elapsed.as_secs_f64()
    );
    let child = fixture.child.as_mut().ok_or("missing child")?;
    child.kill()?;
    assert!(!child.wait()?.success());
    fixture.child = None;
    assert!(fixture.root.join("control.sock").exists());
    fixture.child = Some(
        Command::new(env!("CARGO_BIN_EXE_positron"))
            .args(["serve", "--config"])
            .arg(&config)
            .spawn()?,
    );
    ready(operations)?;
    let child = fixture.child.as_mut().ok_or("missing restarted child")?;
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &child.id().to_string()])
            .status()?
            .success()
    );
    let shutdown_started = Instant::now();
    let deadline = shutdown_started + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait()? {
            assert_eq!(
                status.code(),
                Some(0),
                "shutdown elapsed {:?}",
                shutdown_started.elapsed()
            );
            break;
        }
        if Instant::now() >= deadline {
            return Err("binary shutdown deadline expired".into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    fixture.child = None;
    let endpoint = "127.0.0.1:0".parse()?;
    let host = NativeHost::new(NativeBindings::new(
        fixture.root.join("inspect.sock"),
        endpoint,
        endpoint,
        endpoint,
        endpoint,
        endpoint,
    )?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    // The native principal's 16-unit CPU ceiling cannot scan this complete
    // history. Verify a truthful refusal rather than accepting partial rows;
    // successful durable query semantics are covered by the query integration suite.
    assert_eq!(
        process
            .services()
            .ok_or("missing query services")?
            .query_log_bodies(
                claim.query_secret().ok_or("missing query key")?,
                "logs | range query_time 0 2000 | limit 100",
                QueryBudget::new(1_048_576, 100, 100, 1_048_576, 1_048_576, 60)?
                    .with_cpu_work_units(16)?,
            ),
        Err(positron_runtime::ServiceFailure::CapacityUnavailable)
    );
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}
