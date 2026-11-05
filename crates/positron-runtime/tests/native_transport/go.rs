//! The installed generated Go module client talks to the candidate native Rust server.
use super::*;
use std::process::{Command, Stdio};

#[test]
fn generated_go_sdk_conforms_against_candidate_server() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("go-sdk")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let host = NativeHost::new(bindings(&roots, "go-sdk")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let endpoints = process.bound_endpoints();
    let endpoint = address(&endpoints, positron_runtime::ListenerRole::Api)?;
    let ingest = address(&endpoints, positron_runtime::ListenerRole::OtlpHttp)?;
    let authorization = format!("Bearer {}", claim.ingest_secret().ok_or("ingest key")?);
    let payload = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    time_unix_nano: 42,
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    }
    .encode_to_vec();
    for _ in 0..2 {
        assert_status(
            http(
                ingest,
                "POST",
                "/v1/logs",
                &[
                    ("Authorization", &authorization),
                    ("Content-Type", "application/x-protobuf"),
                ],
                &payload,
            )?,
            200,
        );
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut child = Command::new("python3")
        .arg(root.join("sdk/tests/go/live.py"))
        .current_dir(&root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let input = serde_json::json!({"endpoint":format!("http://{endpoint}"),"bearer":claim.query_secret().ok_or("query key")?,"admin":claim.secret()});
    child
        .stdin
        .take()
        .ok_or("child input")?
        .write_all(&serde_json::to_vec(&input)?)?;
    let output = child.wait_with_output()?;
    drop(process);
    assert!(
        output.status.success(),
        "Go conformance: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Go live conformance passed"));
    Ok(())
}
