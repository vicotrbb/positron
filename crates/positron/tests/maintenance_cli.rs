use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::sync::Arc;

const TASK_ID: &str = "abababababababababababababababab";
const TENANT: &str = "22222222-2222-2222-2222-222222222222";
const IDEMPOTENCY_KEY: &str = "01010101-0101-0101-0101-010101010101";
const CREDENTIAL: &str = "system-administrator-secret";

#[test]
fn maintenance_status_cli_forwards_a_piped_system_bearer() -> Result<(), Box<dyn std::error::Error>>
{
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?.to_string();
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        let (mut stream, _) = listener.accept()?;
        let mut bytes = [0_u8; 4096];
        let read = stream.read(&mut bytes)?;
        let request = String::from_utf8_lossy(&bytes[..read]);
        assert!(request.starts_with("POST /v1/maintenance:status HTTP/1.1\r\n"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer system-administrator\r\n")
        );
        let body = r#"{"tasks":[],"returned":0,"total":0,"queued":0,"running":0,"deferred":0,"terminal":0}"#;
        stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )?;
        Ok(())
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args([
            "maintenance",
            "status",
            "--endpoint",
            &endpoint,
            "--credential-stdin",
            "--allow-plaintext",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("stdin unavailable")?
        .write_all(b"system-administrator")?;
    let output = child.wait_with_output()?;
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stdout)?
            .contains("queued=0 running=0 deferred=0 terminal=0 total=0 tasks=0 pages=1")
    );
    assert!(String::from_utf8(output.stderr)?.is_empty());
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn maintenance_status_cli_defaults_to_tls_and_renders_complete_paged_task_facts()
-> Result<(), Box<dyn std::error::Error>> {
    let certificate = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../positron-runtime/tests/native_transport/fixtures/api-test-cert.pem"
    );
    let private_key = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../positron-runtime/tests/native_transport/fixtures/api-test-key.pem"
    );
    let certificates =
        CertificateDer::pem_file_iter(certificate)?.collect::<Result<Vec<_>, _>>()?;
    let private_key = PrivateKeyDer::from_pem_slice(&std::fs::read(private_key)?)?;
    let configuration = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?.to_string();
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        for (expected_body, body) in [
            (
                "{}",
                status_page(
                    &detailed_task("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "queued"),
                    Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                ),
            ),
            (
                r#"{"cursor":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","limit":32}"#,
                status_page(&terminal_task("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), None),
            ),
        ] {
            let (stream, _) = listener.accept()?;
            let connection = ServerConnection::new(Arc::new(configuration.clone()))
                .map_err(std::io::Error::other)?;
            let mut stream = StreamOwned::new(connection, stream);
            let mut bytes = [0_u8; 8192];
            let read = stream.read(&mut bytes)?;
            let request = String::from_utf8_lossy(&bytes[..read]);
            assert!(request.starts_with("POST /v1/maintenance:status HTTP/1.1\r\n"));
            assert!(request.contains(&format!("\r\n\r\n{expected_body}")));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("authorization: bearer system-administrator-secret\r\n")
            );
            stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )?;
        }
        Ok(())
    });
    let output = run_tls_status(&endpoint, certificate, "localhost")?;
    assert!(output.status.success(), "{output:?}");
    let visible = stdout(&output)?;
    assert!(visible.contains("total=2 tasks=2 pages=2"), "{visible}");
    for fact in [
        "reservations=memory_bytes=11,queue_slots=12,task_slots=13",
        "conflict_owner=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "blocked_precondition=maintenance_pause_active",
        "estimated_output_object_amplification_milli=1250",
        "expected_foreground_impact=memory_bytes=21,queue_slots=22,task_slots=23",
        "checkpoint_sequence=7",
        "checkpoint_completed_inputs=3",
        "terminal_outcome=succeeded",
        "safe_actions=resume",
        "last_progress_at_unix_seconds=unknown",
        "terminal_failure_class=unknown",
    ] {
        assert!(visible.contains(fact), "missing {fact} in {visible}");
    }
    assert!(stderr(&output)?.is_empty());
    server
        .join()
        .map_err(|_| "TLS loopback server panicked")??;
    Ok(())
}

#[test]
fn maintenance_cli_rejects_invalid_or_ambiguous_transport_options()
-> Result<(), Box<dyn std::error::Error>> {
    for arguments in [
        vec![
            "maintenance",
            "status",
            "--endpoint",
            "127.0.0.1:1",
            "--credential-stdin",
        ],
        vec![
            "maintenance",
            "status",
            "--endpoint",
            "127.0.0.1:1",
            "--credential-stdin",
            "--allow-plaintext",
            "--server-name",
            "localhost",
        ],
        vec![
            "maintenance",
            "status",
            "--endpoint",
            "127.0.0.1:1",
            "--credential-stdin",
            "--server-name",
            "127.0.0.2",
            "--trust-file",
            "Cargo.toml",
        ],
        vec![
            "maintenance",
            "status",
            "--endpoint",
            "127.0.0.1:1",
            "--credential-stdin",
            "--server-name",
            "localhost",
            "--trust-file",
            "Cargo.toml",
        ],
    ] {
        let output = run_with_credential(arguments)?;
        assert!(!output.status.success(), "{output:?}");
    }
    Ok(())
}

#[test]
fn maintenance_status_rejects_malformed_or_non_progressing_continuations()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?.to_string();
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        let (mut stream, _) = listener.accept()?;
        let body = format!(
            r#"{{"tasks":[{}],"returned":1,"total":2,"next_cursor":"not-a-task","queued":1,"running":0,"deferred":0,"terminal":1}}"#,
            task("queued")
        );
        stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )?;
        Ok(())
    });
    assert_failure(
        run_control(&endpoint, ["status"])?,
        "maintenance API transport failed",
    )?;
    server
        .join()
        .map_err(|_| "malformed cursor server panicked")??;

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?.to_string();
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        for body in [
            status_page(&task("queued"), Some(TASK_ID)),
            status_page(&task("queued"), None),
        ] {
            let (mut stream, _) = listener.accept()?;
            stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )?;
        }
        Ok(())
    });
    assert_failure(
        run_control(&endpoint, ["status"])?,
        "maintenance status pagination did not advance",
    )?;
    server
        .join()
        .map_err(|_| "non-progressing cursor server panicked")??;
    Ok(())
}

#[test]
fn maintenance_controls_forward_bounded_requests_and_report_canonical_tasks()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?.to_string();
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        for (path, expected_body, body) in [
            (
                "/v1/maintenance:explain",
                format!(r#"{{"identity":"{TASK_ID}"}}"#),
                task_response("queued"),
            ),
            (
                "/v1/maintenance:run",
                format!(
                    r#"{{"class":"compaction","tenant":"{TENANT}","signal":"logs","shard":7,"idempotency_key":"{IDEMPOTENCY_KEY}"}}"#
                ),
                run_response(),
            ),
            (
                "/v1/maintenance:pause",
                format!(
                    r#"{{"identity":"{TASK_ID}","resource_generation":4,"duration_seconds":3600,"idempotency_key":"{IDEMPOTENCY_KEY}"}}"#
                ),
                control_response("pause", 13),
            ),
            (
                "/v1/maintenance:resume",
                format!(r#"{{"identity":"{TASK_ID}","idempotency_key":"{IDEMPOTENCY_KEY}"}}"#),
                control_response("resume", 14),
            ),
        ] {
            let (mut stream, _) = listener.accept()?;
            let mut bytes = [0_u8; 4096];
            let read = stream.read(&mut bytes)?;
            let request = String::from_utf8_lossy(&bytes[..read]);
            assert!(request.starts_with(&format!("POST {path} HTTP/1.1\r\n")));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains(&format!("authorization: bearer {CREDENTIAL}\r\n"))
            );
            assert!(request.contains(&format!("\r\n\r\n{expected_body}")));
            stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )?;
        }
        Ok(())
    });

    let explain = run_control(&endpoint, ["explain", "--task-id", TASK_ID])?;
    assert!(explain.status.success(), "{explain:?}");
    assert!(stdout(&explain)?.contains(&format!("identity={TASK_ID} class=compaction")));

    let run = run_control(
        &endpoint,
        [
            "run",
            "--tenant",
            TENANT,
            "--signal",
            "logs",
            "--shard",
            "7",
            "--idempotency-key",
            IDEMPOTENCY_KEY,
        ],
    )?;
    assert!(run.status.success(), "{run:?}");
    assert!(stdout(&run)?.contains("resource_generation=4"));

    let pause = run_control(
        &endpoint,
        [
            "pause",
            "--task-id",
            TASK_ID,
            "--resource-generation",
            "4",
            "--duration-seconds",
            "3600",
            "--idempotency-key",
            IDEMPOTENCY_KEY,
        ],
    )?;
    assert!(pause.status.success(), "{pause:?}");
    let pause_stdout = stdout(&pause)?;
    assert!(pause_stdout.contains("action=pause resource_generation=4"));
    assert!(pause_stdout.contains("audit_position=13"));

    let resume = run_control(
        &endpoint,
        [
            "resume",
            "--task-id",
            TASK_ID,
            "--idempotency-key",
            IDEMPOTENCY_KEY,
        ],
    )?;
    assert!(resume.status.success(), "{resume:?}");
    let resume_stdout = stdout(&resume)?;
    assert!(resume_stdout.contains("action=resume resource_generation=none"));
    assert!(resume_stdout.contains("audit_position=14"));
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn maintenance_explain_reports_unavailable_task_without_disclosing_stdin_credential()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?.to_string();
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        let (mut stream, _) = listener.accept()?;
        let mut bytes = [0_u8; 4096];
        let read = stream.read(&mut bytes)?;
        let request = String::from_utf8_lossy(&bytes[..read]);
        assert!(request.starts_with("POST /v1/maintenance:explain HTTP/1.1\r\n"));
        let body = r#"{"code":"task_unavailable"}"#;
        stream.write_all(
            format!(
                "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )?;
        Ok(())
    });

    let output = run_control(&endpoint, ["explain", "--task-id", TASK_ID])?;
    assert!(!output.status.success(), "{output:?}");
    let visible = format!("{}{}", stdout(&output)?, stderr(&output)?);
    assert!(
        visible.contains("maintenance task unavailable"),
        "{visible}"
    );
    assert!(!visible.contains(CREDENTIAL), "{visible}");
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn maintenance_status_run_pause_and_resume_report_canonical_failures_without_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?.to_string();
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        for (path, status, body) in [
            (
                "/v1/maintenance:status",
                "503 Service Unavailable",
                r#"{"code":"administration_unavailable"}"#,
            ),
            (
                "/v1/maintenance:run",
                "404 Not Found",
                r#"{"code":"source_unavailable"}"#,
            ),
            (
                "/v1/maintenance:pause",
                "409 Conflict",
                r#"{"code":"precondition_failed"}"#,
            ),
            (
                "/v1/maintenance:resume",
                "409 Conflict",
                r#"{"code":"idempotency_conflict"}"#,
            ),
        ] {
            let (mut stream, _) = listener.accept()?;
            let mut bytes = [0_u8; 4096];
            let read = stream.read(&mut bytes)?;
            let request = String::from_utf8_lossy(&bytes[..read]);
            assert!(request.starts_with(&format!("POST {path} HTTP/1.1\r\n")));
            stream.write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )?;
        }
        Ok(())
    });

    assert_failure(
        run_control(&endpoint, ["status"])?,
        "maintenance administration unavailable",
    )?;
    assert_failure(
        run_control(
            &endpoint,
            [
                "run",
                "--tenant",
                TENANT,
                "--signal",
                "logs",
                "--shard",
                "7",
                "--idempotency-key",
                IDEMPOTENCY_KEY,
            ],
        )?,
        "maintenance source unavailable",
    )?;
    assert_failure(
        run_control(
            &endpoint,
            [
                "pause",
                "--task-id",
                TASK_ID,
                "--resource-generation",
                "4",
                "--duration-seconds",
                "3600",
                "--idempotency-key",
                IDEMPOTENCY_KEY,
            ],
        )?,
        "maintenance precondition failed",
    )?;
    assert_failure(
        run_control(
            &endpoint,
            [
                "resume",
                "--task-id",
                TASK_ID,
                "--idempotency-key",
                IDEMPOTENCY_KEY,
            ],
        )?,
        "maintenance idempotency conflict",
    )?;
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn maintenance_pause_rejects_a_duration_outside_the_bounded_window()
-> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args([
            "maintenance",
            "pause",
            "--endpoint",
            "127.0.0.1:1",
            "--credential-stdin",
            "--allow-plaintext",
            "--task-id",
            TASK_ID,
            "--resource-generation",
            "1",
            "--duration-seconds",
            "86401",
            "--idempotency-key",
            IDEMPOTENCY_KEY,
        ])
        .stdin(Stdio::null())
        .output()?;
    assert!(!output.status.success(), "{output:?}");
    assert!(stderr(&output)?.contains("invalid maintenance pause request"));
    Ok(())
}

fn run_control<const N: usize>(
    endpoint: &str,
    arguments: [&str; N],
) -> Result<std::process::Output, std::io::Error> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .arg("maintenance")
        .args(arguments)
        .args([
            "--endpoint",
            endpoint,
            "--credential-stdin",
            "--allow-plaintext",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("stdin unavailable"))?
        .write_all(CREDENTIAL.as_bytes())?;
    child.wait_with_output()
}

fn run_tls_status(
    endpoint: &str,
    trust_file: &str,
    server_name: &str,
) -> Result<std::process::Output, std::io::Error> {
    run_with_credential([
        "maintenance",
        "status",
        "--endpoint",
        endpoint,
        "--credential-stdin",
        "--server-name",
        server_name,
        "--trust-file",
        trust_file,
    ])
}

fn run_with_credential<'a>(
    arguments: impl IntoIterator<Item = &'a str>,
) -> Result<std::process::Output, std::io::Error> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("stdin unavailable"))?
        .write_all(CREDENTIAL.as_bytes())?;
    child.wait_with_output()
}

fn status_page(task: &str, next_cursor: Option<&str>) -> String {
    let next_cursor = next_cursor.map_or_else(String::new, |cursor| {
        format!(",\"next_cursor\":\"{cursor}\"")
    });
    format!(
        r#"{{"tasks":[{task}],"returned":1,"total":2{next_cursor},"queued":1,"running":0,"deferred":0,"terminal":1}}"#
    )
}

fn detailed_task(identity: &str, phase: &str) -> String {
    format!(
        r#"{{"identity":"{identity}","class":"compaction","scope":"tenant:{TENANT}","phase":"{phase}","submitted_at_unix_seconds":123,"checkpoint_sequence":7,"capacity_risk":"foreground_reservation","retention_impact":"unaffected","recovery_impact":"unaffected","cancellation_requested":false,"resource_generation":2,"reservations":{},"expected_foreground_impact":{},"blocked_precondition":"maintenance_pause_active","safe_actions":["resume"],"backlog_age_seconds":9,"conflict_owner":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","checkpoint_completed_inputs":3,"input_object_count":4,"output_object_count":5,"estimated_output_object_amplification_milli":1250}}"#,
        reservations(11),
        reservations(21),
    )
}

fn terminal_task(identity: &str) -> String {
    format!(
        r#"{{"identity":"{identity}","class":"compaction","scope":"tenant:{TENANT}","phase":"succeeded","submitted_at_unix_seconds":124,"cancellation_requested":false,"input_object_count":1,"output_object_count":1,"terminal_outcome":"succeeded"}}"#
    )
}

fn reservations(start: u64) -> String {
    format!(
        r#"{{"memory_bytes":{start},"queue_slots":{},"task_slots":{},"buffer_cache_bytes":{},"batch_items":{},"lease_slots":{},"retry_slots":{},"io_permits":{},"cpu_work_units":{},"file_descriptors":{},"disk_headroom_bytes":{}}}"#,
        start + 1,
        start + 2,
        start + 3,
        start + 4,
        start + 5,
        start + 6,
        start + 7,
        start + 8,
        start + 9,
        start + 10,
    )
}

fn task_response(phase: &str) -> String {
    format!(r#"{{"task":{}}}"#, task(phase))
}

fn run_response() -> String {
    format!(
        r#"{{"task":{},"resource_generation":4}}"#,
        acknowledgement()
    )
}

fn control_response(action: &str, audit_position: u64) -> String {
    match action {
        "pause" => format!(
            r#"{{"task":{},"action":"pause","resource_generation":4,"pause_until_unix_seconds":3723,"audit_position":{audit_position}}}"#,
            acknowledgement()
        ),
        "resume" => format!(
            r#"{{"task":{},"action":"resume","audit_position":{audit_position}}}"#,
            acknowledgement()
        ),
        _ => String::new(),
    }
}

fn acknowledgement() -> String {
    format!(
        r#"{{"identity":"{TASK_ID}","class":"compaction","scope":"tenant:{TENANT}","submitted_at_unix_seconds":123}}"#
    )
}

fn task(phase: &str) -> String {
    format!(
        r#"{{"identity":"{TASK_ID}","class":"compaction","scope":"tenant:{TENANT}","phase":"{phase}","submitted_at_unix_seconds":123,"cancellation_requested":false}}"#
    )
}

fn stdout(output: &std::process::Output) -> Result<String, std::string::FromUtf8Error> {
    String::from_utf8(output.stdout.clone())
}

fn stderr(output: &std::process::Output) -> Result<String, std::string::FromUtf8Error> {
    String::from_utf8(output.stderr.clone())
}

fn assert_failure(
    output: std::process::Output,
    expected_message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    assert!(!output.status.success(), "{output:?}");
    let visible = format!("{}{}", stdout(&output)?, stderr(&output)?);
    assert!(visible.contains(expected_message), "{visible}");
    assert!(!visible.contains(CREDENTIAL), "{visible}");
    Ok(())
}
