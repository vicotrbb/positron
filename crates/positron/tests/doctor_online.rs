//! Public online-Doctor transport regressions.

use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    process::{Command, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const STATUS_BODY: &str = "{\"phase\":\"serving\",\"integrity_degraded\":false,\"effective_digest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"desired_digest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"drift_disposition\":\"none\",\"pending_restart\":false,\"doctor\":{\"key_custody\":\"verified\",\"catalog_bootstrap\":\"verified\",\"catalog_generation\":1,\"backup_repository\":\"configured\",\"durable_operations\":0,\"active_durable_operations\":0,\"snapshot_leases\":0,\"listener_topology\":{\"control\":true,\"operations\":true,\"api\":true,\"otlp_grpc\":true,\"otlp_http\":true,\"loki_push\":true},\"required_families\":{\"storage\":{\"disposition\":\"observed\",\"ownership\":\"held\",\"capabilities\":\"not_probed_read_only\",\"usable_disk_bytes\":100000000,\"disk_pressure\":\"healthy\"},\"catalog_integrity\":{\"disposition\":\"observed\",\"audit_chain\":\"verified\",\"frontier\":1,\"manifest_objects\":7,\"quarantine_findings\":0,\"scrub\":\"observed\"},\"resource_governor\":{\"disposition\":\"observed\",\"queues\":\"observed\",\"fairness\":\"within_bound\",\"recovery_reserve\":\"configured\"},\"listener_security\":{\"disposition\":\"observed\",\"profiles\":\"active\",\"certificates\":\"loaded\",\"proxy_trust\":\"not_configured\",\"drain\":\"accepting\"},\"backup_verification\":{\"disposition\":\"observed\",\"manifest_verification\":\"verified\",\"purge_compatibility\":\"compatible\"},\"health_state\":{\"disposition\":\"observed\",\"derivation\":\"serving_ready_live\"},\"configuration\":{\"disposition\":\"observed\",\"contract\":\"valid\",\"effective_sources\":\"redacted\",\"key_custody\":\"verified\"}}},\"maintenance\":{\"queued\":0,\"outstanding_reservations\":0,\"clock_uncertain\":false,\"running_no_durable_progress_slo_breaches\":0,\"running_no_durable_progress_slo_unknown\":0,\"checkpointed_tasks\":0,\"paused_tasks\":0,\"conflicted_tasks\":0}}";
const LISTENER_WAIT: Duration = Duration::from_secs(10);
const CHILD_WAIT: Duration = Duration::from_secs(9);
const REQUEST_BOUND: Duration = Duration::from_secs(6);
const STALL_DURATION: Duration = Duration::from_secs(7);

#[derive(Debug, PartialEq, Eq)]
enum ProxyObservation {
    NoRequest,
    ReceivedRequest,
}

#[test]
fn online_doctor_bypasses_an_ambient_proxy_before_sending_administrator_bearer()
-> Result<(), Box<dyn std::error::Error>> {
    let done = Arc::new(AtomicBool::new(false));
    let status_listener = TcpListener::bind("127.0.0.1:0")?;
    let status_endpoint = status_listener.local_addr()?;
    let status = spawn_status_listener(status_listener, Arc::clone(&done));
    let proxy_listener = TcpListener::bind("127.0.0.1:0")?;
    let proxy_endpoint = proxy_listener.local_addr()?;
    let proxy = spawn_proxy_listener(proxy_listener, Arc::clone(&done));

    let child = online_doctor(status_endpoint, Some(proxy_endpoint));
    done.store(true, Ordering::Release);
    let status_result = join_listener(status, "status listener");
    let proxy_result = join_listener(proxy, "proxy listener");
    let output = child?;
    assert_eq!(proxy_result?, ProxyObservation::NoRequest);
    status_result?;
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8(output.stdout)?.contains("status=healthy"));
    Ok(())
}

#[test]
fn online_doctor_reports_unavailable_within_the_five_second_deadline_when_a_peer_stalls()
-> Result<(), Box<dyn std::error::Error>> {
    let done = Arc::new(AtomicBool::new(false));
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?;
    let server = spawn_stalling_listener(listener, Arc::clone(&done));

    let child = online_doctor(endpoint, None);
    let finished = Instant::now();
    done.store(true, Ordering::Release);
    let accepted_at = join_listener(server, "stalling status listener")?;
    let output = child?;

    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(
        String::from_utf8(output.stdout)?
            .contains("finding_code=DOCTOR_ONLINE_INSPECTION_UNAVAILABLE")
    );
    assert!(
        finished.duration_since(accepted_at) < REQUEST_BOUND,
        "request exceeded the configured bound after the peer accepted it"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn online_doctor_rejects_an_oversized_trust_file_before_connecting()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temporary_path("oversized-trust.pem");
    std::fs::write(&path, vec![0_u8; 65_537])?;

    let output = online_doctor_with_trust_file(&path)?;

    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout)?,
        "report_version=1\nmode=online\nstatus=trust_file_rejected\nfinding_code=DOCTOR_TRUST_FILE_REJECTED\nseverity=error\nevidence_scope=none\nsafe_command=provide_a_regular_bounded_trust_file\n"
    );
    std::fs::remove_file(path)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn online_doctor_rejects_a_non_regular_trust_file_without_opening_it()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temporary_path("socket-trust.pem");
    let listener = std::os::unix::net::UnixListener::bind(&path)?;

    let output = online_doctor_with_trust_file(&path)?;

    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout)?,
        "report_version=1\nmode=online\nstatus=trust_file_rejected\nfinding_code=DOCTOR_TRUST_FILE_REJECTED\nseverity=error\nevidence_scope=none\nsafe_command=provide_a_regular_bounded_trust_file\n"
    );
    drop(listener);
    std::fs::remove_file(path)?;
    Ok(())
}

fn spawn_status_listener(
    listener: TcpListener,
    done: Arc<AtomicBool>,
) -> JoinHandle<io::Result<()>> {
    spawn_status_body(listener, done, STATUS_BODY.to_owned())
}

fn spawn_status_body(
    listener: TcpListener,
    done: Arc<AtomicBool>,
    body: String,
) -> JoinHandle<io::Result<()>> {
    thread::spawn(move || {
        let mut stream = accept_direct_request(&listener, &done, "status listener")?;
        read_request(&mut stream)?;
        stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
    })
}

fn spawn_proxy_listener(
    listener: TcpListener,
    done: Arc<AtomicBool>,
) -> JoinHandle<io::Result<ProxyObservation>> {
    thread::spawn(move || {
        listener.set_nonblocking(true)?;
        let deadline = Instant::now() + LISTENER_WAIT;
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    read_request(&mut stream)?;
                    stream.write_all(
                        b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )?;
                    return Ok(ProxyObservation::ReceivedRequest);
                },
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if done.load(Ordering::Acquire) {
                        return Ok(ProxyObservation::NoRequest);
                    }
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "proxy listener did not observe completion within its bound",
                        ));
                    }
                    thread::sleep(Duration::from_millis(10));
                },
                Err(error) => return Err(error),
            }
        }
    })
}

fn spawn_stalling_listener(
    listener: TcpListener,
    done: Arc<AtomicBool>,
) -> JoinHandle<io::Result<Instant>> {
    thread::spawn(move || {
        let mut stream = accept_direct_request(&listener, &done, "stalling status listener")?;
        read_request(&mut stream)?;
        let accepted_at = Instant::now();
        while accepted_at.elapsed() < STALL_DURATION && !done.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(10));
        }
        Ok(accepted_at)
    })
}

fn accept_direct_request(
    listener: &TcpListener,
    done: &AtomicBool,
    listener_name: &str,
) -> io::Result<TcpStream> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + LISTENER_WAIT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if done.load(Ordering::Acquire) {
                    return Err(io::Error::other(format!(
                        "{listener_name} stopped before accepting the Doctor request"
                    )));
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "{listener_name} did not receive a Doctor request within its bound"
                        ),
                    ));
                }
                thread::sleep(Duration::from_millis(10));
            },
            Err(error) => return Err(error),
        }
    }
}

fn read_request(stream: &mut TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut request = [0_u8; 4096];
    if stream.read(&mut request)? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Doctor connected without sending an HTTP request",
        ));
    }
    Ok(())
}

fn join_listener<T>(
    listener: JoinHandle<io::Result<T>>,
    listener_name: &str,
) -> Result<T, Box<dyn std::error::Error>> {
    let result = listener
        .join()
        .map_err(|_| io::Error::other(format!("{listener_name} panicked")))?;
    Ok(result?)
}

fn online_doctor(
    endpoint: std::net::SocketAddr,
    proxy: Option<std::net::SocketAddr>,
) -> Result<Output, Box<dyn std::error::Error>> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_positron"));
    command
        .args([
            "doctor",
            "--online",
            "--credential-stdin",
            "--endpoint",
            &endpoint.to_string(),
            "--allow-plaintext",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy");
    if let Some(proxy) = proxy {
        command.env("HTTP_PROXY", format!("http://{proxy}"));
    }
    let mut child = command.spawn()?;
    let stdin = child
        .stdin
        .as_mut()
        .ok_or("doctor credential stdin unavailable")?;
    if let Err(error) = stdin.write_all(b"system-administrator\n") {
        terminate_child(&mut child)?;
        return Err(Box::new(error));
    }
    child.stdin.take();
    let status = wait_for_child(&mut child)?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or("doctor stdout unavailable after child completion")?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or("doctor stderr unavailable after child completion")?;
    let mut output = Output {
        status,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    stdout.read_to_end(&mut output.stdout)?;
    stderr.read_to_end(&mut output.stderr)?;
    Ok(output)
}

#[cfg(unix)]
fn online_doctor_with_trust_file(
    trust_file: &std::path::Path,
) -> Result<Output, Box<dyn std::error::Error>> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_positron"));
    command
        .args([
            "doctor",
            "--online",
            "--endpoint",
            "127.0.0.1:1",
            "--credential-stdin",
            "--server-name",
            "localhost",
            "--trust-file",
        ])
        .arg(trust_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut child = command.spawn()?;
    let mut input = child.stdin.take().ok_or("doctor stdin")?;
    input.write_all(b"system-administrator\n")?;
    drop(input);
    Ok(child.wait_with_output()?)
}

#[cfg(unix)]
fn temporary_path(name: &str) -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("positron-doctor-{name}-{nonce}"))
}

fn wait_for_child(child: &mut std::process::Child) -> io::Result<std::process::ExitStatus> {
    let deadline = Instant::now() + CHILD_WAIT;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            terminate_child(child)?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Doctor child exceeded the bounded test deadline",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn terminate_child(child: &mut std::process::Child) -> io::Result<()> {
    match child.try_wait()? {
        Some(_) => Ok(()),
        None => {
            child.kill()?;
            let _status = child.wait()?;
            Ok(())
        },
    }
}

#[test]
fn online_doctor_excludes_unknown_secret_canaries_from_declared_fields()
-> Result<(), Box<dyn std::error::Error>> {
    const CANARY: &str = "secretcanary87NeverExportThis";
    for (field, original) in [
        ("phase", "serving"),
        (
            "effective_digest",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        ("key_custody", "verified"),
        ("backup_repository", "configured"),
    ] {
        let done = Arc::new(AtomicBool::new(false));
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = listener.local_addr()?;
        let body = STATUS_BODY.replace(
            &format!("\"{field}\":\"{original}\""),
            &format!("\"{field}\":\"{CANARY}\""),
        );
        let server = spawn_status_body(listener, Arc::clone(&done), body);
        let result = online_doctor(endpoint, None);
        done.store(true, Ordering::Release);
        join_listener(server, "canary status listener")?;
        let output = result?;
        let stdout = String::from_utf8(output.stdout)?;
        assert!(
            !stdout.contains(CANARY),
            "prohibited field {field} escaped: {stdout}"
        );
        assert_eq!(output.status.code(), Some(3));
        assert!(stdout.contains("DOCTOR_ONLINE_INSPECTION_UNAVAILABLE"));
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn online_control_doctor_bounds_the_whole_response_when_a_peer_trickles_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};
    let path = temporary_path("trickle.sock");
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let done = Arc::new(AtomicBool::new(false));
    let server_done = Arc::clone(&done);
    let server = thread::spawn(move || -> io::Result<Instant> {
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        let mut request = [0_u8; 4096];
        assert!(stream.read(&mut request)? > 0);
        let accepted = Instant::now();
        while accepted.elapsed() < STALL_DURATION && !server_done.load(Ordering::Acquire) {
            if stream.write_all(b"x").is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        Ok(accepted)
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["doctor", "--online", "--credential-stdin", "--control-path"])
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut input = child.stdin.take().ok_or("doctor stdin")?;
    input.write_all(b"system-administrator\n")?;
    drop(input);
    let status = wait_for_child(&mut child);
    let finished = Instant::now();
    done.store(true, Ordering::Release);
    let accepted = join_listener(server, "trickling control listener")?;
    let status = status?;
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .ok_or("doctor stdout")?
        .read_to_string(&mut stdout)?;
    std::fs::remove_file(path)?;
    assert_eq!(status.code(), Some(3));
    assert!(stdout.contains("DOCTOR_ONLINE_INSPECTION_UNAVAILABLE"));
    assert!(
        finished.duration_since(accepted) < REQUEST_BOUND,
        "control response exceeded the five-second whole-request deadline"
    );
    Ok(())
}

#[test]
fn online_doctor_excludes_unknown_family_values_and_does_not_claim_complete_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let done = Arc::new(AtomicBool::new(false));
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?;
    let body = STATUS_BODY.replace(
        "\"audit_chain\":\"verified\"",
        "\"audit_chain\":\"secretcanaryFamily87\"",
    );
    let server = spawn_status_body(listener, Arc::clone(&done), body);
    let result = online_doctor(endpoint, None);
    done.store(true, Ordering::Release);
    join_listener(server, "family status listener")?;
    let output = result?;
    let stdout = String::from_utf8(output.stdout)?;
    assert!(
        !stdout.contains("secretcanaryFamily87"),
        "unknown family value escaped: {stdout}"
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(stdout.contains("catalog_audit_chain=missing"));
    assert!(stdout.contains("required_diagnostic_families_complete=false"));
    Ok(())
}
