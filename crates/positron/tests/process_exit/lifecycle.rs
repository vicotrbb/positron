use super::diagnostics::support::*;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{io::BufRead, io::BufReader, io::Read};

#[cfg(unix)]
use positron_kernel::MountQualification;
#[cfg(unix)]
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::process::Stdio;

#[cfg(target_os = "macos")]
use super::diagnostics::PROCESS_TEST;
#[cfg(all(unix, not(target_os = "macos")))]
static PROCESS_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(unix)]
#[test]
fn first_os_signal_drains_and_exits_successfully() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root =
        std::env::temp_dir().join(format!("positron-process-{}-{nonce}", std::process::id()));
    let data = root.join("data");
    let secrets = root.join("secrets");
    fs::create_dir_all(&data).map_err(|error| format!("create data: {error}"))?;
    fs::create_dir_all(&secrets).map_err(|error| format!("create secrets: {error}"))?;
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("protect secrets: {error}"))?;
    let [
        operations_port,
        api_port,
        otlp_grpc_port,
        otlp_http_port,
        loki_push_port,
    ] = available_ports()?;
    let configuration = process_configuration(
        &root,
        &data,
        &secrets,
        [
            operations_port,
            api_port,
            otlp_grpc_port,
            otlp_http_port,
            loki_push_port,
        ],
    );
    let config_path = root.join("positron.toml");
    fs::write(&config_path, configuration)
        .map_err(|error| format!("write configuration: {error}"))?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["serve", "--init-if-empty", "--config"])
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("spawn positron: {error}"))?;
    wait_for_ready(operations_port)?;
    std::thread::sleep(Duration::from_millis(50));
    let signal = Command::new("/bin/kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .map_err(|error| format!("signal positron: {error}"))?;
    assert!(signal.success());
    let status = wait_for_child(&mut child)?;
    let authorization = format!(
        "Bearer {}",
        InstanceBootstrap::claim(&BootstrapPaths::new(
            &data,
            &secrets,
            MountQualification::LocalHost,
        )?)?
        .secret()
    );
    assert_eq!(
        status.code(),
        Some(0),
        "first termination must drain gracefully; stderr={:?}; {}",
        bounded_child_stderr(&mut child, &authorization),
        bounded_crash_record_observation(&data, &secrets, &authorization),
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn supervised_cold_launch_retains_original_checkpoint_before_late_readiness()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = Arc::clone(&stop);
    let ready_at = Instant::now() + Duration::from_millis(2700);
    let server = std::thread::spawn(move || -> std::io::Result<()> {
        while !stopped.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false)?;
                    let io_deadline = Instant::now() + Duration::from_millis(100);
                    stream.set_read_timeout(Some(
                        io_deadline.saturating_duration_since(Instant::now()),
                    ))?;
                    let mut request = [0; 256];
                    match stream.read(&mut request) {
                        Ok(0) => continue,
                        Ok(_) => {},
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) =>
                        {
                            continue;
                        },
                        Err(error) => return Err(error),
                    }
                    let status = if Instant::now() >= ready_at {
                        "200 OK"
                    } else {
                        "503 Service Unavailable"
                    };
                    let body = "{\"status\":\"not_ready\"}";
                    let remaining = io_deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        continue;
                    }
                    stream.set_write_timeout(Some(remaining))?;
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    stream.write_all(response.as_bytes())?;
                },
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5))
                },
                Err(error) => return Err(error),
            }
        }
        Ok(())
    });
    let mut child = Command::new("/bin/sh")
        .args(["-c", "read -r line"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut diagnostics = Vec::new();
    let outcome = wait_for_supervised_readiness(
        &mut child,
        port,
        std::path::Path::new("/unavailable-supervised-test-control.sock"),
        Instant::now(),
        true,
        &mut diagnostics,
    );
    stop.store(true, Ordering::Release);
    let cleanup = terminate_and_describe_child(&mut child, "");
    let server_outcome = server.join();
    outcome?;
    server_outcome.map_err(|_| "scripted readiness server panic")??;
    let diagnostics = String::from_utf8(diagnostics)?;
    assert!(diagnostics.contains("original_checkpoint"), "{diagnostics}");
    assert!(diagnostics.contains("http_503"), "{diagnostics}");
    assert!(diagnostics.contains("child_state=running"), "{diagnostics}");
    assert!(
        diagnostics.contains("first_complete_operations_ms=Some("),
        "{diagnostics}"
    );
    assert!(diagnostics.len() < 2048, "{diagnostics}");
    assert!(child.try_wait()?.is_some(), "{cleanup}");
    Ok(())
}

#[cfg(unix)]
#[test]
fn supervised_cold_launch_does_not_refresh_an_expired_total_budget()
-> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new("/bin/sh")
        .args(["-c", "read -r line"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let started = Instant::now()
        .checked_sub(Duration::from_secs(10))
        .ok_or("monotonic time unavailable")?;
    let outcome = wait_for_supervised_readiness(
        &mut child,
        0,
        std::path::Path::new("/unavailable-supervised-test-control.sock"),
        started,
        false,
        &mut Vec::new(),
    );
    let cleanup = terminate_and_describe_child(&mut child, "");
    let failure = outcome.expect_err("expired cold-launch budget").to_string();
    assert!(failure.contains("launch_phase=restart"), "{failure}");
    assert!(failure.contains("child_state=running"), "{failure}");
    assert!(
        failure.contains("first_complete_operations_ms=None"),
        "{failure}"
    );
    assert!(failure.contains("last=no_response"), "{failure}");
    assert!(child.try_wait()?.is_some(), "{cleanup}");
    Ok(())
}

#[cfg(unix)]
#[test]
fn supervised_foreground_process_recovers_forced_exit_then_drains_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::ExitStatusExt;
    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root =
        std::path::Path::new("/tmp").join(format!("p-supervised-{}-{nonce}", std::process::id()));
    let roots = ChildRoots::new(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let ports = available_ports()?;
    let config_path = root.join("positron.toml");
    fs::write(
        &config_path,
        process_configuration(&root, &roots.data, &roots.secrets, ports).replace(
            &root.with_extension("sock").display().to_string(),
            &root.join("control.sock").display().to_string(),
        ),
    )?;
    let paths = BootstrapPaths::new(&roots.data, &roots.secrets, MountQualification::LocalHost)?;
    for forced in [true, false] {
        let started = Instant::now();
        let mut command = Command::new(env!("CARGO_BIN_EXE_positron"));
        command.arg("serve");
        if forced {
            command.arg("--init-if-empty");
        }
        let mut child = command
            .arg("--config")
            .arg(&config_path)
            .env("POSITRON__RUNTIME__SHUTDOWN_GRACE_SECONDS", "2")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Err(failure) = wait_for_supervised_readiness(
            &mut child,
            ports[0],
            &root.join("control.sock"),
            started,
            forced,
            &mut std::io::stderr().lock(),
        ) {
            if child.try_wait()?.is_none() {
                child.kill()?;
            }
            let status = wait_for_child(&mut child)?;
            let stderr = bounded_child_stderr(&mut child, "Bearer unavailable");
            return Err(format!(
                "supervised readiness forced={forced} status={status}: {failure}; stderr={stderr}"
            )
            .into());
        }
        assert!(child.try_wait()?.is_none());
        assert!(
            InstanceBootstrap::reopen(&paths).is_err(),
            "live supervised child owns storage"
        );
        if forced {
            child.kill()?;
        } else {
            assert!(
                Command::new("/bin/kill")
                    .args(["-TERM", &child.id().to_string()])
                    .status()?
                    .success()
            );
        }
        let status = wait_for_child(&mut child)?;
        if forced {
            assert_eq!(status.signal(), Some(9));
        } else {
            assert_eq!(status.code(), Some(0));
        }
        let reopened = InstanceBootstrap::reopen(&paths)?;
        assert_eq!(
            reopened.graceful_shutdown_record()?.is_some(),
            !forced,
            "the supervisor must distinguish forced recovery from completed Drain"
        );
        drop(reopened);
    }
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn sighup_reloads_a_valid_candidate_and_keeps_serving_after_a_rejected_candidate()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-reload-{}-{nonce}", std::process::id()));
    let data = root.join("data");
    let secrets = root.join("secrets");
    fs::create_dir_all(&data)?;
    fs::create_dir_all(&secrets)?;
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))?;
    let [
        operations_port,
        api_port,
        otlp_grpc_port,
        otlp_http_port,
        loki_push_port,
    ] = available_ports()?;
    let config_path = root.join("positron.toml");
    let base_configuration = process_configuration(
        &root,
        &data,
        &secrets,
        [
            operations_port,
            api_port,
            otlp_grpc_port,
            otlp_http_port,
            loki_push_port,
        ],
    );
    fs::write(&config_path, &base_configuration)?;
    let bootstrap_paths = BootstrapPaths::new(&data, &secrets, MountQualification::LocalHost)?;
    drop(InstanceBootstrap::initialize(
        &bootstrap_paths,
        InitializationPlan::non_interactive(),
    )?);
    let authorization = format!(
        "Bearer {}",
        InstanceBootstrap::claim(&bootstrap_paths)?.secret()
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["serve", "--config"])
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Err(error) = wait_for_ready(operations_port) {
        return Err(format!(
            "initial reload fixture readiness failed: {error}; {}",
            terminate_and_describe_child(&mut child, &authorization)
        )
        .into());
    }

    fs::write(
        &config_path,
        format!("{base_configuration}\n[diagnostics]\nlog_level = \"debug\"\n"),
    )?;
    let debug_candidate = resolve_probe_configuration(&config_path).map_err(|error| {
        format!(
            "debug candidate resolution failed: {error}; {}",
            terminate_and_describe_child(&mut child, &authorization)
        )
    })?;
    let debug_digest = probe_configuration_digest(&debug_candidate);
    assert!(
        Command::new("/bin/kill")
            .args(["-HUP", &child.id().to_string()])
            .status()?
            .success()
    );
    let debug_publication = wait_for_published_configuration(
        operations_port,
        &authorization,
        &debug_digest,
        &debug_digest,
        false,
    );
    if let Err(error) = debug_publication.and_then(|_| wait_for_ready(operations_port)) {
        let status = configuration_status(operations_port, &authorization)
            .map(|response| bounded_redacted_observation(&response, &authorization))
            .unwrap_or_else(|status_error| format!("status_request={status_error}"));
        return Err(format!(
            "valid reload did not return to readiness: {error}; status={status}; {}",
            terminate_and_describe_child(&mut child, &authorization)
        )
        .into());
    }

    assert!(child.try_wait()?.is_none());

    let restart_required_configuration = base_configuration.replacen(
        "shutdown_grace_seconds = 2",
        "shutdown_grace_seconds = 60",
        1,
    );
    fs::write(&config_path, restart_required_configuration)?;
    let restart_candidate = resolve_probe_configuration(&config_path).map_err(|error| {
        format!(
            "restart candidate resolution failed: {error}; {}",
            terminate_and_describe_child(&mut child, &authorization)
        )
    })?;
    let pending_effective_digest =
        probe_configuration_digest(&debug_candidate.with_live_changes_from(&restart_candidate));
    let pending_desired_digest = probe_configuration_digest(&restart_candidate);
    assert!(
        Command::new("/bin/kill")
            .args(["-HUP", &child.id().to_string()])
            .status()?
            .success()
    );
    let pending_status = wait_for_published_configuration(
        operations_port,
        &authorization,
        &pending_effective_digest,
        &pending_desired_digest,
        true,
    )
    .map_err(|error| {
        format!(
            "restart candidate publication failed: {error}; {}",
            terminate_and_describe_child(&mut child, &authorization)
        )
    })?;
    let pending = ConfigurationStatus::from_response(&pending_status)?;
    assert_eq!(pending.phase, "serving");
    assert!(pending.pending_restart);
    assert_eq!(pending.drift_disposition, "reconcile");
    assert_ne!(pending.effective_digest, pending.desired_digest);

    fs::write(&config_path, &base_configuration)?;
    let mut send_reload = || -> Result<(), Box<dyn std::error::Error>> {
        let status = Command::new("/bin/kill")
            .args(["-HUP", &child.id().to_string()])
            .status()?;
        status
            .success()
            .then_some(())
            .ok_or_else(|| format!("reload signal failed with {status}").into())
    };
    let (restored_status, _) = match restore_configuration_with_at_most_one_retry(
        &pending,
        &mut send_reload,
        || configuration_status(operations_port, &authorization),
        &authorization,
        CONFIGURATION_RESTORE_PROBE_TIMEOUT,
    ) {
        Ok(status) => status,
        Err(error) => {
            return Err(format!(
                "configuration did not restore after reload: {error}; {}",
                terminate_and_describe_child(&mut child, &authorization)
            )
            .into());
        },
    };
    let restored = ConfigurationStatus::from_response(&restored_status)?;
    assert_eq!(restored.observed_generation, pending.observed_generation);
    assert!(restored.is_restored());

    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &child.id().to_string()])
            .status()?
            .success()
    );
    assert_eq!(child.wait_with_output()?.status.code(), Some(0));

    // A reload signal reads its source when the owner consumes it. Keep the
    // rejected-source scenario in a fresh child so the one permitted restore
    // retry cannot still be pending when this fixture replaces the document.
    fs::write(&config_path, &base_configuration)?;
    let mut rejected_child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["serve", "--config"])
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    wait_for_ready(operations_port)?;
    fs::write(
        &config_path,
        "schema_version = 1\n[diagnostics]\nlog_level = \"invalid\"\n",
    )?;
    assert!(
        Command::new("/bin/kill")
            .args(["-HUP", &rejected_child.id().to_string()])
            .status()?
            .success()
    );
    let stderr = rejected_child.stderr.take().ok_or("child stderr")?;
    let flags = rustix::fs::fcntl_getfl(&stderr)?;
    rustix::fs::fcntl_setfl(&stderr, flags | rustix::fs::OFlags::NONBLOCK)?;
    let mut stderr = BufReader::new(stderr);
    let diagnostic_deadline = Instant::now() + Duration::from_secs(5);
    let mut records = Vec::new();
    for _ in 0..32 {
        let mut line = String::new();
        loop {
            match stderr.read_line(&mut line) {
                Ok(0) => return Err("reload diagnostic stderr closed".into()),
                Ok(_) => break,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= diagnostic_deadline {
                        if rejected_child.try_wait()?.is_none() {
                            rejected_child.kill()?;
                        }
                        wait_for_child(&mut rejected_child)?;
                        return Err("reload diagnostic stderr deadline exhausted".into());
                    }
                    std::thread::sleep(Duration::from_millis(1));
                },
                Err(error) => return Err(error.into()),
            }
        }
        let record: serde_json::Value = serde_json::from_str(&line)?;
        assert_eq!(record["component"], "runtime");
        let rejected = record["event"] == "configuration_reload_rejected";
        records.push(record);
        if rejected {
            break;
        }
    }
    let warnings: Vec<_> = records
        .iter()
        .filter(|record| record["event"] == "transport_security_warning")
        .collect();
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0]["warning"], "operations transport is plaintext");
    let rejected: Vec<_> = records
        .iter()
        .filter(|record| record["event"] == "configuration_reload_rejected")
        .collect();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0]["category"], "source_rejected");
    assert_eq!(rejected[0]["severity"], "error");
    assert!(rejected_child.try_wait()?.is_none());
    if let Err(error) = wait_for_ready(operations_port) {
        let status = configuration_status(operations_port, &authorization)
            .map(|response| bounded_redacted_observation(&response, &authorization))
            .unwrap_or_else(|status_error| format!("status_request={status_error}"));
        return Err(format!(
            "rejected reload did not preserve readiness: {error}; status={status}; {}",
            terminate_and_describe_child(&mut rejected_child, &authorization)
        )
        .into());
    }
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &rejected_child.id().to_string()])
            .status()?
            .success()
    );
    assert_eq!(wait_for_child(&mut rejected_child)?.code(), Some(0));
    let mut buffered_tail = Vec::new();
    buffered_tail.extend_from_slice(stderr.buffer());
    rejected_child.stderr = Some(stderr.into_inner());
    let tail = String::from_utf8(buffered_tail)?
        + &bounded_child_stderr(&mut rejected_child, &authorization);
    assert!(tail.is_empty(), "unexpected child stderr: {tail}");
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
fn status_value<'response>(
    response: &'response str,
    field: &str,
) -> Result<&'response str, Box<dyn std::error::Error>> {
    let prefix = format!("\"{field}\":");
    let value = response
        .split_once(&prefix)
        .map(|(_, value)| value)
        .ok_or_else(|| format!("status field {field} missing"))?;
    value
        .split([',', '}'])
        .next()
        .map(|value| value.trim_matches('"'))
        .ok_or_else(|| format!("status field {field} missing value").into())
}

#[cfg(unix)]
const CONFIGURATION_RESTORE_PROBE_TIMEOUT: Duration = Duration::from_millis(2_500);

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ConfigurationStatus {
    phase: String,
    observed_generation: String,
    effective_digest: String,
    desired_digest: String,
    drift_disposition: String,
    pending_restart: bool,
}

#[cfg(unix)]
impl ConfigurationStatus {
    fn from_response(response: &str) -> Result<Self, Box<dyn std::error::Error>> {
        if !response.starts_with("HTTP/1.1 200 ") {
            return Err("configuration status did not return HTTP 200".into());
        }
        let pending_restart = match status_value(response, "pending_restart")? {
            "true" => true,
            "false" => false,
            value => {
                return Err(format!("configuration pending_restart was invalid: {value}").into());
            },
        };
        Ok(Self {
            phase: status_value(response, "phase")?.to_owned(),
            observed_generation: status_value(response, "observed_generation")?.to_owned(),
            effective_digest: status_value(response, "effective_digest")?.to_owned(),
            desired_digest: status_value(response, "desired_digest")?.to_owned(),
            drift_disposition: status_value(response, "drift_disposition")?.to_owned(),
            pending_restart,
        })
    }

    fn is_restored(&self) -> bool {
        self.phase == "serving"
            && !self.pending_restart
            && self.drift_disposition == "none"
            && self.effective_digest == self.desired_digest
    }

    fn is_unchanged_pending_reconciliation_of(&self, pending: &Self) -> bool {
        self.phase == "serving"
            && self.pending_restart
            && self.drift_disposition == "reconcile"
            && self.observed_generation == pending.observed_generation
            && self.effective_digest == pending.effective_digest
            && self.desired_digest == pending.desired_digest
    }
}

#[cfg(unix)]
fn restore_configuration_with_at_most_one_retry(
    pending: &ConfigurationStatus,
    send_reload: &mut impl FnMut() -> Result<(), Box<dyn std::error::Error>>,
    mut observe: impl FnMut() -> Result<String, Box<dyn std::error::Error>>,
    authorization: &str,
    probe_timeout: Duration,
) -> Result<(String, bool), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + probe_timeout;
    send_reload()?;
    let mut second_reload_sent = false;

    loop {
        let last_observation = match observe() {
            Ok(response) => match ConfigurationStatus::from_response(&response) {
                Ok(status) if status.is_restored() => return Ok((response, second_reload_sent)),
                Ok(status)
                    if !second_reload_sent
                        && status.is_unchanged_pending_reconciliation_of(pending) =>
                {
                    second_reload_sent = true;
                    send_reload()?;
                    "unchanged_pending_reconciliation".to_owned()
                },
                Ok(status) => {
                    format!(
                        "phase={} pending_restart={} drift_disposition={} effective_digest={} desired_digest={}",
                        status.phase,
                        status.pending_restart,
                        status.drift_disposition,
                        status.effective_digest,
                        status.desired_digest,
                    )
                },
                Err(error) => {
                    format!(
                        "parse={error} response={:?}",
                        bounded_redacted_observation(&response, authorization)
                    )
                },
            },
            Err(error) => format!("request={error}"),
        };
        if Instant::now() >= deadline {
            return Err(format!(
                "configuration did not restore within the original bounded reload probe: {}",
                last_observation
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(unix)]
#[test]
fn configuration_restore_probe_accepts_immediate_serving_convergence()
-> Result<(), Box<dyn std::error::Error>> {
    let pending = ConfigurationStatus::from_response(&configuration_status_response(
        "serving",
        "12",
        "old",
        "new",
        "reconcile",
        true,
    )?)?;
    let restored = configuration_status_response("serving", "12", "base", "base", "none", false)?;
    let mut signals = 0;
    let (response, retried) = restore_configuration_with_at_most_one_retry(
        &pending,
        &mut || {
            signals += 1;
            Ok(())
        },
        || Ok(restored.clone()),
        "Bearer test-token",
        Duration::ZERO,
    )?;
    assert_eq!(signals, 1);
    assert!(!retried);
    assert_eq!(
        ConfigurationStatus::from_response(&response)?.observed_generation,
        "12"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn configuration_restore_probe_retries_once_for_unchanged_pending_reconciliation()
-> Result<(), Box<dyn std::error::Error>> {
    let pending_response =
        configuration_status_response("serving", "12", "old", "new", "reconcile", true)?;
    let pending = ConfigurationStatus::from_response(&pending_response)?;
    let restored = configuration_status_response("serving", "12", "base", "base", "none", false)?;
    let mut observations = [pending_response, restored].into_iter();
    let mut signals = 0;
    let (response, retried) = restore_configuration_with_at_most_one_retry(
        &pending,
        &mut || {
            signals += 1;
            Ok(())
        },
        || {
            observations
                .next()
                .ok_or_else(|| "configuration status observations exhausted".into())
        },
        "Bearer test-token",
        Duration::from_secs(1),
    )?;
    assert_eq!(signals, 2);
    assert!(retried);
    assert!(ConfigurationStatus::from_response(&response)?.is_restored());
    Ok(())
}

#[cfg(unix)]
#[test]
fn configuration_restore_probe_never_retries_a_changed_pending_status()
-> Result<(), Box<dyn std::error::Error>> {
    let pending = ConfigurationStatus::from_response(&configuration_status_response(
        "serving",
        "12",
        "old",
        "new",
        "reconcile",
        true,
    )?)?;
    let changed =
        configuration_status_response("serving", "12", "old", "other", "reconcile", true)?;
    let mut signals = 0;
    let error = restore_configuration_with_at_most_one_retry(
        &pending,
        &mut || {
            signals += 1;
            Ok(())
        },
        || Ok(changed.clone()),
        "Bearer test-token",
        Duration::ZERO,
    )
    .expect_err("a changed pending status must not trigger a second reload");
    assert_eq!(signals, 1);
    assert!(error.to_string().contains("original bounded reload probe"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn configuration_restore_probe_never_retries_a_generation_changed_pending_status()
-> Result<(), Box<dyn std::error::Error>> {
    let pending = ConfigurationStatus::from_response(&configuration_status_response(
        "serving",
        "12",
        "old",
        "new",
        "reconcile",
        true,
    )?)?;
    let changed = configuration_status_response("serving", "13", "old", "new", "reconcile", true)?;
    let mut signals = 0;
    let error = restore_configuration_with_at_most_one_retry(
        &pending,
        &mut || {
            signals += 1;
            Ok(())
        },
        || Ok(changed.clone()),
        "Bearer test-token",
        Duration::ZERO,
    )
    .expect_err("a changed generation must not trigger a second reload");
    assert_eq!(signals, 1);
    assert!(error.to_string().contains("original bounded reload probe"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn configuration_restore_probe_never_sends_a_third_reload_for_unresolved_pending_status()
-> Result<(), Box<dyn std::error::Error>> {
    let pending_response =
        configuration_status_response("serving", "12", "old", "new", "reconcile", true)?;
    let pending = ConfigurationStatus::from_response(&pending_response)?;
    let mut signals = 0;
    let error = restore_configuration_with_at_most_one_retry(
        &pending,
        &mut || {
            signals += 1;
            Ok(())
        },
        || Ok(pending_response.clone()),
        "Bearer test-token",
        Duration::ZERO,
    )
    .expect_err("an unresolved pending status must fail after the single permitted retry");
    assert_eq!(signals, 2);
    assert!(error.to_string().contains("original bounded reload probe"));
    Ok(())
}

#[cfg(unix)]
fn configuration_status_response(
    phase: &str,
    generation: &str,
    effective_digest: &str,
    desired_digest: &str,
    disposition: &str,
    pending_restart: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(format!(
        "HTTP/1.1 200 OK\r\n\r\n{{\"phase\":\"{phase}\",\"observed_generation\":{generation},\"effective_digest\":\"{effective_digest}\",\"desired_digest\":\"{desired_digest}\",\"drift_disposition\":\"{disposition}\",\"pending_restart\":{pending_restart}}}"
    ))
}

#[cfg(unix)]
fn bounded_child_stderr(child: &mut std::process::Child, authorization: &str) -> String {
    const MAX_CHILD_STDERR_BYTES: u64 = 4 * 1024;
    let Some(mut stderr) = child.stderr.take() else {
        return "stderr_unavailable".to_owned();
    };
    let flags = match rustix::fs::fcntl_getfl(&stderr) {
        Ok(flags) => flags,
        Err(error) => return format!("stderr_read_error={error}"),
    };
    if let Err(error) = rustix::fs::fcntl_setfl(&stderr, flags | rustix::fs::OFlags::NONBLOCK) {
        return format!("stderr_read_error={error}");
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut bytes = Vec::with_capacity((MAX_CHILD_STDERR_BYTES + 1) as usize);
    let suffix = loop {
        match stderr
            .by_ref()
            .take(MAX_CHILD_STDERR_BYTES + 1 - bytes.len() as u64)
            .read_to_end(&mut bytes)
        {
            Ok(_) => break "",
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    break "…<stderr_deadline_exhausted>";
                }
                std::thread::sleep(Duration::from_millis(1));
            },
            Err(error) => return format!("stderr_read_error={error}"),
        }
        if bytes.len() > MAX_CHILD_STDERR_BYTES as usize {
            break "…<truncated>";
        }
    };
    let truncated = bytes.len() > MAX_CHILD_STDERR_BYTES as usize;
    bytes.truncate(MAX_CHILD_STDERR_BYTES as usize);
    let observation = bounded_redacted_observation(&String::from_utf8_lossy(&bytes), authorization);
    format!(
        "{observation}{}",
        if truncated { "…<truncated>" } else { suffix }
    )
}

#[cfg(unix)]
fn bounded_crash_record_observation(
    data: &std::path::Path,
    secrets: &std::path::Path,
    authorization: &str,
) -> String {
    const MAX_CRASH_RECORD_FILES: usize = 4;
    const MAX_CRASH_RECORD_BYTES: usize = 1_536;

    let Ok(paths) = BootstrapPaths::new(data, secrets, MountQualification::LocalHost) else {
        return "crash_records=unavailable".to_owned();
    };
    let Ok(instance) = InstanceBootstrap::reopen(&paths) else {
        return "crash_records=unavailable".to_owned();
    };
    let Ok(records) = instance.crash_records() else {
        return "crash_records=unavailable".to_owned();
    };
    let Ok(readout) = records.read_recent(
        Duration::from_secs(60),
        MAX_CRASH_RECORD_FILES,
        MAX_CRASH_RECORD_BYTES,
        SystemTime::now(),
    ) else {
        return "crash_records=unavailable".to_owned();
    };
    format!(
        "crash_records={}",
        bounded_redacted_observation(&readout.render(), authorization)
    )
}

#[cfg(unix)]
fn terminate_and_describe_child(child: &mut std::process::Child, authorization: &str) -> String {
    let (termination, exit) = match child.try_wait() {
        Ok(Some(status)) => ("term=not_needed".to_owned(), format!("exit={status}")),
        Ok(None) | Err(_) => {
            let termination = match Command::new("/bin/kill")
                .args(["-TERM", &child.id().to_string()])
                .status()
            {
                Ok(status) if status.success() => "term=sent".to_owned(),
                Ok(status) => format!("term=exit_{status}"),
                Err(error) => format!("term_error={error}"),
            };
            let exit = match wait_for_child(child) {
                Ok(status) => format!("exit={status}"),
                Err(error) => format!("exit_error={error}"),
            };
            (termination, exit)
        },
    };
    let stderr = bounded_child_stderr(child, authorization);
    format!("child_cleanup {termination} {exit} stderr={stderr:?}")
}

#[cfg(unix)]
fn wait_for_supervised_readiness(
    child: &mut std::process::Child,
    port: u16,
    control: &std::path::Path,
    started: Instant,
    initializes: bool,
    diagnostics: &mut impl std::io::Write,
) -> Result<(), Box<dyn std::error::Error>> {
    // Both supervisor iterations launch a new OS process. Match the existing
    // cold-listener fixtures; retain the old observation window as a checkpoint.
    let deadline = started + Duration::from_secs(10);
    let checkpoint = started + STARTUP_PROBE_BUDGET;
    let launch_phase = if initializes { "initial" } else { "restart" };
    let mut first_control_ms = None;
    let mut first_operations_ms = None;
    let mut checkpoint_recorded = false;
    let mut last = "no_response".to_owned();
    loop {
        if first_control_ms.is_none() && control.exists() {
            first_control_ms = Some(started.elapsed().as_millis());
        }
        let child_state = if child.try_wait()?.is_some() {
            "exited"
        } else {
            "running"
        };
        let now = Instant::now();
        if now >= deadline || child_state == "exited" {
            return Err(format!("supervised cold-launch readiness unavailable launch_phase={launch_phase} elapsed_ms={} child_state={child_state} control_path_present={} first_observed_control_ms={first_control_ms:?} first_complete_operations_ms={first_operations_ms:?} last={last}", started.elapsed().as_millis(), control.exists()).into());
        }
        let ready = match probe_response(
            port,
            b"GET /health/ready HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
            deadline.min(now + Duration::from_millis(100)),
        ) {
            Ok(response) => {
                first_operations_ms.get_or_insert(started.elapsed().as_millis());
                let ready = response.starts_with("HTTP/1.1 200 ");
                let status = if ready {
                    "http_200"
                } else if response.starts_with("HTTP/1.1 503 ") {
                    "http_503"
                } else {
                    "unexpected_http_status"
                };
                last = format!("{status} {}", bounded_redacted_observation(&response, ""));
                if !ready && status != "http_503" {
                    return Err(format!("unexpected supervised readiness response: {last}").into());
                }
                ready
            },
            Err(error) => {
                last = bounded_redacted_observation(&format!("probe_unavailable {error}"), "");
                false
            },
        };
        if !checkpoint_recorded && Instant::now() >= checkpoint {
            writeln!(
                diagnostics,
                "supervised_cold_launch original_checkpoint launch_phase={launch_phase} elapsed_ms={} child_state={child_state} control_path_present={} first_observed_control_ms={first_control_ms:?} first_complete_operations_ms={first_operations_ms:?} last={last}",
                started.elapsed().as_millis(),
                control.exists()
            )?;
            checkpoint_recorded = true;
        }
        if ready {
            writeln!(
                diagnostics,
                "supervised_cold_launch ready launch_phase={launch_phase} elapsed_ms={} original_checkpoint={} first_observed_control_ms={first_control_ms:?} first_complete_operations_ms={first_operations_ms:?}",
                started.elapsed().as_millis(),
                if checkpoint_recorded {
                    "recorded"
                } else {
                    "not_reached"
                }
            )?;
            return Ok(());
        }
        std::thread::sleep(
            Duration::from_millis(25).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

#[cfg(unix)]
fn wait_for_recovery_readiness(
    child: &mut std::process::Child,
    port: u16,
    expected_status: &str,
    deadline: Instant,
    stage: &str,
    authorization: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let started = Instant::now();
    match wait_for_readiness_until(port, expected_status, deadline) {
        Ok(()) => Ok(()),
        Err(failure) => {
            let elapsed_ms = started.elapsed().as_millis();
            let child_state = match child.try_wait() {
                Ok(Some(_)) => "exited",
                Ok(None) => "running",
                Err(_) => "unavailable",
            };
            let cleanup = terminate_and_describe_child(child, authorization);
            Err(format!(
                "{failure}; stage={stage} elapsed_ms={elapsed_ms} child_state={child_state}; {cleanup}"
            )
            .into())
        },
    }
}

#[cfg(unix)]
#[test]
fn already_reaped_child_cleanup_retains_status_without_signal()
-> Result<(), Box<dyn std::error::Error>> {
    let authorization = "Bearer already-reaped-canary";
    let mut child = Command::new("/bin/sh")
        .args(["-c", "printf 'Bearer already-reaped-canary\\n' >&2; exit 7"])
        .stderr(Stdio::piped())
        .spawn()?;
    let original_status = child.wait()?;
    assert_eq!(original_status.code(), Some(7));
    let observation = terminate_and_describe_child(&mut child, authorization);
    assert!(observation.contains("term=not_needed"), "{observation}");
    assert!(
        observation.contains(&format!("exit={original_status}")),
        "{observation}"
    );
    assert!(observation.contains("<redacted>"), "{observation}");
    assert!(!observation.contains("already-reaped-canary"));
    assert!(observation.len() < 4096);
    assert_eq!(child.try_wait()?.and_then(|status| status.code()), Some(7));
    Ok(())
}

#[cfg(unix)]
#[test]
fn expired_recovery_readiness_reaps_child_and_retains_redacted_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let authorization = "Bearer readiness-cleanup-canary";
    let mut child = Command::new("/bin/sh")
        .args([
            "-c",
            "printf 'Bearer readiness-cleanup-canary\\n' >&2; printf 'ready\\n'; read -r line",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let observation = (|| -> Result<_, Box<dyn std::error::Error>> {
        let stdout = child.stdout.take().ok_or("child marker pipe unavailable")?;
        let mut marker = String::new();
        BufReader::new(stdout).read_line(&mut marker)?;
        if marker != "ready\n" {
            return Err("child marker unavailable".into());
        }
        let failure = match wait_for_recovery_readiness(
            &mut child,
            0,
            "HTTP/1.1 200 ",
            Instant::now(),
            "post_ownership_release",
            authorization,
        ) {
            Ok(()) => return Err("an expired readiness deadline unexpectedly succeeded".into()),
            Err(failure) => failure.to_string(),
        };
        let reaped_before_fallback = child.try_wait()?.is_some();
        Ok((failure, reaped_before_fallback))
    })();
    // The baseline must not leak its child even when the regression assertion fails.
    let fallback_cleanup = terminate_and_describe_child(&mut child, authorization);
    let (failure, reaped_before_fallback) = observation?;
    assert!(failure.starts_with("readiness deadline expired before expected response:"));
    assert!(
        child.try_wait()?.is_some(),
        "fallback cleanup: {fallback_cleanup}"
    );
    assert!(!fallback_cleanup.contains("readiness-cleanup-canary"));
    assert!(
        reaped_before_fallback,
        "the readiness failure must reap its owned child before returning; {failure}"
    );
    assert!(failure.contains("stage=post_ownership_release"));
    assert!(failure.contains("child_cleanup"));
    assert!(!failure.contains("readiness-cleanup-canary"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn cold_recovery_listener_observation_keeps_ownership_held()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "positron-cold-listener-diagnostic-{}-{nonce}",
        std::process::id()
    ));
    let data = root.join("data");
    let secrets = root.join("secrets");
    fs::create_dir_all(&data)?;
    fs::create_dir_all(&secrets)?;
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))?;
    let [
        operations_port,
        api_port,
        otlp_grpc_port,
        otlp_http_port,
        loki_push_port,
    ] = available_ports()?;
    let config_path = root.join("positron.toml");
    fs::write(
        &config_path,
        process_configuration(
            &root,
            &data,
            &secrets,
            [
                operations_port,
                api_port,
                otlp_grpc_port,
                otlp_http_port,
                loki_push_port,
            ],
        ),
    )?;
    let ownership = positron_kernel::PrimaryDataVolume::acquire(
        &data,
        positron_kernel::MountQualification::LocalHost,
    )?;
    let started = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["serve", "--init-if-empty", "--config"])
        .arg(&config_path)
        .stderr(Stdio::piped())
        .spawn()?;

    let deadline = started + Duration::from_secs(10);
    let checkpoint = started + STARTUP_PROBE_BUDGET;
    let observation = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut first_control_ms = None;
        let mut first_response_ms = None;
        let mut checkpoint_recorded = false;
        let mut last = "no_response";
        loop {
            let now = Instant::now();
            if first_control_ms.is_none() && process_control_path(&root).exists() {
                first_control_ms = Some(started.elapsed().as_millis());
            }
            if !checkpoint_recorded && now >= checkpoint {
                let state = match child.try_wait()? {
                    Some(_) => "exited",
                    None => "running",
                };
                eprintln!(
                    "cold_listener original_checkpoint elapsed_ms={} observation={last} child_state={state} first_observed_control_ms={first_control_ms:?} first_complete_response_ms={first_response_ms:?}",
                    started.elapsed().as_millis()
                );
                checkpoint_recorded = true;
            }
            if now >= deadline {
                return Err(format!("cold listener diagnostic deadline: last={last} first_observed_control_ms={first_control_ms:?} first_complete_response_ms={first_response_ms:?}").into());
            }
            match probe_response(
                operations_port,
                b"GET /health/ready HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
                deadline.min(now + Duration::from_millis(100)),
            ) {
                Ok(response) => {
                    let elapsed_ms = started.elapsed().as_millis();
                    first_response_ms.get_or_insert(elapsed_ms);
                    last = if response.starts_with("HTTP/1.1 503 ") {
                        "http_503"
                    } else {
                        "unexpected_http_status"
                    };
                    eprintln!(
                        "cold_listener first_complete_response elapsed_ms={elapsed_ms} late={} observation={last} first_observed_control_ms={first_control_ms:?}",
                        Instant::now() >= checkpoint
                    );
                    if last != "http_503" {
                        return Err("ownership-held listener must report HTTP503".into());
                    }
                    if !checkpoint_recorded {
                        eprintln!(
                            "cold_listener original_checkpoint not_reached response_before_deadline=true"
                        );
                    }
                    return Ok(());
                },
                Err(_) => last = "probe_unavailable",
            }
            std::thread::sleep(
                Duration::from_millis(25).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    })();
    let cleanup = terminate_and_describe_child(&mut child, "");
    drop(ownership);
    eprintln!("cold_listener cleanup={cleanup}");
    let reaped = child.try_wait()?.is_some();
    observation?;
    if !reaped {
        return Err("cold listener diagnostic child not reaped".into());
    }
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn native_recovery_survives_the_old_deadline_and_sighup_then_restores_readiness()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "positron-recovery-sighup-{}-{nonce}",
        std::process::id()
    ));
    let data = root.join("data");
    let secrets = root.join("secrets");
    fs::create_dir_all(&data)?;
    fs::create_dir_all(&secrets)?;
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))?;
    let [
        operations_port,
        api_port,
        otlp_grpc_port,
        otlp_http_port,
        loki_push_port,
    ] = available_ports()?;
    let config_path = root.join("positron.toml");
    fs::write(
        &config_path,
        process_configuration(
            &root,
            &data,
            &secrets,
            [
                operations_port,
                api_port,
                otlp_grpc_port,
                otlp_http_port,
                loki_push_port,
            ],
        ),
    )?;
    let ownership = positron_kernel::PrimaryDataVolume::acquire(
        &data,
        positron_kernel::MountQualification::LocalHost,
    )?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["serve", "--init-if-empty", "--config"])
        .arg(&config_path)
        .stderr(Stdio::piped())
        .spawn()?;

    // Cold process launch uses the same allowance as the fenced startup fixture.
    wait_for_recovery_readiness(
        &mut child,
        operations_port,
        "HTTP/1.1 503 ",
        Instant::now() + Duration::from_secs(10),
        "pre_sighup",
        "",
    )?;
    assert!(
        Command::new("/bin/kill")
            .args(["-HUP", &child.id().to_string()])
            .status()?
            .success()
    );
    std::thread::sleep(Duration::from_millis(3_200));
    assert!(
        child.try_wait()?.is_none(),
        "recoverable dependency outage must remain alive after the old deadline"
    );
    wait_for_recovery_readiness(
        &mut child,
        operations_port,
        "HTTP/1.1 503 ",
        Instant::now() + STARTUP_PROBE_BUDGET,
        "post_sighup",
        "",
    )?;
    assert!(
        std::net::TcpStream::connect(("127.0.0.1", api_port)).is_err(),
        "data listener must remain unbound throughout the dependency outage"
    );

    drop(ownership);
    wait_for_recovery_readiness(
        &mut child,
        operations_port,
        "HTTP/1.1 200 ",
        Instant::now() + STARTUP_PROBE_BUDGET,
        "post_ownership_release",
        "",
    )?;
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &child.id().to_string()])
            .status()?
            .success()
    );
    let status = wait_for_child(&mut child)?;
    if status.code() != Some(0) {
        let authorization = BootstrapPaths::new(&data, &secrets, MountQualification::LocalHost)
            .and_then(|paths| InstanceBootstrap::claim(&paths))
            .map(|credential| format!("Bearer {}", credential.secret()))
            .map_err(|failure| format!("reopen failure context unavailable: {failure:?}"));
        let context = match authorization {
            Ok(authorization) => format!(
                "stderr={:?}; {}",
                bounded_child_stderr(&mut child, &authorization),
                bounded_crash_record_observation(&data, &secrets, &authorization),
            ),
            Err(failure) => failure,
        };
        return Err(format!("recovery SIGHUP shutdown exited {status}; {context}").into());
    }
    assert_eq!(status.code(), Some(0));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn fenced_native_process_stays_alive_until_signal_and_retains_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-fenced-{}-{nonce}", std::process::id()));
    let roots = ChildRoots::new(&root)?;
    fs::write(roots.data.join("foreign"), b"ambiguous")?;
    let [
        operations_port,
        api_port,
        otlp_grpc_port,
        otlp_http_port,
        loki_push_port,
    ] = available_ports()?;
    let configuration = process_configuration(
        &root,
        &roots.data,
        &roots.secrets,
        [
            operations_port,
            api_port,
            otlp_grpc_port,
            otlp_http_port,
            loki_push_port,
        ],
    );
    let config_path = root.join("positron.toml");
    fs::write(&config_path, configuration)?;
    // Cold native launch precedes every listener. Use the same bounded startup
    // allowance as binary_ingestion's native readiness fixture; the shorter
    // status-probe allowance is for an already running process.
    let startup_deadline = Instant::now() + Duration::from_secs(10);
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["serve", "--init-if-empty", "--config"])
        .arg(&config_path)
        .spawn()?;
    if let Err(failure) = wait_for_fenced_startup(
        operations_port,
        &process_control_path(&root),
        startup_deadline,
    ) {
        let alive = child.try_wait()?.is_none();
        if alive {
            let delivered = Command::new("/bin/kill")
                .args(["-TERM", &child.id().to_string()])
                .status()?;
            if !delivered.success() {
                return Err("failed to stop owned Fenced fixture child".into());
            }
        }
        let shutdown = wait_for_child(&mut child)?;
        return Err(format!("Fenced startup probe failed: shutdown={shutdown}; {failure}").into());
    }
    assert!(child.try_wait()?.is_none());
    let failure = positron_kernel::PrimaryDataVolume::acquire(
        &roots.data,
        positron_kernel::MountQualification::LocalHost,
    )
    .expect_err("the Fenced process retains its volume owner until shutdown");
    assert_eq!(failure.code(), positron_kernel::VolumeFailureCode::Busy);
    assert_eq!(
        failure.operation(),
        positron_kernel::VolumeOperation::AcquireOwnershipLock
    );
    assert!(child.try_wait()?.is_none());
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &child.id().to_string()])
            .status()?
            .success()
    );
    assert_eq!(wait_for_child(&mut child)?.code(), Some(0));
    assert!(
        positron_kernel::PrimaryDataVolume::acquire(
            &roots.data,
            positron_kernel::MountQualification::LocalHost,
        )
        .is_ok()
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn second_os_signal_escalates_to_forced_exit() -> Result<(), Box<dyn std::error::Error>> {
    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-force-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&root)?;
    let ready = root.join("ready");
    let draining = root.join("draining");
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "lifecycle::blocked_shutdown_child_fixture",
            "--nocapture",
        ])
        .env("POSITRON_BLOCKED_CHILD", &root)
        .spawn()?;
    wait_for_file(&ready)?;
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &child.id().to_string()])
            .status()?
            .success()
    );
    wait_for_file(&draining)?;
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &child.id().to_string()])
            .status()?
            .success()
    );
    assert_eq!(wait_for_child(&mut child)?.code(), Some(4));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
#[ignore = "owned subprocess fixture"]
fn blocked_shutdown_child_fixture() -> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::MountQualification;
    use positron_runtime::{
        ApplicationRuntime, BootstrapPaths, HostInputs, InitializationMode, ServeConfiguration,
        ShutdownTrigger,
    };

    let Some(root) = std::env::var_os("POSITRON_BLOCKED_CHILD").map(std::path::PathBuf::from)
    else {
        return Ok(());
    };
    let roots = ChildRoots::new(&root)?;
    let host = BlockedHost;
    let paths = BootstrapPaths::new(&roots.data, &roots.secrets, MountQualification::LocalHost)?;
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::InitializeIfEmpty),
        HostInputs::new(&host, &host),
    )?;
    let mut signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::signal::SIGINT,
        signal_hook::consts::signal::SIGTERM,
    ])?;
    fs::write(root.join("ready"), b"ready")?;
    let Some(_) = signals.forever().next() else {
        return Err("signal stream ended".into());
    };
    let draining = process.begin_shutdown();
    fs::write(root.join("draining"), b"draining")?;
    let outcome = draining.finish_with_termination_probe(ShutdownTrigger::FirstSignal, || {
        signals.pending().next().is_some()
    });
    std::process::exit(if outcome == positron_runtime::ExitOutcome::Forced {
        4
    } else {
        3
    });
}

#[cfg(unix)]
fn resolve_probe_configuration(
    path: &std::path::Path,
) -> Result<positron_config::EffectiveConfiguration, Box<dyn std::error::Error>> {
    let inputs = positron_config::ConfigurationInputs::try_from_sources(
        Some(path),
        std::env::vars(),
        [] as [(&str, &str); 0],
    )
    .map_err(|_| "configuration probe inputs unavailable")?;
    positron_config::resolve(inputs).map_err(|_| "configuration probe candidate invalid".into())
}

#[cfg(unix)]
fn probe_configuration_digest(configuration: &positron_config::EffectiveConfiguration) -> String {
    use sha2::Digest;
    format!(
        "{:x}",
        sha2::Sha256::digest(configuration.redacted_effective().as_bytes())
    )
}

#[cfg(unix)]
fn wait_for_published_configuration(
    port: u16,
    authorization: &str,
    effective_digest: &str,
    desired_digest: &str,
    pending_restart: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    wait_for_configuration_status(
        port,
        authorization,
        &[
            "\"phase\":\"serving\"",
            &format!("\"pending_restart\":{pending_restart}"),
            &format!(
                "\"drift_disposition\":\"{}\"",
                if pending_restart { "reconcile" } else { "none" }
            ),
            &format!("\"effective_digest\":\"{effective_digest}\""),
            &format!("\"desired_digest\":\"{desired_digest}\""),
        ],
        Instant::now() + STARTUP_PROBE_BUDGET,
    )
}

#[cfg(unix)]
#[test]
fn configuration_publication_barrier_rejects_readiness_and_unrelated_pending_state()
-> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "macos")]
    let _guard = PROCESS_TEST.lock().map_err(|_| "process test lock")?;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    listener.set_nonblocking(true)?;
    let responses = [
        configuration_status_response("serving", "1", "base", "base", "none", false)?,
        configuration_status_response("serving", "1", "base", "base", "none", false)?,
        configuration_status_response("serving", "2", "unrelated", "candidate", "reconcile", true)?,
        configuration_status_response("serving", "3", "debug", "debug", "none", false)?,
        configuration_status_response("serving", "3", "debug", "debug", "none", false)?,
        configuration_status_response("serving", "4", "unrelated", "candidate", "reconcile", true)?,
        configuration_status_response("serving", "4", "active", "restart", "reconcile", true)?,
    ];
    let (stop, stopped) = std::sync::mpsc::channel();
    let peer = std::thread::spawn(move || -> std::io::Result<usize> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut delivered = 0;
        for response in responses {
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if stopped.try_recv().is_ok() {
                            return Ok(delivered);
                        }
                        if Instant::now() >= deadline {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "publication peer accept deadline",
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    },
                    Err(error) => return Err(error),
                }
            };
            stream.set_nonblocking(false)?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "publication peer deadline",
                ));
            }
            stream.set_read_timeout(Some(remaining))?;
            stream.set_write_timeout(Some(remaining))?;
            let mut reader = BufReader::new(&mut stream);
            let mut request_bytes = 0;
            loop {
                let mut line = Vec::new();
                let read = reader.by_ref().take(8193).read_until(b'\n', &mut line)?;
                request_bytes += read;
                if read == 0 || request_bytes > 8192 {
                    return Err(std::io::Error::other("publication peer request bound"));
                }
                if line == b"\r\n" {
                    break;
                }
            }
            drop(reader);
            stream.write_all(response.as_bytes())?;
            delivered += 1;
        }
        Ok(delivered)
    });
    // Readiness is already true before the requested configuration is active.
    let ready = wait_for_ready(port);
    let published = ready.and_then(|()| {
        wait_for_published_configuration(port, "Bearer test-token", "debug", "debug", false)
    });
    let pending = match published {
        Ok(_) => {
            wait_for_published_configuration(port, "Bearer test-token", "active", "restart", true)
        },
        Err(_) => Err("debug publication barrier failed".into()),
    };
    let _ = stop.send(());
    let delivered = peer.join().map_err(|_| "publication peer panicked")??;
    let published = ConfigurationStatus::from_response(&published?)?;
    let pending = ConfigurationStatus::from_response(&pending?)?;
    assert_eq!(published.effective_digest, "debug");
    assert_eq!(delivered, 7);
    assert_eq!(pending.effective_digest, "active");
    assert_eq!(pending.desired_digest, "restart");
    assert!(pending.pending_restart);
    assert_eq!(published.observed_generation, "3");
    assert_eq!(published.effective_digest, "debug");
    assert!(published.is_restored());
    Ok(())
}

#[cfg(unix)]
#[test]
fn child_stderr_observation_is_bounded_when_a_descendant_retains_the_writer()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let mut child = Command::new("/bin/sh")
        .args(["-c", "sleep 5 & exit 0"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    assert!(wait_for_child(&mut child)?.success());
    let started = Instant::now();
    let observation = bounded_child_stderr(&mut child, "Bearer fixture-secret");
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(observation.contains("stderr_deadline_exhausted"));
    Ok(())
}
