use super::offline::offline_verify_command;
use super::online::online_status_request;
use super::{DoctorFailure, Options};
use std::{
    io::{Read, Write},
    net::TcpListener,
    path::Path,
};

#[test]
fn doctor_requires_one_explicit_mode() {
    assert!(Options::parse(["--offline".to_owned()].into_iter()).is_ok());
    assert!(Options::parse(std::iter::empty()).is_err());
    assert!(Options::parse(["--online".to_owned()].into_iter()).is_err());
}

#[test]
fn offline_continuation_command_preserves_safe_configuration_arguments() {
    let command = offline_verify_command(
        Some("deadbeef"),
        Some(Path::new("/tmp/operator's config.toml")),
        &[("runtime.max_registered_tenants".to_owned(), "4".to_owned())],
    );

    assert_eq!(
        command,
        "positron verify --offline --config '/tmp/operator'\"'\"'s config.toml' --set 'runtime.max_registered_tenants=4' --continuation 'deadbeef'"
    );
}

#[test]
fn online_doctor_uses_authenticated_operations_status() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?;
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        let (mut stream, _) = listener.accept()?;
        let mut request = [0_u8; 4096];
        let read = stream.read(&mut request)?;
        let request = String::from_utf8_lossy(&request[..read]);
        assert!(request.starts_with("GET /status HTTP/1.1\r\n"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer system-administrator")
        );
        let body = "{\"phase\":\"serving\",\"integrity_degraded\":false,\"effective_digest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"desired_digest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"drift_disposition\":\"none\",\"pending_restart\":false,\"doctor\":{\"key_custody\":\"verified\",\"catalog_bootstrap\":\"verified\",\"catalog_generation\":1,\"backup_repository\":\"not_configured\",\"durable_operations\":0,\"active_durable_operations\":0,\"snapshot_leases\":0,\"listener_topology\":{\"control\":true,\"operations\":true,\"api\":true,\"otlp_grpc\":true,\"otlp_http\":true,\"loki_push\":true}},\"maintenance\":{\"queued\":0,\"outstanding_reservations\":0,\"clock_uncertain\":false,\"running_no_durable_progress_slo_breaches\":0,\"running_no_durable_progress_slo_unknown\":0,\"checkpointed_tasks\":0,\"paused_tasks\":0,\"conflicted_tasks\":0}}";
        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())
    });
    let options = Options::parse(
        [
            "--online",
            "--credential-stdin",
            "--endpoint",
            &endpoint.to_string(),
            "--allow-plaintext",
        ]
        .into_iter()
        .map(ToOwned::to_owned),
    )?;
    let (exit, report) = online_status_request(&options, "system-administrator")?;
    assert_eq!(exit, std::process::ExitCode::from(3));
    assert!(
        report.contains("status=degraded\nfinding_code=DOCTOR_BACKUP_REPOSITORY_NOT_CONFIGURED")
    );
    assert!(report.contains("evidence_scope=authenticated_operations_status"));
    assert!(report.contains("key_custody=verified"));
    assert!(report.contains("catalog_bootstrap=verified"));
    assert!(report.contains("listener_topology=active"));
    assert!(report.contains("effective_configuration_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    assert!(report.contains("desired_configuration_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    assert!(report.contains("configuration_drift_disposition=none"));
    assert!(report.contains("configuration_pending_restart=false"));
    assert!(!report.contains("system-administrator"));
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn online_doctor_reports_clock_uncertainty_and_stalled_work_as_degraded()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?;
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        let (mut stream, _) = listener.accept()?;
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request)?;
        let body = "{\"phase\":\"serving\",\"integrity_degraded\":false,\"effective_digest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"desired_digest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"drift_disposition\":\"none\",\"pending_restart\":false,\"doctor\":{\"key_custody\":\"verified\",\"catalog_bootstrap\":\"verified\",\"catalog_generation\":1,\"backup_repository\":\"configured\",\"durable_operations\":1,\"active_durable_operations\":1,\"snapshot_leases\":1,\"listener_topology\":{\"control\":true,\"operations\":true,\"api\":true,\"otlp_grpc\":true,\"otlp_http\":true,\"loki_push\":true}},\"maintenance\":{\"queued\":0,\"outstanding_reservations\":0,\"clock_uncertain\":true,\"running_no_durable_progress_slo_breaches\":1,\"running_no_durable_progress_slo_unknown\":0,\"checkpointed_tasks\":2,\"paused_tasks\":1,\"conflicted_tasks\":1}}";
        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())
    });
    let options = Options::parse(
        [
            "--online",
            "--credential-stdin",
            "--endpoint",
            &endpoint.to_string(),
            "--allow-plaintext",
        ]
        .into_iter()
        .map(ToOwned::to_owned),
    )?;
    let (exit, report) = online_status_request(&options, "system-administrator")?;
    assert_eq!(exit, std::process::ExitCode::from(3));
    assert!(report.contains("status=degraded"));
    assert!(report.contains("maintenance_clock_uncertain=true"));
    assert!(report.contains("maintenance_running_no_durable_progress_slo_breaches=1"));
    assert!(report.contains("maintenance_checkpointed_tasks=2"));
    assert!(report.contains("maintenance_paused_tasks=1"));
    assert!(report.contains("maintenance_conflicted_tasks=1"));
    assert!(report.contains("durable_operations=1"));
    assert!(report.contains("snapshot_leases=1"));
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn online_doctor_rejects_unauthorized_status_without_a_fallback()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?;
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        let (mut stream, _) = listener.accept()?;
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request)?;
        stream.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: 34\r\nConnection: close\r\n\r\n{\"code\":\"authentication_rejected\"}")
    });
    let options = Options::parse(
        [
            "--online",
            "--credential-stdin",
            "--endpoint",
            &endpoint.to_string(),
            "--allow-plaintext",
        ]
        .into_iter()
        .map(ToOwned::to_owned),
    )?;
    assert!(matches!(
        online_status_request(&options, "unauthorized"),
        Err(DoctorFailure::AuthenticationRejected)
    ));
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn online_doctor_reports_pending_configuration_restart_as_degraded()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?;
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        let (mut stream, _) = listener.accept()?;
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request)?;
        let body = "{\"phase\":\"serving\",\"integrity_degraded\":false,\"effective_digest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"desired_digest\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"drift_disposition\":\"reconcile\",\"pending_restart\":true,\"doctor\":{\"key_custody\":\"verified\",\"catalog_bootstrap\":\"verified\",\"catalog_generation\":1,\"backup_repository\":\"configured\",\"durable_operations\":0,\"active_durable_operations\":0,\"snapshot_leases\":0,\"listener_topology\":{\"control\":true,\"operations\":true,\"api\":true,\"otlp_grpc\":true,\"otlp_http\":true,\"loki_push\":true}},\"maintenance\":{\"queued\":0,\"outstanding_reservations\":0,\"clock_uncertain\":false,\"running_no_durable_progress_slo_breaches\":0,\"running_no_durable_progress_slo_unknown\":0,\"checkpointed_tasks\":0,\"paused_tasks\":0,\"conflicted_tasks\":0}}";
        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())
    });
    let options = Options::parse(
        [
            "--online",
            "--credential-stdin",
            "--endpoint",
            &endpoint.to_string(),
            "--allow-plaintext",
        ]
        .into_iter()
        .map(ToOwned::to_owned),
    )?;

    let (exit, report) = online_status_request(&options, "system-administrator")?;

    assert_eq!(exit, std::process::ExitCode::from(3));
    assert!(report.contains("status=degraded\nfinding_code=DOCTOR_CONFIGURATION_DEGRADED"));
    assert!(report.contains("effective_configuration_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    assert!(report.contains("desired_configuration_digest=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
    assert!(report.contains("configuration_drift_disposition=reconcile"));
    assert!(report.contains("configuration_pending_restart=true"));
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn online_doctor_treats_missing_configuration_status_as_unavailable()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?;
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        let (mut stream, _) = listener.accept()?;
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request)?;
        let body = "{\"phase\":\"serving\",\"integrity_degraded\":false,\"doctor\":{\"key_custody\":\"verified\",\"catalog_bootstrap\":\"verified\",\"catalog_generation\":1,\"backup_repository\":\"configured\",\"durable_operations\":0,\"active_durable_operations\":0,\"snapshot_leases\":0,\"listener_topology\":{\"control\":true,\"operations\":true,\"api\":true,\"otlp_grpc\":true,\"otlp_http\":true,\"loki_push\":true}},\"maintenance\":{\"queued\":0,\"outstanding_reservations\":0,\"clock_uncertain\":false,\"running_no_durable_progress_slo_breaches\":0,\"running_no_durable_progress_slo_unknown\":0,\"checkpointed_tasks\":0,\"paused_tasks\":0,\"conflicted_tasks\":0}}";
        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())
    });
    let options = Options::parse(
        [
            "--online",
            "--credential-stdin",
            "--endpoint",
            &endpoint.to_string(),
            "--allow-plaintext",
        ]
        .into_iter()
        .map(ToOwned::to_owned),
    )?;

    assert!(matches!(
        online_status_request(&options, "system-administrator"),
        Err(DoctorFailure::EndpointUnavailable)
    ));
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}
