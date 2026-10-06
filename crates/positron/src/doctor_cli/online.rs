use super::*;

pub(super) fn execute(options: &Options) -> Result<(ExitCode, String), DoctorFailure> {
    let input = std::io::stdin();
    if input.is_terminal() {
        return Err(DoctorFailure::Arguments);
    }
    let mut credential = Zeroizing::new(String::new());
    input
        .take(1025)
        .read_to_string(&mut credential)
        .map_err(|_| DoctorFailure::EndpointUnavailable)?;
    let bearer = credential.trim_end_matches(['\r', '\n']);
    if credential.len() > 1024
        || bearer.is_empty()
        || bearer.len() > 1024
        || !bearer
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(DoctorFailure::Arguments);
    }
    online_status_request(options, bearer)
}

pub(super) fn online_status_request(
    options: &Options,
    bearer: &str,
) -> Result<(ExitCode, String), DoctorFailure> {
    let report = operations_status(options, bearer)?;
    let report = report
        .as_object()
        .ok_or(DoctorFailure::EndpointUnavailable)?;
    let phase = required_string(report, "phase")?;
    if phase == "fenced" {
        return fenced_control_report(report);
    }
    let degraded = required_bool(report, "integrity_degraded")?;
    let effective_configuration_digest = required_string(report, "effective_digest")?;
    let desired_configuration_digest = required_string(report, "desired_digest")?;
    let configuration_drift_disposition = required_string(report, "drift_disposition")?;
    let configuration_pending_restart = required_bool(report, "pending_restart")?;
    let maintenance = required_object(report, "maintenance")?;
    let queued = required_u64(maintenance, "queued")?;
    let reservations = required_u64(maintenance, "outstanding_reservations")?;
    let clock_uncertain = required_bool(maintenance, "clock_uncertain")?;
    let stalled = required_u64(maintenance, "running_no_durable_progress_slo_breaches")?;
    let progress_unknown = required_u64(maintenance, "running_no_durable_progress_slo_unknown")?;
    let checkpointed_tasks = required_u64(maintenance, "checkpointed_tasks")?;
    let paused_tasks = required_u64(maintenance, "paused_tasks")?;
    let conflicted_tasks = required_u64(maintenance, "conflicted_tasks")?;
    let doctor = required_object(report, "doctor")?;
    let key_custody = required_string(doctor, "key_custody")?;
    let catalog_bootstrap = required_string(doctor, "catalog_bootstrap")?;
    let catalog_generation = required_u64(doctor, "catalog_generation")?;
    let backup_repository = required_string(doctor, "backup_repository")?;
    let durable_operations = required_u64(doctor, "durable_operations")?;
    let active_durable_operations = required_u64(doctor, "active_durable_operations")?;
    let snapshot_leases = required_u64(doctor, "snapshot_leases")?;
    let listeners = required_object(doctor, "listener_topology")?;
    let topology_active = [
        "control",
        "operations",
        "api",
        "otlp_grpc",
        "otlp_http",
        "loki_push",
    ]
    .into_iter()
    .try_fold(true, |active, role| {
        required_bool(listeners, role).map(|bound| active && bound)
    })?;
    let evidence = format!(
        "evidence_scope=authenticated_operations_status\nprocess_phase={phase}\nintegrity_degraded={degraded}\neffective_configuration_digest={effective_configuration_digest}\ndesired_configuration_digest={desired_configuration_digest}\nconfiguration_drift_disposition={configuration_drift_disposition}\nconfiguration_pending_restart={configuration_pending_restart}\nmaintenance_queued={queued}\nmaintenance_clock_uncertain={clock_uncertain}\nmaintenance_running_no_durable_progress_slo_breaches={stalled}\nmaintenance_running_no_durable_progress_slo_unknown={progress_unknown}\nmaintenance_checkpointed_tasks={checkpointed_tasks}\nmaintenance_paused_tasks={paused_tasks}\nmaintenance_conflicted_tasks={conflicted_tasks}\ndurable_operations={durable_operations}\nactive_durable_operations={active_durable_operations}\nsnapshot_leases={snapshot_leases}\noutstanding_reservations={reservations}\nkey_custody={key_custody}\ncatalog_bootstrap={catalog_bootstrap}\ncatalog_generation={catalog_generation}\nlistener_topology={}\nbackup_repository={backup_repository}\n",
        if topology_active {
            "active"
        } else {
            "incomplete"
        },
    );
    if key_custody != "verified" || catalog_bootstrap != "verified" || !topology_active {
        return Ok((
            ExitCode::from(EXIT_DIAGNOSTIC_FAILURE),
            format!(
                "report_version=1\nmode=online\nstatus=inspection_incomplete\nfinding_code=DOCTOR_RUNTIME_FACTS_INCOMPLETE\nseverity=warning\n{evidence}"
            ),
        ));
    }
    if effective_configuration_digest != desired_configuration_digest
        || configuration_drift_disposition != "none"
        || configuration_pending_restart
    {
        return Ok((
            ExitCode::from(EXIT_DIAGNOSTIC_FAILURE),
            format!(
                "report_version=1\nmode=online\nstatus=degraded\nfinding_code=DOCTOR_CONFIGURATION_DEGRADED\nseverity=warning\n{evidence}safe_command=inspect_configuration_status\n"
            ),
        ));
    }
    if backup_repository == "not_configured" {
        return Ok((
            ExitCode::from(EXIT_DIAGNOSTIC_FAILURE),
            format!(
                "report_version=1\nmode=online\nstatus=degraded\nfinding_code=DOCTOR_BACKUP_REPOSITORY_NOT_CONFIGURED\nseverity=warning\n{evidence}safe_command=configure_backup_repository\n"
            ),
        ));
    }
    if phase == "serving"
        && !degraded
        && backup_repository == "configured"
        && !clock_uncertain
        && stalled == 0
        && progress_unknown == 0
    {
        return Ok((
            ExitCode::SUCCESS,
            format!(
                "report_version=1\nmode=online\nstatus=healthy\nfinding_code=DOCTOR_RUNTIME_VERIFIED\nseverity=info\n{evidence}safe_command=none\n"
            ),
        ));
    }
    Ok((
        ExitCode::from(EXIT_DIAGNOSTIC_FAILURE),
        format!(
            "report_version=1\nmode=online\nstatus=degraded\nfinding_code=DOCTOR_RUNTIME_DEGRADED\nseverity=error\n{evidence}safe_command=inspect_runtime_state\n"
        ),
    ))
}

fn required_object<'a>(
    value: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<&'a serde_json::Map<String, serde_json::Value>, DoctorFailure> {
    value
        .get(key)
        .and_then(serde_json::Value::as_object)
        .ok_or(DoctorFailure::EndpointUnavailable)
}

fn required_string<'a>(
    value: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<&'a str, DoctorFailure> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or(DoctorFailure::EndpointUnavailable)
}

fn required_bool(
    value: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<bool, DoctorFailure> {
    value
        .get(key)
        .and_then(serde_json::Value::as_bool)
        .ok_or(DoctorFailure::EndpointUnavailable)
}

fn required_u64(
    value: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u64, DoctorFailure> {
    value
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .ok_or(DoctorFailure::EndpointUnavailable)
}

fn operations_status(options: &Options, bearer: &str) -> Result<serde_json::Value, DoctorFailure> {
    if let Some(path) = options.control_path.as_deref() {
        return control_status(path, bearer);
    }
    let endpoint = options.endpoint.ok_or(DoctorFailure::Arguments)?;
    if endpoint.port() == 0 {
        return Err(DoctorFailure::Arguments);
    }
    let mut builder = reqwest::blocking::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(5));
    let target = if options.allow_plaintext {
        if options.server_name.is_some() || options.trust_file.is_some() {
            return Err(DoctorFailure::Arguments);
        }
        format!("http://{endpoint}")
    } else {
        let name = options
            .server_name
            .as_deref()
            .ok_or(DoctorFailure::Arguments)?;
        let pem = std::fs::read(
            options
                .trust_file
                .as_deref()
                .ok_or(DoctorFailure::Arguments)?,
        )
        .map_err(|_| DoctorFailure::EndpointUnavailable)?;
        builder = builder
            .add_root_certificate(
                reqwest::Certificate::from_pem(&pem).map_err(|_| DoctorFailure::Arguments)?,
            )
            .resolve(name, endpoint);
        format!("https://{name}:{}", endpoint.port())
    };
    let response = builder
        .build()
        .map_err(|_| DoctorFailure::EndpointUnavailable)?
        .get(format!("{target}/status"))
        .bearer_auth(bearer)
        .send()
        .map_err(|_| DoctorFailure::EndpointUnavailable)?;
    if response.status().as_u16() == 401 {
        return Err(DoctorFailure::AuthenticationRejected);
    }
    if !response.status().is_success() {
        return Err(DoctorFailure::EndpointUnavailable);
    }
    let mut bytes = Vec::with_capacity(8_192);
    response
        .take(8_193)
        .read_to_end(&mut bytes)
        .map_err(|_| DoctorFailure::EndpointUnavailable)?;
    if bytes.len() > 8_192 {
        return Err(DoctorFailure::EndpointUnavailable);
    }
    serde_json::from_slice(&bytes).map_err(|_| DoctorFailure::EndpointUnavailable)
}

fn fenced_control_report(
    report: &serde_json::Map<String, serde_json::Value>,
) -> Result<(ExitCode, String), DoctorFailure> {
    let doctor = required_object(report, "doctor")?;
    let key_custody = required_string(doctor, "key_custody")?;
    let catalog_bootstrap = required_string(doctor, "catalog_bootstrap")?;
    let catalog_generation = required_u64(doctor, "catalog_generation")?;
    let backup_repository = required_string(doctor, "backup_repository")?;
    let listeners = required_object(doctor, "listener_topology")?;
    let control = required_bool(listeners, "control")?;
    let operations = required_bool(listeners, "operations")?;
    let data_retired = ["api", "otlp_grpc", "otlp_http", "loki_push"]
        .into_iter()
        .try_fold(true, |retired, role| {
            required_bool(listeners, role).map(|bound| retired && !bound)
        })?;
    let reason = required_string(report, "reason")?;
    Ok((
        ExitCode::from(EXIT_DIAGNOSTIC_FAILURE),
        format!(
            "report_version=1\nmode=online\nstatus=fenced\nfinding_code=DOCTOR_RUNTIME_FENCED\nseverity=error\nevidence_scope=owner_local_control\nprocess_phase=fenced\nfence_reason={reason}\nkey_custody={key_custody}\ncatalog_bootstrap={catalog_bootstrap}\ncatalog_generation={catalog_generation}\nbackup_repository={backup_repository}\ncontrol_listener_active={control}\noperations_listener_active={operations}\ndata_listeners_retired={data_retired}\nsafe_command=inspect_integrity_recovery\n"
        ),
    ))
}

#[cfg(unix)]
fn control_status(path: &Path, bearer: &str) -> Result<serde_json::Value, DoctorFailure> {
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(path).map_err(|_| DoctorFailure::EndpointUnavailable)?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|_| DoctorFailure::EndpointUnavailable)?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|_| DoctorFailure::EndpointUnavailable)?;
    stream
        .write_all(
            format!(
                "GET /control/fenced/inspection HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {bearer}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .map_err(|_| DoctorFailure::EndpointUnavailable)?;
    let mut response = Vec::with_capacity(8_192);
    stream
        .take(8_193)
        .read_to_end(&mut response)
        .map_err(|_| DoctorFailure::EndpointUnavailable)?;
    if response.len() > 8_192 {
        return Err(DoctorFailure::EndpointUnavailable);
    }
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(DoctorFailure::EndpointUnavailable)?;
    let (head, body) = response.split_at(separator + 4);
    if head.starts_with(b"HTTP/1.1 401 ") {
        return Err(DoctorFailure::AuthenticationRejected);
    }
    if !head.starts_with(b"HTTP/1.1 200 ") {
        return Err(DoctorFailure::EndpointUnavailable);
    }
    serde_json::from_slice(body).map_err(|_| DoctorFailure::EndpointUnavailable)
}

#[cfg(not(unix))]
fn control_status(_path: &Path, _bearer: &str) -> Result<serde_json::Value, DoctorFailure> {
    Err(DoctorFailure::EndpointUnavailable)
}
