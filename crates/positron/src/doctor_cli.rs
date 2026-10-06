//! Bounded read-only Doctor reports.

use std::{
    io::{IsTerminal, Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

use positron_config::{ConfigurationInputs, resolve};
use positron_kernel::MountQualification;
use positron_runtime::{
    BootstrapPaths, OfflineDiskPressure, OfflineIntegrityFailure, OfflineIntegrityVerification,
    verify_offline_integrity,
};
use zeroize::Zeroizing;

const EXIT_USAGE: u8 = 2;
const EXIT_DIAGNOSTIC_FAILURE: u8 = 3;

pub(super) fn run(
    arguments: impl Iterator<Item = String>,
    environment: impl IntoIterator<Item = (String, String)>,
) -> ExitCode {
    match execute(arguments, environment) {
        Ok((exit, report)) => write_report(&report)
            .map_or_else(|()| ExitCode::from(EXIT_DIAGNOSTIC_FAILURE), |_| exit),
        Err(failure) => write_report(failure.render()).map_or_else(
            |()| ExitCode::from(EXIT_DIAGNOSTIC_FAILURE),
            |_| ExitCode::from(failure.exit_code()),
        ),
    }
}

fn write_report(report: &str) -> Result<(), ()> {
    let stdout = std::io::stdout();
    let mut locked = stdout.lock();
    locked.write_all(report.as_bytes()).map_err(|_| ())?;
    locked.flush().map_err(|_| ())
}

fn execute(
    arguments: impl Iterator<Item = String>,
    environment: impl IntoIterator<Item = (String, String)>,
) -> Result<(ExitCode, String), DoctorFailure> {
    let options = Options::parse(arguments)?;
    match options.mode {
        Mode::Offline => execute_offline(&options, environment),
        Mode::Online => execute_online(&options),
    }
}

fn execute_offline(
    options: &Options,
    environment: impl IntoIterator<Item = (String, String)>,
) -> Result<(ExitCode, String), DoctorFailure> {
    let inputs = ConfigurationInputs::try_from_sources(
        options.config.as_deref().map(Path::new),
        environment,
        options.overrides.clone(),
    )
    .map_err(|_| DoctorFailure::Arguments)?;
    let effective = resolve(inputs).map_err(|_| DoctorFailure::Arguments)?;
    let paths = BootstrapPaths::with_local_key(
        Path::new(effective.data_directory()),
        Path::new(effective.secrets_directory()),
        effective.local_key_file().as_path(),
        MountQualification::LocalHost,
    )
    .map_err(|_| DoctorFailure::Arguments)?;
    match verify_offline_integrity(&paths, effective.max_registered_tenants()) {
        Ok(report) => {
            let verified = report.is_verified();
            Ok((
                if verified {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(EXIT_DIAGNOSTIC_FAILURE)
                },
                offline_success_report(
                    verified,
                    &report,
                    &effective,
                    options.config.as_deref(),
                    &options.overrides,
                ),
            ))
        },
        Err(failure) => Ok((
            ExitCode::from(EXIT_DIAGNOSTIC_FAILURE),
            offline_failure_report(failure),
        )),
    }
}

/// Renders only facts established by the exclusive offline inspection path.
/// Storage ownership proves no Positron process currently owns this volume;
/// runtime-only families are therefore explicitly unavailable, never inferred
/// from stale files or placeholder values.
pub(crate) fn offline_success_report(
    verified: bool,
    inspection: &OfflineIntegrityVerification,
    effective: &positron_config::EffectiveConfiguration,
    configuration: Option<&Path>,
    overrides: &[(String, String)],
) -> String {
    let facts = inspection.facts();
    let pressure = match facts.disk_pressure() {
        OfflineDiskPressure::Healthy => "healthy",
        OfflineDiskPressure::Soft => "soft",
        OfflineDiskPressure::Hard => "hard",
    };
    let complete = inspection.is_complete();
    let (status, finding, severity) = if verified {
        ("healthy", "VERIFIED", "info")
    } else if !complete {
        ("incomplete", "INCOMPLETE", "warning")
    } else {
        ("fenced", "FENCED", "error")
    };
    let continuation = inspection.continuation().map(|value| hex(value.encoded()));
    let safe_command = continuation.as_ref().map_or_else(
        || {
            if verified {
                "none".to_owned()
            } else {
                "positron verify --offline".to_owned()
            }
        },
        |value| offline_verify_command(Some(value), configuration, overrides),
    );
    let mut report = format!(
        "report_version=1\nmode=offline\nstatus={}\nfinding_code=DOCTOR_INTEGRITY_{}\nseverity={}\nevidence_scope=offline_integrity_reports\nsafe_command={}\nreport_count={}\nverified_scope_count={}\nfenced_scope_count={}\nincomplete_scope_count={}\n",
        status,
        finding,
        severity,
        safe_command,
        inspection.reports().len(),
        facts.verified_scope_count(),
        facts.fenced_scope_count(),
        facts.incomplete_scope_count(),
    );
    if let Some(continuation) = continuation {
        report.push_str(&format!("aggregate_continuation={continuation}\n"));
    }
    report.push_str(
        "finding_code=DOCTOR_CONFIGURATION_RESOLVED\nseverity=info\nevidence_scope=effective_configuration\nconfiguration_contract=valid\nconfiguration_effective_redacted_begin=true\n",
    );
    report.push_str(&effective.redacted_effective());
    report.push_str("\nconfiguration_effective_redacted_end=true\nsafe_command=none\n");
    report.push_str(&format!(
        "finding_code=DOCTOR_STORAGE_CAPACITY_OBSERVED\nseverity=info\nevidence_scope=primary_data_volume\nusable_disk_bytes={}\ndisk_pressure={pressure}\nsafe_command=none\n",
        facts.usable_disk_bytes(),
    ));
    report.push_str(&format!(
        "finding_code=DOCTOR_KEY_ENVELOPES_VERIFIED\nseverity={}\nevidence_scope=authenticated_tenant_envelopes\nverified_envelope_count={}\nsafe_command={}\n",
        if verified { "info" } else { "error" },
        facts.verified_envelope_count(),
        if verified { "none" } else { "positron verify --offline" },
    ));
    report.push_str(&format!(
        "finding_code=DOCTOR_CATALOG_FRONTIERS_VERIFIED\nseverity={}\nevidence_scope=authenticated_catalog_snapshot\ncatalog_generation={}\nregistered_tenant_count={}\nreachable_scope_count={}\nquarantine_finding_count={}\nsafe_command={}\n",
        if verified { "info" } else { "error" },
        facts.catalog_generation(),
        facts.registered_tenant_count(),
        facts.reachable_scope_count(),
        facts.quarantine_finding_count(),
        if verified { "none" } else { "positron verify --offline" },
    ));
    let backup = facts.backup_repository().label();
    report.push_str(&format!(
        "finding_code=DOCTOR_BACKUP_REPOSITORY_NOT_CONFIGURED\nseverity=warning\nevidence_scope=authenticated_catalog_backup_binding\nbackup_repository={backup}\nsafe_command=configure_backup_repository\n"
    ));
    report.push_str(
        "finding_code=DOCTOR_GOVERNOR_RUNTIME_UNAVAILABLE_OFFLINE\nseverity=info\nevidence_scope=runtime_resource_governor\nruntime_state=not_observable_offline\nsafe_command=start_positron_for_live_governor_status\n",
    );
    for (code, command) in [
        (
            "DOCTOR_MAINTENANCE_RUNTIME_UNAVAILABLE_OFFLINE",
            "start_positron_for_maintenance_status",
        ),
        (
            "DOCTOR_OPERATIONS_LEASES_UNAVAILABLE_OFFLINE",
            "start_positron_for_operations_status",
        ),
        (
            "DOCTOR_LISTENERS_UNAVAILABLE_OFFLINE",
            "start_positron_for_listener_status",
        ),
        (
            "DOCTOR_HEALTH_UNAVAILABLE_OFFLINE",
            "start_positron_for_process_health",
        ),
    ] {
        report.push_str(&format!(
            "finding_code={code}\nseverity=info\nevidence_scope=exclusive_primary_data_volume_ownership\nruntime_state=not_observable_offline\nsafe_command={command}\n"
        ));
    }
    report
}

fn offline_verify_command(
    continuation: Option<&str>,
    configuration: Option<&Path>,
    overrides: &[(String, String)],
) -> String {
    let Some(continuation) = continuation else {
        return "positron verify --offline".to_owned();
    };
    let mut command = String::from("positron verify --offline");
    if let Some(configuration) = configuration {
        let Some(configuration) = configuration.to_str().and_then(shell_quote) else {
            return "inspect_effective_configuration_before_resuming".to_owned();
        };
        command.push_str(" --config ");
        command.push_str(&configuration);
    }
    for (key, value) in overrides {
        let Some(override_value) = shell_quote(&format!("{key}={value}")) else {
            return "inspect_effective_configuration_before_resuming".to_owned();
        };
        command.push_str(" --set ");
        command.push_str(&override_value);
    }
    let Some(continuation) = shell_quote(continuation) else {
        return "inspect_effective_configuration_before_resuming".to_owned();
    };
    command.push_str(" --continuation ");
    command.push_str(&continuation);
    command
}

fn shell_quote(value: &str) -> Option<String> {
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return None;
    }
    Some(format!("'{}'", value.replace('\'', "'\"'\"'")))
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn execute_online(options: &Options) -> Result<(ExitCode, String), DoctorFailure> {
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

fn online_status_request(
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

fn offline_failure_report(failure: OfflineIntegrityFailure) -> String {
    format!(
        "report_version=1\nmode=offline\nstatus={}\nfinding_code={}\nseverity=error\nevidence_scope=primary_data_volume\nsafe_command={}\nreport_count=0\n",
        status(failure),
        code(failure),
        safe_command(failure)
    )
}

fn status(failure: OfflineIntegrityFailure) -> &'static str {
    match failure {
        OfflineIntegrityFailure::OwnershipLocked => "storage_locked",
        OfflineIntegrityFailure::BootstrapUnavailable => "bootstrap_unavailable",
        OfflineIntegrityFailure::KeyUnavailable => "key_unavailable",
        OfflineIntegrityFailure::CatalogUnavailable => "catalog_busy",
        OfflineIntegrityFailure::CorruptState => "fenced",
        OfflineIntegrityFailure::CapacityUnavailable => "capacity_unavailable",
        OfflineIntegrityFailure::StorageUnavailable => "storage_unavailable",
    }
}
fn code(failure: OfflineIntegrityFailure) -> &'static str {
    match failure {
        OfflineIntegrityFailure::OwnershipLocked => "DOCTOR_STORAGE_LOCKED",
        OfflineIntegrityFailure::BootstrapUnavailable => "DOCTOR_BOOTSTRAP_UNAVAILABLE",
        OfflineIntegrityFailure::KeyUnavailable => "DOCTOR_KEY_UNAVAILABLE",
        OfflineIntegrityFailure::CatalogUnavailable => "DOCTOR_CATALOG_BUSY",
        OfflineIntegrityFailure::CorruptState => "DOCTOR_INTEGRITY_FENCED",
        OfflineIntegrityFailure::CapacityUnavailable => "DOCTOR_CAPACITY_UNAVAILABLE",
        OfflineIntegrityFailure::StorageUnavailable => "DOCTOR_STORAGE_UNAVAILABLE",
    }
}
const fn safe_command(failure: OfflineIntegrityFailure) -> &'static str {
    match failure {
        OfflineIntegrityFailure::OwnershipLocked => "stop_positron_before_offline_doctor",
        _ => "inspect_storage_without_mutation",
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Offline,
    Online,
}
struct Options {
    mode: Mode,
    config: Option<PathBuf>,
    overrides: Vec<(String, String)>,
    endpoint: Option<SocketAddr>,
    control_path: Option<PathBuf>,
    server_name: Option<String>,
    trust_file: Option<PathBuf>,
    allow_plaintext: bool,
}

impl Options {
    fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, DoctorFailure> {
        let mut mode = None;
        let mut config = None;
        let mut overrides = Vec::new();
        let mut endpoint = None;
        let mut control_path = None;
        let mut server_name = None;
        let mut trust_file = None;
        let mut allow_plaintext = false;
        let mut credential_stdin = false;
        let mut arguments = arguments;
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--offline" if mode.is_none() => mode = Some(Mode::Offline),
                "--online" if mode.is_none() => mode = Some(Mode::Online),
                "--config" if config.is_none() => {
                    config = Some(PathBuf::from(
                        arguments.next().ok_or(DoctorFailure::Arguments)?,
                    ))
                },
                "--set" => {
                    let value = arguments.next().ok_or(DoctorFailure::Arguments)?;
                    let (key, value) = value.split_once('=').ok_or(DoctorFailure::Arguments)?;
                    overrides.push((key.to_owned(), value.to_owned()));
                },
                "--endpoint" if endpoint.is_none() => {
                    endpoint = Some(
                        arguments
                            .next()
                            .ok_or(DoctorFailure::Arguments)?
                            .parse()
                            .map_err(|_| DoctorFailure::Arguments)?,
                    )
                },
                "--control-path" if control_path.is_none() => {
                    control_path = Some(PathBuf::from(
                        arguments.next().ok_or(DoctorFailure::Arguments)?,
                    ))
                },
                "--server-name" if server_name.is_none() => {
                    server_name = Some(arguments.next().ok_or(DoctorFailure::Arguments)?)
                },
                "--trust-file" if trust_file.is_none() => {
                    trust_file = Some(PathBuf::from(
                        arguments.next().ok_or(DoctorFailure::Arguments)?,
                    ))
                },
                "--allow-plaintext" if !allow_plaintext => allow_plaintext = true,
                "--credential-stdin" if !credential_stdin => credential_stdin = true,
                _ => return Err(DoctorFailure::Arguments),
            }
        }
        let mode = mode.ok_or(DoctorFailure::Arguments)?;
        match mode {
            Mode::Offline
                if endpoint.is_some()
                    || control_path.is_some()
                    || server_name.is_some()
                    || trust_file.is_some()
                    || allow_plaintext
                    || credential_stdin =>
            {
                Err(DoctorFailure::Arguments)
            },
            Mode::Online
                if config.is_some()
                    || !overrides.is_empty()
                    || !credential_stdin
                    || (endpoint.is_some() == control_path.is_some())
                    || (control_path.is_some()
                        && (server_name.is_some() || trust_file.is_some() || allow_plaintext)) =>
            {
                Err(DoctorFailure::Arguments)
            },
            Mode::Offline | Mode::Online => Ok(Self {
                mode,
                config,
                overrides,
                endpoint,
                control_path,
                server_name,
                trust_file,
                allow_plaintext,
            }),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum DoctorFailure {
    Arguments,
    AuthenticationRejected,
    EndpointUnavailable,
}
impl std::fmt::Display for DoctorFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.render())
    }
}
impl std::error::Error for DoctorFailure {}
impl DoctorFailure {
    const fn exit_code(self) -> u8 {
        match self {
            Self::Arguments => EXIT_USAGE,
            Self::AuthenticationRejected | Self::EndpointUnavailable => EXIT_DIAGNOSTIC_FAILURE,
        }
    }
    const fn render(self) -> &'static str {
        match self {
            Self::Arguments => {
                "report_version=1\nmode=unknown\nstatus=invalid_arguments\nfinding_code=DOCTOR_ARGUMENTS_INVALID\nseverity=error\nsafe_command=correct_doctor_arguments\n"
            },
            Self::AuthenticationRejected => {
                "report_version=1\nmode=online\nstatus=authentication_rejected\nfinding_code=DOCTOR_AUTHENTICATION_REJECTED\nseverity=error\nevidence_scope=none\nsafe_command=use_system_administrator_credential\n"
            },
            Self::EndpointUnavailable => {
                "report_version=1\nmode=online\nstatus=inspection_unavailable\nfinding_code=DOCTOR_ONLINE_INSPECTION_UNAVAILABLE\nseverity=error\nevidence_scope=none\nsafe_command=inspect_runtime_connectivity\n"
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DoctorFailure, Options, offline_verify_command, online_status_request};
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
    fn online_doctor_uses_authenticated_operations_status() -> Result<(), Box<dyn std::error::Error>>
    {
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
            report
                .contains("status=degraded\nfinding_code=DOCTOR_BACKUP_REPOSITORY_NOT_CONFIGURED")
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
}
