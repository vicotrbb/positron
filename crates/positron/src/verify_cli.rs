use std::{
    io::{IsTerminal, Read},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
};

use positron_api::maintenance::{
    MaintenanceServiceClient, MaintenanceServiceClientFailure, MaintenanceTransport,
    OnlineVerificationReport, OnlineVerificationRequest,
};
use positron_config::{ConfigurationInputs, resolve};
use positron_domain::{
    identity::TenantId,
    routing::{SignalKind, VirtualShardId},
};
use positron_kernel::{IntegrityScrubContinuation, MountQualification, SegmentScope};
use positron_runtime::{
    BootstrapPaths, OfflineIntegrityFailure, resume_offline_integrity, verify_offline_integrity,
};
use zeroize::Zeroizing;

const EXIT_CONFIGURATION: u8 = 2;
const EXIT_INTEGRITY: u8 = 3;

pub(super) fn run(
    arguments: impl Iterator<Item = String>,
    environment: impl IntoIterator<Item = (String, String)>,
) -> ExitCode {
    let arguments = arguments.collect::<Vec<_>>();
    let selected_mode = selected_mode(&arguments);
    match execute(arguments.into_iter(), environment) {
        Ok((exit, output)) => {
            print!("{output}");
            exit
        },
        Err(failure) => {
            print!(
                "mode={selected_mode}\nstatus={}\nverification_complete=false\n",
                failure.status()
            );
            ExitCode::from(EXIT_CONFIGURATION)
        },
    }
}

fn selected_mode(arguments: &[String]) -> &'static str {
    let online = arguments.iter().any(|argument| argument == "--online");
    let offline = arguments.iter().any(|argument| argument == "--offline");
    match (online, offline) {
        (true, false) => "online",
        (false, true) => "offline",
        (false, false) | (true, true) => "usage",
    }
}

fn execute(
    arguments: impl Iterator<Item = String>,
    environment: impl IntoIterator<Item = (String, String)>,
) -> Result<(ExitCode, String), VerifyFailure> {
    let options = VerifyOptions::parse(arguments)?;
    if options.online {
        return execute_online(&options);
    }
    let offline_resume = options
        .continuation
        .as_deref()
        .map(|cursor| {
            Ok((
                offline_scope(&options)?,
                decode_offline_continuation(cursor)?,
            ))
        })
        .transpose()?;
    let inputs = ConfigurationInputs::try_from_sources(
        options.config.as_deref().map(Path::new),
        environment,
        options.overrides,
    )
    .map_err(|_| VerifyFailure::Configuration)?;
    let effective = resolve(inputs).map_err(|_| VerifyFailure::Configuration)?;
    let paths = BootstrapPaths::with_local_key(
        Path::new(effective.data_directory()),
        Path::new(effective.secrets_directory()),
        effective.local_key_file().as_path(),
        MountQualification::LocalHost,
    )
    .map_err(|_| VerifyFailure::Configuration)?;
    let offline = match offline_resume {
        Some((scope, continuation)) => resume_offline_integrity(
            &paths,
            effective.max_registered_tenants(),
            scope,
            continuation,
        ),
        None => verify_offline_integrity(&paths, effective.max_registered_tenants()),
    };
    match offline {
        Ok(report) => {
            let status = if report.is_verified() {
                "verified"
            } else {
                "fenced"
            };
            let mut output = format!(
                "mode=offline\nstatus={status}\nverification_complete={}\nreport_count={}\n",
                report.is_complete(),
                report.reports().len(),
            );
            for item in report.reports() {
                output.push_str(&render_report(*item));
            }
            for finding in report.findings() {
                output.push_str(&render_finding(*finding));
            }
            let exit = if report.is_verified() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(EXIT_INTEGRITY)
            };
            Ok((exit, output))
        },
        Err(failure) => Ok((
            ExitCode::from(EXIT_INTEGRITY),
            format!(
                "mode=offline\nstatus={}\nverification_complete=false\nreport_count=0\n",
                failure_status(failure)
            ),
        )),
    }
}

fn execute_online(options: &VerifyOptions) -> Result<(ExitCode, String), VerifyFailure> {
    let input = std::io::stdin();
    if input.is_terminal() {
        return Err(VerifyFailure::Usage);
    }
    let mut credential = Zeroizing::new(String::new());
    input
        .take(1025)
        .read_to_string(&mut credential)
        .map_err(|_| VerifyFailure::Configuration)?;
    let bearer = credential.trim_end_matches(['\r', '\n']);
    if credential.len() > 1024
        || bearer.is_empty()
        || bearer.len() > 1024
        || !bearer
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(VerifyFailure::Usage);
    }
    let request = OnlineVerificationRequest::new(
        options.tenant.clone().ok_or(VerifyFailure::Usage)?,
        options.signal.clone().ok_or(VerifyFailure::Usage)?,
        options.shard.ok_or(VerifyFailure::Usage)?,
        options.expected_catalog_generation,
        options.continuation.clone(),
    );
    online_request(options, bearer, &request)
}

fn online_request(
    options: &VerifyOptions,
    bearer: &str,
    request: &OnlineVerificationRequest,
) -> Result<(ExitCode, String), VerifyFailure> {
    let transport = online_transport(options)?;
    let client =
        MaintenanceServiceClient::new(transport).map_err(|_| VerifyFailure::Configuration)?;
    let report = client.verify(bearer, request).map_err(online_failure)?;
    let exit = if report.verification_complete && report.outcome == "verified" {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_INTEGRITY)
    };
    Ok((exit, render_online_report(&report)))
}

fn online_transport(options: &VerifyOptions) -> Result<MaintenanceTransport, VerifyFailure> {
    let endpoint = options.endpoint.ok_or(VerifyFailure::Usage)?;
    if endpoint.port() == 0 {
        return Err(VerifyFailure::Usage);
    }
    if options.allow_plaintext {
        if options.server_name.is_some() || options.trust_file.is_some() {
            return Err(VerifyFailure::Usage);
        }
        Ok(MaintenanceTransport::PlaintextOptOut { endpoint })
    } else {
        Ok(MaintenanceTransport::Tls {
            endpoint,
            server_name: options.server_name.clone().ok_or(VerifyFailure::Usage)?,
            trust_file: options.trust_file.clone().ok_or(VerifyFailure::Usage)?,
        })
    }
}

fn online_failure(failure: MaintenanceServiceClientFailure) -> VerifyFailure {
    match failure {
        MaintenanceServiceClientFailure::InvalidRequest
        | MaintenanceServiceClientFailure::AuthenticationRejected
        | MaintenanceServiceClientFailure::SourceUnavailable => VerifyFailure::Usage,
        MaintenanceServiceClientFailure::TaskUnavailable
        | MaintenanceServiceClientFailure::PreconditionFailed
        | MaintenanceServiceClientFailure::IdempotencyConflict
        | MaintenanceServiceClientFailure::AdministrationUnavailable
        | MaintenanceServiceClientFailure::Transport => VerifyFailure::Configuration,
    }
}

fn render_finding(finding: positron_kernel::IntegrityQuarantineFinding) -> String {
    let scope = finding.scope();
    let signal = match scope.signal_kind() {
        positron_domain::routing::SignalKind::Logs => "logs",
        positron_domain::routing::SignalKind::Traces => "traces",
    };
    let (event_provenance, event_earliest, event_latest) = event_range(finding.event_range());
    let (ingest_provenance, ingest_earliest, ingest_latest) = ingest_range(finding.ingest_range());
    format!(
        "quarantine_tenant={} quarantine_signal={signal} quarantine_shard={} quarantine_segment={} quarantine_base_position={} quarantine_event_provenance={event_provenance} quarantine_event_earliest_unix_nanos={event_earliest} quarantine_event_latest_unix_nanos={event_latest} quarantine_ingest_provenance={ingest_provenance} quarantine_ingest_earliest_unix_nanos={ingest_earliest} quarantine_ingest_latest_unix_nanos={ingest_latest}\n",
        scope.tenant_id(),
        scope.shard_id().value(),
        hex(&finding.segment().to_bytes()),
        finding.base_position(),
    )
}

fn event_range(range: positron_kernel::AuthenticatedEventRange) -> (&'static str, String, String) {
    match range {
        positron_kernel::AuthenticatedEventRange::Known { earliest, latest } => (
            "known",
            earliest.value().to_string(),
            latest.value().to_string(),
        ),
        positron_kernel::AuthenticatedEventRange::Unavailable(reason) => (
            match reason {
                positron_kernel::EventRangeUnavailable::MissingSourceTime => "missing_source_time",
                positron_kernel::EventRangeUnavailable::InvalidSourceTime => "invalid_source_time",
                positron_kernel::EventRangeUnavailable::LegacyFormat => "legacy_format",
            },
            "none".to_owned(),
            "none".to_owned(),
        ),
    }
}

fn ingest_range(
    range: positron_kernel::AuthenticatedIngestRange,
) -> (&'static str, String, String) {
    match range {
        positron_kernel::AuthenticatedIngestRange::Known { earliest, latest } => (
            "known",
            earliest.value().to_string(),
            latest.value().to_string(),
        ),
        positron_kernel::AuthenticatedIngestRange::Unavailable => {
            ("unavailable", "none".to_owned(), "none".to_owned())
        },
    }
}

fn render_report(report: positron_kernel::IntegrityVerificationReport) -> String {
    let scope = report.scope();
    let signal = match scope.signal_kind() {
        positron_domain::routing::SignalKind::Logs => "logs",
        positron_domain::routing::SignalKind::Traces => "traces",
    };
    let outcome = match report.outcome() {
        positron_kernel::IntegrityVerificationOutcome::Verified => "verified",
        positron_kernel::IntegrityVerificationOutcome::Incomplete => "incomplete",
        positron_kernel::IntegrityVerificationOutcome::Stale => "stale",
        positron_kernel::IntegrityVerificationOutcome::Quarantined => "quarantined",
        positron_kernel::IntegrityVerificationOutcome::Fenced => "fenced",
    };
    let quarantined = report
        .quarantined_segment()
        .map(|segment| hex(&segment.to_bytes()))
        .unwrap_or_else(|| "none".to_owned());
    let continuation = report
        .continuation()
        .map(|cursor| hex(&cursor.encode()))
        .unwrap_or_else(|| "none".to_owned());
    format!(
        "report_scope_tenant={} report_scope_signal={signal} report_scope_shard={} catalog_generation={} examined_segments={} examined_bytes={} omitted_segments={} outcome={outcome} continuation={continuation} quarantined_segment={quarantined} report_checksum={}\n",
        scope.tenant_id(),
        scope.shard_id().value(),
        report.catalog_generation(),
        report.examined_segments(),
        report.examined_bytes(),
        report.omitted_segments(),
        hex(&report.checksum()),
    )
}

fn render_online_report(report: &OnlineVerificationReport) -> String {
    let continuation = report.continuation.as_deref().unwrap_or("none");
    let mut output = format!(
        "report_version={}\nmode=online\nstatus={}\nverification_complete={}\nreport_checksum={}\nreport_scope_tenant={} report_scope_signal={} report_scope_shard={} catalog_generation={} examined_segments={} examined_bytes={} omitted_segments={} continuation={}\n",
        report.report_version,
        report.outcome,
        report.verification_complete,
        report.report_checksum,
        report.tenant,
        report.signal,
        report.shard,
        report.catalog_generation,
        report.examined_segments,
        report.examined_bytes,
        report.omitted_segments,
        continuation,
    );
    for finding in &report.findings {
        output.push_str(&format!(
            "quarantine_tenant={} quarantine_signal={} quarantine_shard={} quarantine_segment={} quarantine_base_position={} quarantine_event_provenance={} quarantine_event_earliest_unix_nanos={} quarantine_event_latest_unix_nanos={} quarantine_ingest_provenance={} quarantine_ingest_earliest_unix_nanos={} quarantine_ingest_latest_unix_nanos={}\n",
            finding.tenant,
            finding.signal,
            finding.shard,
            finding.segment,
            finding.base_position,
            finding.event_range.provenance,
            finding.event_range.earliest_unix_nanos.map_or_else(|| "none".to_owned(), |value| value.to_string()),
            finding.event_range.latest_unix_nanos.map_or_else(|| "none".to_owned(), |value| value.to_string()),
            finding.ingest_range.provenance,
            finding.ingest_range.earliest_unix_nanos.map_or_else(|| "none".to_owned(), |value| value.to_string()),
            finding.ingest_range.latest_unix_nanos.map_or_else(|| "none".to_owned(), |value| value.to_string()),
        ));
    }
    output
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    result
}

fn offline_scope(options: &VerifyOptions) -> Result<SegmentScope, VerifyFailure> {
    let tenant = TenantId::parse_canonical(options.tenant.as_deref().ok_or(VerifyFailure::Usage)?)
        .map_err(|_| VerifyFailure::Usage)?;
    let signal = match options.signal.as_deref() {
        Some("logs") => SignalKind::Logs,
        Some("traces") => SignalKind::Traces,
        _ => return Err(VerifyFailure::Usage),
    };
    let shard = VirtualShardId::new(options.shard.ok_or(VerifyFailure::Usage)?)
        .map_err(|_| VerifyFailure::Usage)?;
    Ok(SegmentScope::new(tenant, signal, shard))
}

fn decode_offline_continuation(value: &str) -> Result<IntegrityScrubContinuation, VerifyFailure> {
    if value.len() != 112 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(VerifyFailure::Usage);
    }
    let mut bytes = [0_u8; 56];
    for (slot, pair) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let high = hex_value(pair[0]).ok_or(VerifyFailure::Usage)?;
        let low = hex_value(pair[1]).ok_or(VerifyFailure::Usage)?;
        *slot = (high << 4) | low;
    }
    IntegrityScrubContinuation::decode(&bytes).map_err(|_| VerifyFailure::Usage)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn failure_status(failure: OfflineIntegrityFailure) -> &'static str {
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

#[derive(Default)]
struct VerifyOptions {
    offline: bool,
    online: bool,
    config: Option<PathBuf>,
    overrides: Vec<(String, String)>,
    endpoint: Option<SocketAddr>,
    server_name: Option<String>,
    trust_file: Option<PathBuf>,
    allow_plaintext: bool,
    credential_stdin: bool,
    tenant: Option<String>,
    signal: Option<String>,
    shard: Option<u32>,
    expected_catalog_generation: Option<u64>,
    continuation: Option<String>,
}

impl VerifyOptions {
    fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, VerifyFailure> {
        let mut result = Self::default();
        let mut arguments = arguments;
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--offline" if !result.offline && !result.online => result.offline = true,
                "--online" if !result.online && !result.offline => result.online = true,
                "--allow-plaintext" if !result.allow_plaintext => result.allow_plaintext = true,
                "--credential-stdin" if !result.credential_stdin => result.credential_stdin = true,
                "--config" if result.config.is_none() => {
                    result.config =
                        Some(PathBuf::from(arguments.next().ok_or(VerifyFailure::Usage)?));
                },
                "--set" => {
                    let value = arguments.next().ok_or(VerifyFailure::Usage)?;
                    let (path, value) = value.split_once('=').ok_or(VerifyFailure::Usage)?;
                    result.overrides.push((path.to_owned(), value.to_owned()));
                },
                "--endpoint" if result.endpoint.is_none() => {
                    result.endpoint = Some(
                        arguments
                            .next()
                            .ok_or(VerifyFailure::Usage)?
                            .parse()
                            .map_err(|_| VerifyFailure::Usage)?,
                    );
                },
                "--server-name" if result.server_name.is_none() => {
                    result.server_name = Some(arguments.next().ok_or(VerifyFailure::Usage)?);
                },
                "--trust-file" if result.trust_file.is_none() => {
                    result.trust_file =
                        Some(PathBuf::from(arguments.next().ok_or(VerifyFailure::Usage)?));
                },
                "--tenant" if result.tenant.is_none() => {
                    result.tenant = Some(arguments.next().ok_or(VerifyFailure::Usage)?);
                },
                "--signal" if result.signal.is_none() => {
                    result.signal = Some(arguments.next().ok_or(VerifyFailure::Usage)?);
                },
                "--shard" if result.shard.is_none() => {
                    result.shard = Some(
                        arguments
                            .next()
                            .ok_or(VerifyFailure::Usage)?
                            .parse()
                            .map_err(|_| VerifyFailure::Usage)?,
                    );
                },
                "--expected-catalog-generation" if result.expected_catalog_generation.is_none() => {
                    result.expected_catalog_generation = Some(
                        arguments
                            .next()
                            .ok_or(VerifyFailure::Usage)?
                            .parse()
                            .map_err(|_| VerifyFailure::Usage)?,
                    );
                },
                "--continuation" if result.continuation.is_none() => {
                    result.continuation = Some(arguments.next().ok_or(VerifyFailure::Usage)?);
                },
                _ => return Err(VerifyFailure::Usage),
            }
        }
        if !result.offline && !result.online {
            return Err(VerifyFailure::Usage);
        }
        if result.offline
            && (result.endpoint.is_some()
                || result.server_name.is_some()
                || result.trust_file.is_some()
                || result.allow_plaintext
                || result.expected_catalog_generation.is_some())
        {
            return Err(VerifyFailure::Usage);
        }
        if result.offline
            && result.continuation.is_some()
            && (result.tenant.is_none() || result.signal.is_none() || result.shard.is_none())
        {
            return Err(VerifyFailure::Usage);
        }
        if result.offline
            && result.continuation.is_none()
            && (result.tenant.is_some() || result.signal.is_some() || result.shard.is_some())
        {
            return Err(VerifyFailure::Usage);
        }
        if result.online
            && (result.config.is_some()
                || !result.overrides.is_empty()
                || !result.credential_stdin
                || result.tenant.is_none()
                || result.signal.is_none()
                || result.shard.is_none()
                || result
                    .continuation
                    .as_ref()
                    .is_some_and(|_| result.expected_catalog_generation.is_none()))
        {
            return Err(VerifyFailure::Usage);
        }
        Ok(result)
    }
}

#[derive(Clone, Copy, Debug)]
enum VerifyFailure {
    Usage,
    Configuration,
}

impl VerifyFailure {
    const fn status(self) -> &'static str {
        match self {
            Self::Usage => "invalid_arguments",
            Self::Configuration => "configuration_rejected",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use positron_api::maintenance::OnlineVerificationReport;

    use super::{VerifyFailure, VerifyOptions, online_request, selected_mode};

    #[test]
    fn failure_mode_preserves_the_selected_online_path() {
        assert_eq!(selected_mode(&["--online".to_owned()]), "online");
        assert_eq!(selected_mode(&["--offline".to_owned()]), "offline");
        assert_eq!(selected_mode(&[]), "usage");
        assert_eq!(
            selected_mode(&["--online".to_owned(), "--offline".to_owned()]),
            "usage"
        );
    }

    #[test]
    fn offline_arguments_require_explicit_mode_and_accept_configuration_overrides() {
        let options = VerifyOptions::parse(
            [
                "--offline".to_owned(),
                "--config".to_owned(),
                "positron.toml".to_owned(),
                "--set".to_owned(),
                "runtime.max_registered_tenants=4".to_owned(),
            ]
            .into_iter(),
        )
        .expect("offline CLI arguments");
        assert!(options.offline);
        assert_eq!(
            options.config.as_deref().and_then(|path| path.to_str()),
            Some("positron.toml")
        );
        assert_eq!(
            options.overrides,
            [("runtime.max_registered_tenants".to_owned(), "4".to_owned())]
        );
        assert!(matches!(
            VerifyOptions::parse(["--config".to_owned(), "x".to_owned()].into_iter()),
            Err(VerifyFailure::Usage)
        ));
    }

    #[test]
    fn offline_resume_requires_and_accepts_the_reported_scope_and_cursor() {
        let cursor = format!("01{}{}", "00".repeat(32), "01".repeat(16));
        let options = VerifyOptions::parse(
            [
                "--offline".to_owned(),
                "--tenant".to_owned(),
                "00000000-0000-0000-0000-000000000001".to_owned(),
                "--signal".to_owned(),
                "logs".to_owned(),
                "--shard".to_owned(),
                "1".to_owned(),
                "--continuation".to_owned(),
                cursor,
            ]
            .into_iter(),
        )
        .expect("offline resume arguments");
        assert!(options.offline);
        assert!(options.continuation.is_some());
        assert!(
            VerifyOptions::parse(
                [
                    "--offline".to_owned(),
                    "--continuation".to_owned(),
                    "01".repeat(56),
                ]
                .into_iter(),
            )
            .is_err()
        );
    }

    #[test]
    fn online_arguments_require_a_piped_credential_and_an_explicit_scope() {
        let options = VerifyOptions::parse(
            [
                "--online".to_owned(),
                "--credential-stdin".to_owned(),
                "--endpoint".to_owned(),
                "127.0.0.1:9443".to_owned(),
                "--allow-plaintext".to_owned(),
                "--tenant".to_owned(),
                "00000000-0000-0000-0000-000000000001".to_owned(),
                "--signal".to_owned(),
                "logs".to_owned(),
                "--shard".to_owned(),
                "1".to_owned(),
            ]
            .into_iter(),
        )
        .expect("online CLI arguments");
        assert!(options.online);
        assert!(options.credential_stdin);
        assert!(options.allow_plaintext);
        assert!(matches!(
            VerifyOptions::parse(
                [
                    "--online".to_owned(),
                    "--endpoint".to_owned(),
                    "127.0.0.1:9443".to_owned(),
                    "--allow-plaintext".to_owned(),
                    "--tenant".to_owned(),
                    "00000000-0000-0000-0000-000000000001".to_owned(),
                    "--signal".to_owned(),
                    "logs".to_owned(),
                    "--shard".to_owned(),
                    "1".to_owned(),
                ]
                .into_iter(),
            ),
            Err(VerifyFailure::Usage)
        ));
    }

    #[test]
    fn online_cli_renders_the_authenticated_machine_report_and_never_promotes_partial_work()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = listener.local_addr()?;
        let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
            let (mut stream, _) = listener.accept()?;
            let mut request = [0_u8; 4096];
            let read = stream.read(&mut request)?;
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.starts_with("POST /v1/maintenance:verify HTTP/1.1\r\n"));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("authorization: bearer administration-secret")
            );
            let mut report = OnlineVerificationReport {
                report_version: 1,
                tenant: "00000000-0000-0000-0000-000000000001".to_owned(),
                signal: "logs".to_owned(),
                shard: 1,
                catalog_generation: 7,
                examined_segments: 1,
                examined_bytes: 42,
                omitted_segments: 0,
                outcome: "verified".to_owned(),
                verification_complete: true,
                report_checksum: String::new(),
                continuation: None,
                findings: Vec::new(),
            };
            report.report_checksum = report.checksum();
            let body = String::from_utf8(
                report
                    .encode()
                    .map_err(|_| std::io::Error::other("report"))?,
            )
            .map_err(std::io::Error::other)?;
            stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
        });
        let options = VerifyOptions::parse(
            [
                "--online".to_owned(),
                "--credential-stdin".to_owned(),
                "--endpoint".to_owned(),
                endpoint.to_string(),
                "--allow-plaintext".to_owned(),
                "--tenant".to_owned(),
                "00000000-0000-0000-0000-000000000001".to_owned(),
                "--signal".to_owned(),
                "logs".to_owned(),
                "--shard".to_owned(),
                "1".to_owned(),
            ]
            .into_iter(),
        )
        .map_err(|failure| format!("parse online options: {}", failure.status()))?;
        let request = positron_api::maintenance::OnlineVerificationRequest::new(
            "00000000-0000-0000-0000-000000000001".to_owned(),
            "logs".to_owned(),
            1,
            None,
            None,
        );
        let (exit, output) = online_request(&options, "administration-secret", &request)
            .map_err(|failure| format!("online request: {}", failure.status()))?;
        assert_eq!(exit, std::process::ExitCode::SUCCESS);
        assert!(output.contains(
            "report_version=1\nmode=online\nstatus=verified\nverification_complete=true\n"
        ));
        server.join().map_err(|_| "server panicked")??;
        Ok(())
    }

    #[test]
    fn hexadecimal_identity_rendering_is_fixed_and_machine_parseable() {
        assert_eq!(super::hex(&[0, 10, 255]), "000aff");
    }
}
