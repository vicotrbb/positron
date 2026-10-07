use std::{
    io::{IsTerminal, Read, Write},
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
use positron_kernel::{MountQualification, SegmentScope};
use positron_runtime::{
    BootstrapPaths, OfflineIntegrityAggregateOutcome, OfflineIntegrityContinuation,
    OfflineIntegrityFailure, resume_offline_integrity, verify_offline_integrity,
    verify_offline_integrity_scope,
};
use zeroize::Zeroizing;

const EXIT_CONFIGURATION: u8 = 2;
const EXIT_INTEGRITY: u8 = 3;

mod offline;
mod online;
mod options;
mod render;

use offline::{decode_offline_continuation, failure_status, offline_scope};
#[cfg(test)]
use online::online_request;
use options::{VerifyFailure, VerifyOptions};
use render::{hex, render_aggregate_evidence, render_finding, render_report};

#[doc(hidden)]
pub(super) fn fuzz_offline_continuation_hex(value: &str) {
    let _ = decode_offline_continuation(value);
}

pub(super) fn run(
    arguments: impl Iterator<Item = String>,
    environment: impl IntoIterator<Item = (String, String)>,
) -> ExitCode {
    let arguments = arguments.collect::<Vec<_>>();
    let selected_mode = selected_mode(&arguments);
    match execute(arguments.into_iter(), environment) {
        Ok((exit, output)) => {
            write_report(&output).map_or_else(|()| ExitCode::from(EXIT_INTEGRITY), |_| exit)
        },
        Err(failure) => {
            let report = format!(
                "mode={selected_mode}\nstatus={}\nverification_complete=false\n",
                failure.status()
            );
            write_report(&report).map_or_else(
                |()| ExitCode::from(EXIT_INTEGRITY),
                |_| ExitCode::from(EXIT_CONFIGURATION),
            )
        },
    }
}

fn write_report(report: &str) -> Result<(), ()> {
    let stdout = std::io::stdout();
    let mut locked = stdout.lock();
    locked.write_all(report.as_bytes()).map_err(|_| ())?;
    locked.flush().map_err(|_| ())
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
        return online::execute_online(&options);
    }
    let offline_scope =
        (options.tenant.is_some() || options.signal.is_some() || options.shard.is_some())
            .then(|| offline_scope(&options))
            .transpose()?;
    let offline_resume = options
        .continuation
        .as_deref()
        .map(decode_offline_continuation)
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
        Some(continuation) => {
            resume_offline_integrity(&paths, effective.max_registered_tenants(), continuation)
        },
        None if offline_scope.is_some() => verify_offline_integrity_scope(
            &paths,
            effective.max_registered_tenants(),
            offline_scope.ok_or(VerifyFailure::Usage)?,
        ),
        None => verify_offline_integrity(&paths, effective.max_registered_tenants()),
    };
    match offline {
        Ok(report) => {
            let status = offline_status(report.aggregate_outcome());
            let mut output = format!(
                "mode=offline\nstatus={status}\naggregate_outcome={status}\nverification_complete={}\nreport_count={}\naggregate_scope=all_reachable\naggregate_catalog_generation={}\naggregate_covered_scopes={}\naggregate_reachable_scopes={}\naggregate_examined_segments={}\naggregate_examined_bytes={}\naggregate_omitted_segments={}\naggregate_evidence_count={}\n",
                report.is_complete(),
                report.reports().len(),
                report.facts().catalog_generation(),
                report.aggregate_evidence().len(),
                report.facts().reachable_scope_count(),
                report.examined_segments(),
                report.examined_bytes(),
                report.omitted_segments(),
                report.aggregate_evidence().len(),
            );
            for item in report.reports() {
                output.push_str(&render_report(*item));
            }
            for evidence in report.aggregate_evidence() {
                output.push_str(&render_aggregate_evidence(*evidence));
            }
            if let Some(continuation) = report.continuation() {
                output.push_str(&format!(
                    "aggregate_continuation={}\n",
                    hex(continuation.encoded())
                ));
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

const fn offline_status(outcome: OfflineIntegrityAggregateOutcome) -> &'static str {
    match outcome {
        OfflineIntegrityAggregateOutcome::Verified => "verified",
        OfflineIntegrityAggregateOutcome::Incomplete => "incomplete",
        OfflineIntegrityAggregateOutcome::Quarantined => "quarantined",
        OfflineIntegrityAggregateOutcome::Fenced => "fenced",
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use positron_api::maintenance::OnlineVerificationReport;
    use positron_runtime::OfflineIntegrityAggregateOutcome;

    use super::{VerifyFailure, VerifyOptions, offline_status, online_request, selected_mode};

    #[test]
    fn offline_aggregate_status_preserves_quarantine_and_fence_distinctions() {
        assert_eq!(
            offline_status(OfflineIntegrityAggregateOutcome::Quarantined),
            "quarantined"
        );
        assert_eq!(
            offline_status(OfflineIntegrityAggregateOutcome::Fenced),
            "fenced"
        );
        assert_eq!(
            offline_status(OfflineIntegrityAggregateOutcome::Incomplete),
            "incomplete"
        );
    }

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
            ["--offline".to_owned(), "--continuation".to_owned(), cursor].into_iter(),
        )
        .expect("offline resume arguments");
        assert!(options.offline);
        assert!(options.continuation.is_some());
        assert!(
            VerifyOptions::parse(
                [
                    "--offline".to_owned(),
                    "--tenant".to_owned(),
                    "00000000-0000-0000-0000-000000000001".to_owned(),
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
