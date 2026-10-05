use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use positron_config::{ConfigurationInputs, resolve};
use positron_kernel::MountQualification;
use positron_runtime::{BootstrapPaths, OfflineIntegrityFailure, verify_offline_integrity};

const EXIT_CONFIGURATION: u8 = 2;
const EXIT_INTEGRITY: u8 = 3;

pub(super) fn run(
    arguments: impl Iterator<Item = String>,
    environment: impl IntoIterator<Item = (String, String)>,
) -> ExitCode {
    match execute(arguments, environment) {
        Ok((exit, output)) => {
            print!("{output}");
            exit
        },
        Err(failure) => {
            print!(
                "mode=offline\nstatus={}\nverification_complete=false\n",
                failure.status()
            );
            ExitCode::from(EXIT_CONFIGURATION)
        },
    }
}

fn execute(
    arguments: impl Iterator<Item = String>,
    environment: impl IntoIterator<Item = (String, String)>,
) -> Result<(ExitCode, String), VerifyFailure> {
    let options = VerifyOptions::parse(arguments)?;
    if !options.offline {
        return Err(VerifyFailure::Usage);
    }
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
    match verify_offline_integrity(&paths, effective.max_registered_tenants()) {
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
    format!(
        "report_scope_tenant={} report_scope_signal={signal} report_scope_shard={} catalog_generation={} examined_segments={} examined_bytes={} omitted_segments={} outcome={outcome} quarantined_segment={quarantined}\n",
        scope.tenant_id(),
        scope.shard_id().value(),
        report.catalog_generation(),
        report.examined_segments(),
        report.examined_bytes(),
        report.omitted_segments(),
    )
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

fn failure_status(failure: OfflineIntegrityFailure) -> &'static str {
    match failure {
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
    config: Option<PathBuf>,
    overrides: Vec<(String, String)>,
}

impl VerifyOptions {
    fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, VerifyFailure> {
        let mut result = Self::default();
        let mut arguments = arguments;
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--offline" if !result.offline => result.offline = true,
                "--config" if result.config.is_none() => {
                    result.config =
                        Some(PathBuf::from(arguments.next().ok_or(VerifyFailure::Usage)?));
                },
                "--set" => {
                    let value = arguments.next().ok_or(VerifyFailure::Usage)?;
                    let (path, value) = value.split_once('=').ok_or(VerifyFailure::Usage)?;
                    result.overrides.push((path.to_owned(), value.to_owned()));
                },
                _ => return Err(VerifyFailure::Usage),
            }
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
    use super::VerifyOptions;

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
        assert!(
            !VerifyOptions::parse(["--config".to_owned(), "x".to_owned()].into_iter())
                .expect("parse without mode")
                .offline
        );
    }

    #[test]
    fn hexadecimal_identity_rendering_is_fixed_and_machine_parseable() {
        assert_eq!(super::hex(&[0, 10, 255]), "000aff");
    }
}
