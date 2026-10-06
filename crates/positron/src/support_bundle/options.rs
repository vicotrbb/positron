use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use super::privacy::IdentifierRetention;
use super::{
    DEFAULT_ELAPSED_LIMIT, DEFAULT_LOG_WINDOW, DEFAULT_OUTPUT_LIMIT, DEFAULT_SOURCE_FILES,
    EXIT_FAILURE, EXIT_USAGE, MAX_OUTPUT_LIMIT, TAR_RECORD,
};

/// Validated command-line choices for one bounded support-bundle invocation.
pub(crate) struct BundleOptions {
    pub(super) config: PathBuf,
    pub(super) output: PathBuf,
    pub(super) recipients: Vec<String>,
    pub(super) plaintext_warning: bool,
    pub(super) offline_key_unavailable: bool,
    pub(super) output_limit: usize,
    pub(super) elapsed_limit: Duration,
    pub(super) log_window: Duration,
    pub(super) source_file_limit: usize,
    pub(super) control_path: Option<PathBuf>,
    pub(super) identifier_retention: IdentifierRetention,
}

impl BundleOptions {
    pub(crate) fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, BundleFailure> {
        let mut arguments = arguments;
        if arguments.next().as_deref() != Some("bundle")
            || arguments.next().as_deref() != Some("create")
        {
            return Err(BundleFailure::Arguments);
        }
        let mut config = None;
        let mut output = None;
        let mut recipients = Vec::new();
        let mut plaintext_warning = false;
        let mut offline_key_unavailable = false;
        let mut credential_stdin = false;
        let mut output_limit = DEFAULT_OUTPUT_LIMIT;
        let mut elapsed_limit = DEFAULT_ELAPSED_LIMIT;
        let mut log_window = DEFAULT_LOG_WINDOW;
        let mut source_file_limit = DEFAULT_SOURCE_FILES;
        let mut control_path = None;
        let mut identifier_retention = IdentifierRetention::Ephemeral;
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--config" if config.is_none() => {
                    config = Some(PathBuf::from(
                        arguments.next().ok_or(BundleFailure::Arguments)?,
                    ))
                },
                "--output" if output.is_none() => {
                    output = Some(PathBuf::from(
                        arguments.next().ok_or(BundleFailure::Arguments)?,
                    ))
                },
                "--recipient" if recipients.len() < 16 => {
                    recipients.push(arguments.next().ok_or(BundleFailure::Arguments)?)
                },
                "--allow-plaintext-bundle" if !plaintext_warning => plaintext_warning = true,
                "--offline-key-unavailable" if !offline_key_unavailable => {
                    offline_key_unavailable = true
                },
                "--credential-stdin" if !credential_stdin => credential_stdin = true,
                "--control-path" if control_path.is_none() => {
                    control_path = Some(PathBuf::from(
                        arguments.next().ok_or(BundleFailure::Arguments)?,
                    ))
                },
                "--retain-identifier" if identifier_retention == IdentifierRetention::Ephemeral => {
                    identifier_retention = IdentifierRetention::parse(
                        &arguments.next().ok_or(BundleFailure::Arguments)?,
                    )
                    .map_err(|_| BundleFailure::Arguments)?;
                },
                "--max-output-bytes" => {
                    output_limit = arguments
                        .next()
                        .ok_or(BundleFailure::Arguments)?
                        .parse()
                        .map_err(|_| BundleFailure::Arguments)?
                },
                "--max-elapsed-seconds" => {
                    elapsed_limit = Duration::from_secs(
                        arguments
                            .next()
                            .ok_or(BundleFailure::Arguments)?
                            .parse()
                            .map_err(|_| BundleFailure::Arguments)?,
                    )
                },
                "--log-window-seconds" => {
                    log_window = Duration::from_secs(
                        arguments
                            .next()
                            .ok_or(BundleFailure::Arguments)?
                            .parse()
                            .map_err(|_| BundleFailure::Arguments)?,
                    )
                },
                "--max-source-files" => {
                    source_file_limit = arguments
                        .next()
                        .ok_or(BundleFailure::Arguments)?
                        .parse()
                        .map_err(|_| BundleFailure::Arguments)?
                },
                _ => return Err(BundleFailure::Arguments),
            }
        }
        let config = config.ok_or(BundleFailure::Arguments)?;
        let output = output.ok_or(BundleFailure::Arguments)?;
        if !(TAR_RECORD..=MAX_OUTPUT_LIMIT).contains(&output_limit) {
            return Err(BundleFailure::OutputLimitExceeded);
        }
        if (control_path.is_some() || credential_stdin || !offline_key_unavailable)
            && (!credential_stdin || offline_key_unavailable)
            || log_window.is_zero()
            || source_file_limit == 0
            || (plaintext_warning && !recipients.is_empty())
            || (!plaintext_warning && recipients.is_empty())
            || (offline_key_unavailable && identifier_retention != IdentifierRetention::Ephemeral)
        {
            return Err(BundleFailure::Arguments);
        }
        Ok(Self {
            config,
            output,
            recipients,
            plaintext_warning,
            offline_key_unavailable,
            output_limit,
            elapsed_limit,
            log_window,
            source_file_limit,
            control_path,
            identifier_retention,
        })
    }

    pub(super) fn deadline_exceeded(&self, started: Instant) -> bool {
        self.elapsed_limit.is_zero() || started.elapsed() > self.elapsed_limit
    }

    pub(super) fn remaining_time(&self, started: Instant) -> Option<Duration> {
        (!self.deadline_exceeded(started))
            .then(|| self.elapsed_limit.checked_sub(started.elapsed()))
            .flatten()
            .filter(|remaining| !remaining.is_zero())
    }
}

/// Stable, renderable command failure; no source detail or credential escapes
/// the public CLI boundary.
#[derive(Clone, Copy)]
pub(crate) enum BundleFailure {
    Arguments,
    OutputLimitExceeded,
    AuthenticationRejected,
    InspectionUnavailable,
    OutputUnavailable,
    DeadlineExceeded,
}

impl BundleFailure {
    pub(super) const fn exit_code(self) -> u8 {
        match self {
            Self::Arguments | Self::OutputLimitExceeded => EXIT_USAGE,
            Self::AuthenticationRejected
            | Self::InspectionUnavailable
            | Self::OutputUnavailable
            | Self::DeadlineExceeded => EXIT_FAILURE,
        }
    }

    pub(super) const fn render(self) -> &'static str {
        match self {
            Self::Arguments => {
                "report_version=1\nstatus=invalid_arguments\nfinding_code=SUPPORT_BUNDLE_ARGUMENTS_INVALID\nseverity=error\n"
            },
            Self::OutputLimitExceeded => {
                "report_version=1\nstatus=output_limit_exceeded\nfinding_code=SUPPORT_BUNDLE_OUTPUT_LIMIT_EXCEEDED\nseverity=error\n"
            },
            Self::AuthenticationRejected => {
                "report_version=1\nstatus=authentication_rejected\nfinding_code=SUPPORT_BUNDLE_AUTHENTICATION_REJECTED\nseverity=error\n"
            },
            Self::InspectionUnavailable => {
                "report_version=1\nstatus=inspection_unavailable\nfinding_code=SUPPORT_BUNDLE_INSPECTION_UNAVAILABLE\nseverity=error\n"
            },
            Self::OutputUnavailable => {
                "report_version=1\nstatus=output_unavailable\nfinding_code=SUPPORT_BUNDLE_OUTPUT_UNAVAILABLE\nseverity=error\n"
            },
            Self::DeadlineExceeded => {
                "report_version=1\nstatus=deadline_exceeded\nfinding_code=SUPPORT_BUNDLE_DEADLINE_EXCEEDED\nseverity=error\n"
            },
        }
    }
}
