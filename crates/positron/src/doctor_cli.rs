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
    BootstrapPaths, OfflineDiskPressure, OfflineIntegrityAggregateOutcome, OfflineIntegrityFailure,
    OfflineIntegrityVerification, verify_offline_integrity,
};
use zeroize::Zeroizing;

mod offline;
mod online;
mod options;
mod report;

use offline::execute_offline;
use options::{DoctorFailure, Mode, Options};

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
        Mode::Online => online::execute(&options),
    }
}

#[cfg(test)]
mod tests;

/// Exercises the bounded untrusted Doctor response boundary without I/O.
#[cfg(fuzzing)]
pub(crate) fn fuzz_status(bytes: &[u8]) -> Option<String> {
    if bytes.len() > 8192 {
        return None;
    }
    let value = serde_json::from_slice(bytes).ok()?;
    report::render_status(&value).ok().map(|(_, report)| report)
}
