#[cfg(test)]
use std::path::Path;
use std::time::Duration;

mod archive;
mod command;
mod crash_record;
mod crypto;
mod live_control;
mod options;
mod output;
mod privacy;

use archive::Class;
pub(crate) use archive::{
    AgeRecipients, BundleLimits, BundleMember, ManifestAuthentication, SupportBundle,
};
pub(crate) use command::run;
pub(crate) use command::{canonical_members_with_crash, diagnostics_claim};
#[cfg(test)]
use command::{
    write_bundle, write_bundle_with_after_publication_hook,
    write_plaintext_bundle_with_after_close_hook,
};
pub(crate) use live_control::LiveSupportBundleCollector;
use options::{BundleFailure, BundleOptions};

const POLICY: u16 = 1;
const BLOCK: usize = 512;
const FOOTER: usize = 1024;
const TAR_RECORD: usize = 10_240;
const DEFAULT_OUTPUT_LIMIT: usize = 1_048_576;
/// The signed live collector, bounded archive verifier, and resource claim all
/// use this one transport ceiling. CLI input must not exceed it.
const MAX_OUTPUT_LIMIT: usize = DEFAULT_OUTPUT_LIMIT;
const DEFAULT_ELAPSED_LIMIT: Duration = Duration::from_secs(30);
const DEFAULT_LOG_WINDOW: Duration = Duration::from_secs(300);
const DEFAULT_SOURCE_FILES: usize = 32;
const EXIT_USAGE: u8 = 2;
const EXIT_FAILURE: u8 = 3;

/// Records one typed terminal process failure for later bounded support
/// inspection. Callers pass only fixed product vocabulary, never an error
/// message, address, request, or backtrace.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn capture_process_failure(
    data_directory: &Path,
    phase: &'static str,
    finding_code: &'static str,
    component: &'static str,
) -> Result<(), ()> {
    let record =
        crash_record::SanitizedCrashRecord::new(phase, finding_code, component).map_err(|_| ())?;
    crash_record::CrashRecordStore::under_data_directory(data_directory)?.persist(&record)
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn capture_process_failure_with_catalog_generation(
    data_directory: &Path,
    phase: &'static str,
    finding_code: &'static str,
    component: &'static str,
    catalog_generation: Option<u64>,
) -> Result<(), ()> {
    let record =
        crash_record::SanitizedCrashRecord::new(phase, finding_code, component).map_err(|_| ())?;
    let record = match catalog_generation {
        Some(value) => record.with_catalog_generation(value),
        None => record,
    }
    .with_backtrace(&std::backtrace::Backtrace::capture());
    crash_record::CrashRecordStore::under_data_directory(data_directory)?.persist(&record)
}

/// Bounded public fuzz seam for the unauthenticated Control request body.
/// A successfully parsed request must preserve its exact typed recipients and
/// explicit retention choice through the canonical encoder and parser.
#[doc(hidden)]
#[allow(dead_code, reason = "called by the external cargo-fuzz target")]
pub fn fuzz_live_bundle_request(bytes: &[u8]) {
    let Ok(request) = live_control::LiveBundleRequest::parse(bytes) else {
        return;
    };
    let Ok(encoded) = live_control::LiveBundleRequest::encode_with_retention(
        &request.recipients,
        request.identifier_retention,
    ) else {
        panic!("accepted live support-bundle request must re-encode");
    };
    let Ok(round_trip) = live_control::LiveBundleRequest::parse(&encoded) else {
        panic!("encoded live support-bundle request must re-parse");
    };
    assert_eq!(round_trip, request);
}

/// Bounded fuzz seam for support-bundle CLI token parsing. This is separate
/// from the Control request parser because user-provided command arguments
/// govern output allocation before any live transport is contacted.
#[doc(hidden)]
#[allow(dead_code, reason = "called by the external cargo-fuzz target")]
pub fn fuzz_support_bundle_options(bytes: &[u8]) {
    let mut arguments = vec![
        "bundle".to_owned(),
        "create".to_owned(),
        "--config".to_owned(),
        "positron.toml".to_owned(),
        "--output".to_owned(),
        "bundle.age".to_owned(),
        "--allow-plaintext-bundle".to_owned(),
        "--credential-stdin".to_owned(),
    ];
    arguments.extend(
        bytes
            .split(|byte| *byte == 0)
            .take(32)
            .map(|token| String::from_utf8_lossy(&token[..token.len().min(1_024)]).into_owned()),
    );
    let _ = BundleOptions::parse(arguments.into_iter());
    let impossible = [
        "bundle",
        "create",
        "--config",
        "positron.toml",
        "--output",
        "bundle.age",
        "--allow-plaintext-bundle",
        "--credential-stdin",
        "--max-output-bytes",
        &usize::MAX.to_string(),
    ];
    if BundleOptions::parse(impossible.into_iter().map(str::to_owned)).is_ok() {
        panic!("an impossible output allocation limit must be rejected");
    }
}

#[cfg(test)]
mod tests;
