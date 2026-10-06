use std::{path::Path, time::Duration};

mod archive;
mod command;
mod crash_record;
mod crypto;
mod live_control;
mod output;
mod privacy;

use archive::Class;
pub(crate) use archive::{
    AgeRecipients, BundleLimits, BundleMember, ManifestAuthentication, SupportBundle,
};
pub(crate) use command::run;
use command::{BundleFailure, BundleOptions};
pub(crate) use command::{canonical_members, diagnostics_claim};
#[cfg(test)]
use command::{write_bundle, write_bundle_with_after_publication_hook};
pub(crate) use live_control::LiveSupportBundleCollector;

const POLICY: u16 = 1;
const BLOCK: usize = 512;
const FOOTER: usize = 1024;
const TAR_RECORD: usize = 10_240;
const DEFAULT_OUTPUT_LIMIT: usize = 1_048_576;
const DEFAULT_ELAPSED_LIMIT: Duration = Duration::from_secs(30);
const DEFAULT_LOG_WINDOW: Duration = Duration::from_secs(300);
const DEFAULT_SOURCE_FILES: usize = 32;
const EXIT_USAGE: u8 = 2;
const EXIT_FAILURE: u8 = 3;

/// Records one typed terminal process failure for later bounded support
/// inspection. Callers pass only fixed product vocabulary, never an error
/// message, address, request, or backtrace.
#[cfg(test)]
pub(crate) fn capture_process_failure(
    data_directory: &Path,
    phase: &'static str,
    finding_code: &'static str,
    component: &'static str,
) -> Result<(), ()> {
    let record = crash_record::SanitizedCrashRecord::new(phase, finding_code, component)?;
    crash_record::CrashRecordStore::under_data_directory(data_directory).persist(&record)
}

pub(crate) fn capture_process_failure_with_catalog_generation(
    data_directory: &Path,
    phase: &'static str,
    finding_code: &'static str,
    component: &'static str,
    catalog_generation: Option<u64>,
) -> Result<(), ()> {
    let record = crash_record::SanitizedCrashRecord::new(phase, finding_code, component)?;
    let record = match catalog_generation {
        Some(value) => record.with_catalog_generation(value),
        None => record,
    }
    .with_backtrace(&std::backtrace::Backtrace::capture());
    crash_record::CrashRecordStore::under_data_directory(data_directory).persist(&record)
}

#[cfg(test)]
mod tests;
