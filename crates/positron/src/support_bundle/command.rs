use sha2::{Digest, Sha256};
use std::{
    io::{self, IsTerminal, Read, Write},
    path::Path,
    process::ExitCode,
    time::Instant,
};

use positron_config::{ConfigurationInputs, resolve};
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_kernel::{
    DiskPressureState, MountQualification, ResourceAmounts, ResourceSnapshot, WorkClaim,
};
use positron_runtime::{BootstrapPaths, DoctorRuntimeFacts, InstanceBootstrap};
use zeroize::Zeroizing;

use super::archive::{encode_bytes, hex};
use super::live_control;
use super::privacy::IdentifierRetention;
use super::{
    AgeRecipients, BundleLimits, BundleMember, EXIT_FAILURE, ManifestAuthentication, SupportBundle,
    output, privacy,
};
use super::{BundleFailure, BundleOptions};

#[path = "bundle_evidence.rs"]
mod evidence;
#[path = "bundle_inspection.rs"]
mod inspection;
#[path = "bundle_publication.rs"]
mod publication;

#[cfg(test)]
pub(crate) use evidence::COMPATIBILITY_INPUTS;
use evidence::owned_bundle_doctor_report;
pub(crate) use evidence::{
    canonical_members_with_crash, compatibility_manifest_evidence, diagnostics_claim,
    product_identity_evidence,
};
use evidence::{key_unavailable_doctor_report, offline_operational_status};
use inspection::authenticated_inspection;
use publication::publication_failure;
pub(crate) use publication::write_bundle;
#[cfg(test)]
pub(crate) use publication::write_bundle_with_after_publication_hook;
#[cfg(test)]
pub(crate) use publication::write_plaintext_bundle_with_after_close_hook;

pub(crate) fn run(
    arguments: impl Iterator<Item = String>,
    environment: impl IntoIterator<Item = (String, String)>,
) -> ExitCode {
    match execute(arguments, environment) {
        Ok(report) => write_report(&report)
            .map_or_else(|()| ExitCode::from(EXIT_FAILURE), |_| ExitCode::SUCCESS),
        Err(failure) => write_report(failure.render()).map_or_else(
            |()| ExitCode::from(EXIT_FAILURE),
            |_| ExitCode::from(failure.exit_code()),
        ),
    }
}

fn write_report(report: &str) -> Result<(), ()> {
    let stdout = io::stdout();
    let mut locked = stdout.lock();
    locked.write_all(report.as_bytes()).map_err(|_| ())?;
    locked.flush().map_err(|_| ())
}

pub(crate) const fn online_bundle_report() -> &'static str {
    "report_version=1\nstatus=created\nformat=age_encrypted_opaque_bundle\nmode=online\nencryption=age_x25519\nartifact_authentication=unverified_control_response\nsignature=unverified\nplaintext_export_warning=false\n"
}

fn execute(
    arguments: impl Iterator<Item = String>,
    environment: impl IntoIterator<Item = (String, String)>,
) -> Result<String, BundleFailure> {
    let options = BundleOptions::parse(arguments)?;
    let started = Instant::now();
    let inputs = ConfigurationInputs::try_from_sources(
        Some(options.config.as_path()),
        environment,
        Vec::<(String, String)>::new(),
    )
    .map_err(|_| BundleFailure::Arguments)?;
    let effective = resolve(inputs).map_err(|_| BundleFailure::Arguments)?;
    let paths = BootstrapPaths::with_local_key(
        Path::new(effective.data_directory()),
        Path::new(effective.secrets_directory()),
        effective.local_key_file().as_path(),
        MountQualification::LocalHost,
    )
    .map_err(|_| BundleFailure::InspectionUnavailable)?;
    let output_destination = output::prepare_destination(
        &options.output,
        Path::new(effective.data_directory()),
        Path::new(effective.secrets_directory()),
    )
    .map_err(|_| BundleFailure::Arguments)?;
    let limits = BundleLimits::new(14, options.output_limit)
        .map_err(|_| BundleFailure::Arguments)?
        .with_elapsed_limit(options.elapsed_limit);
    if let Some(control_path) = options.control_path.as_deref() {
        let ciphertext = live_control::request_live_bundle(control_path, &options, started)?;
        output::write_new_owner_only_before_publication(&output_destination, &ciphertext, || {
            !options.deadline_exceeded(started)
        })
        .map_err(publication_failure)?;
        return Ok(online_bundle_report().to_owned());
    }
    let bundle = if options.offline_key_unavailable {
        InstanceBootstrap::with_offline_key_unavailable_diagnostics(
            &paths,
            effective.max_registered_tenants(),
            diagnostics_claim(options.output_limit)?,
            |crash_records| {
                let report = key_unavailable_doctor_report();
                let operational = offline_operational_status(report);
                let crash = crash_records
                    .read_recent(
                        options.log_window,
                        options.source_file_limit,
                        options.output_limit / 4,
                        std::time::SystemTime::now(),
                    )
                    .map_err(|_| BundleFailure::InspectionUnavailable)?;
                let members = canonical_members_with_crash(
                    &effective,
                    report,
                    &operational,
                    &options,
                    started,
                    crash,
                )?;
                let bundle = if options.plaintext_warning {
                    SupportBundle::build_authenticated_for_explicit_plaintext_with_retention(
                        members,
                        limits,
                        ManifestAuthentication::UnsignedKeyUnavailableOffline,
                        options.identifier_retention,
                    )
                } else {
                    SupportBundle::build_authenticated_with_retention(
                        members,
                        limits,
                        ManifestAuthentication::UnsignedKeyUnavailableOffline,
                        options.identifier_retention,
                    )
                }
                .map_err(|_| BundleFailure::OutputUnavailable)?;
                write_bundle(&bundle, &options, &output_destination, started)?;
                Ok(bundle)
            },
        )
        .map_err(|_| BundleFailure::InspectionUnavailable)??
    } else {
        authenticated_inspection(
            &paths,
            options.output_limit,
            |signer, operational, report, crash_records| {
                let crash = crash_records
                    .read_recent(
                        options.log_window,
                        options.source_file_limit,
                        options.output_limit / 4,
                        std::time::SystemTime::now(),
                    )
                    .map_err(|_| BundleFailure::InspectionUnavailable)?;
                let members = canonical_members_with_crash(
                    &effective,
                    &report,
                    &operational,
                    &options,
                    started,
                    crash,
                )?;
                let bundle = if options.plaintext_warning {
                    SupportBundle::build_authenticated_for_explicit_plaintext_with_retention(
                        members,
                        limits,
                        ManifestAuthentication::Signed(&signer),
                        options.identifier_retention,
                    )
                } else {
                    SupportBundle::build_authenticated_with_retention(
                        members,
                        limits,
                        ManifestAuthentication::Signed(&signer),
                        options.identifier_retention,
                    )
                }
                .map_err(|_| BundleFailure::OutputUnavailable)?;
                write_bundle(&bundle, &options, &output_destination, started)?;
                Ok(bundle)
            },
        )?
    };
    let redaction = bundle.redaction_report();
    Ok(format!(
        "report_version=1\nstatus=created\nformat=positron-support-bundle-tar-v1\nencryption={}\nsignature={}\nplaintext_export_warning={}\nincluded_member_count={}\nredaction_omission_count={}\nexcluded_unknown_members={}\n",
        if options.plaintext_warning {
            "plaintext_explicit"
        } else {
            "age_x25519"
        },
        if options.offline_key_unavailable {
            "unsigned_key_unavailable_offline"
        } else {
            "signed"
        },
        redaction.plaintext_warning(),
        bundle.included_member_count(),
        redaction.declared_omissions().len(),
        redaction.excluded_unknown_members(),
    ))
}
