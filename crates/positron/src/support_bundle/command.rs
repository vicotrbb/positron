use sha2::{Digest, Sha256};
use std::{
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, Instant},
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
    AgeRecipients, BundleLimits, BundleMember, DEFAULT_ELAPSED_LIMIT, DEFAULT_LOG_WINDOW,
    DEFAULT_OUTPUT_LIMIT, DEFAULT_SOURCE_FILES, EXIT_FAILURE, EXIT_USAGE, ManifestAuthentication,
    SupportBundle, TAR_RECORD, crash_record, output, privacy,
};

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
        return Ok(
            "report_version=1\nstatus=created\nformat=positron-support-bundle-tar-v1\nmode=online\nencryption=age_x25519\nsignature=signed\nplaintext_export_warning=false\n".to_owned(),
        );
    }
    let bundle = if options.offline_key_unavailable {
        InstanceBootstrap::with_offline_key_unavailable_diagnostics(
            &paths,
            effective.max_registered_tenants(),
            diagnostics_claim(options.output_limit)?,
            || {
                let report = key_unavailable_doctor_report();
                let operational = offline_operational_status(report);
                let members =
                    canonical_members(&effective, report, &operational, &options, started)?;
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
            |signer, operational, report| {
                let members =
                    canonical_members(&effective, &report, &operational, &options, started)?;
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

pub(crate) fn write_bundle(
    bundle: &SupportBundle,
    options: &BundleOptions,
    output_destination: &output::OutputDestination,
    started: Instant,
) -> Result<(), BundleFailure> {
    write_bundle_after_publication(bundle, options, output_destination, started, || {})
}

#[cfg(test)]
pub(crate) fn write_bundle_with_after_publication_hook(
    bundle: &SupportBundle,
    options: &BundleOptions,
    output_destination: &output::OutputDestination,
    started: Instant,
    after_publication: impl FnOnce(),
) -> Result<(), BundleFailure> {
    write_bundle_after_publication(
        bundle,
        options,
        output_destination,
        started,
        after_publication,
    )
}

#[cfg(test)]
pub(super) fn write_plaintext_bundle_with_after_close_hook(
    bundle: &SupportBundle,
    options: &BundleOptions,
    output_destination: &output::OutputDestination,
    started: Instant,
    after_close: impl FnOnce(),
) -> Result<(), BundleFailure> {
    if options.deadline_exceeded(started) {
        return Err(BundleFailure::DeadlineExceeded);
    }
    bundle
        .write_plaintext_explicitly_with_after_close_deadline_hook(
            output_destination,
            after_close,
            || !options.deadline_exceeded(started),
        )
        .map_err(publication_failure)
}

fn write_bundle_after_publication(
    bundle: &SupportBundle,
    options: &BundleOptions,
    output_destination: &output::OutputDestination,
    started: Instant,
    after_publication: impl FnOnce(),
) -> Result<(), BundleFailure> {
    if options.deadline_exceeded(started) {
        return Err(BundleFailure::DeadlineExceeded);
    }
    if options.plaintext_warning {
        if options.deadline_exceeded(started) {
            return Err(BundleFailure::DeadlineExceeded);
        }
        bundle
            .write_plaintext_explicitly_before_publication(output_destination, || {
                !options.deadline_exceeded(started)
            })
            .map_err(publication_failure)?;
    } else {
        let recipients = AgeRecipients::parse(options.recipients.clone())
            .map_err(|_| BundleFailure::Arguments)?;
        let ciphertext = recipients
            .encrypt_bounded(bundle.archive(), options.output_limit)
            .map_err(|_| BundleFailure::OutputUnavailable)?;
        if options.deadline_exceeded(started) {
            return Err(BundleFailure::DeadlineExceeded);
        }
        bundle
            .write_encrypted_before_publication(output_destination, &ciphertext, || {
                !options.deadline_exceeded(started)
            })
            .map_err(publication_failure)?;
    }
    after_publication();
    Ok(())
}

fn publication_failure(failure: output::PublicationFailure) -> BundleFailure {
    match failure {
        output::PublicationFailure::Unavailable => BundleFailure::OutputUnavailable,
        output::PublicationFailure::DeadlineExceeded => BundleFailure::DeadlineExceeded,
    }
}

fn offline_operational_status(report: &str) -> String {
    let finding = report
        .lines()
        .find_map(|line| line.strip_prefix("finding_code="))
        .map_or("DOCTOR_OFFLINE_INSPECTION_UNAVAILABLE", |finding| finding);
    format!(
        "inspection_mode=offline\noperations_runtime_state=not_observable_offline\nevidence_scope=exclusive_primary_data_volume_ownership\nintegrity_finding={finding}\n"
    )
}

/// Builds every Release-1 diagnostic family from an authoritative, read-only
/// source. The unavailable log owner is represented as an explicit typed
/// omission, never as a synthetic log line or a scrape of process memory.
pub(crate) fn canonical_members(
    effective: &positron_config::EffectiveConfiguration,
    doctor: &str,
    operational: &str,
    options: &BundleOptions,
    started: Instant,
) -> Result<Vec<BundleMember>, BundleFailure> {
    if options.deadline_exceeded(started) {
        return Err(BundleFailure::DeadlineExceeded);
    }
    let pseudonyms = privacy::Pseudonymizer::new();
    let data_directory = match options.identifier_retention {
        IdentifierRetention::Ephemeral => pseudonyms
            .pseudonymize(effective.data_directory())
            .map_err(|_| BundleFailure::OutputUnavailable)?,
        IdentifierRetention::DataDirectory => effective.data_directory().to_owned(),
    };
    let secrets_directory = pseudonyms
        .pseudonymize(effective.secrets_directory())
        .map_err(|_| BundleFailure::OutputUnavailable)?;
    let configuration = effective
        .redacted_effective()
        .replace(effective.data_directory(), &data_directory)
        .replace(effective.secrets_directory(), &secrets_directory);
    let crash =
        crash_record::CrashRecordStore::under_data_directory(Path::new(effective.data_directory()))
            .read_recent(
                options.log_window,
                options.source_file_limit,
                options.output_limit / 4,
                std::time::SystemTime::now(),
            )
            .map_err(|_| BundleFailure::InspectionUnavailable)?;
    if options.deadline_exceeded(started) {
        return Err(BundleFailure::DeadlineExceeded);
    }
    let metadata = std::fs::metadata(effective.data_directory()).ok();
    let data_directory_metadata_bytes = metadata.map_or(0, |value| value.len());
    let config_digest =
        hex(configuration.as_bytes()).map_err(|_| BundleFailure::OutputUnavailable)?;
    let health = format!(
        "inspection_owner=offline_doctor\nhealth_runtime_state=not_observable_offline\nlatest_finding={}\n",
        finding_code(doctor),
    );
    let catalog =
        format!("inspection_owner=offline_doctor\nconfiguration_digest={config_digest}\n{doctor}");
    let resource = format!("inspection_owner=offline_doctor\n{doctor}");
    let maintenance = "inspection_owner=maintenance_runtime\navailability=not_observable_offline\nevidence_scope=exclusive_primary_data_volume_ownership\nsafe_command=start_positron_for_maintenance_status\n";
    let listeners = "inspection_owner=listener_runtime\navailability=not_observable_offline\nevidence_scope=exclusive_primary_data_volume_ownership\nsafe_command=start_positron_for_listener_status\n";
    let backup = report_field(doctor, "backup_repository").map_or_else(
        || "inspection_owner=authenticated_catalog_backup_binding\navailability=not_observable_offline\nevidence_scope=exclusive_primary_data_volume_ownership\nsafe_command=inspect_backup_configuration_when_available\n".to_owned(),
        |value| format!("inspection_owner=authenticated_catalog_backup_binding\nbackup_repository={value}\nevidence_scope=authenticated_catalog_snapshot\nsafe_command=configure_backup_repository\n"),
    );
    Ok(vec![
        BundleMember::effective_configuration(configuration.as_bytes()),
        BundleMember::compatibility_manifest(
            compatibility_manifest_evidence()
                .map_err(|_| BundleFailure::OutputUnavailable)?
                .as_bytes(),
        ),
        BundleMember::product_identity(
            product_identity_evidence()
                .map_err(|_| BundleFailure::OutputUnavailable)?
                .as_bytes(),
        ),
        BundleMember::health_state(health.as_bytes()),
        BundleMember::operational_telemetry(operational.as_bytes()),
        BundleMember::operational_logs_with_omission(b"inspection_owner=operational_log_runtime\navailability=not_persisted\n", "operational_log_owner_unavailable"),
        BundleMember::catalog_summary(catalog.as_bytes()),
        BundleMember::resource_status(resource.as_bytes()),
        BundleMember::maintenance_status(maintenance.as_bytes()),
        BundleMember::listener_status(listeners.as_bytes()),
        BundleMember::backup_repository_status(backup.as_bytes()),
        BundleMember::environment(format!("os={}\narch={}\ndata_directory_identity={}\ndata_directory_metadata_bytes={data_directory_metadata_bytes}\n", std::env::consts::OS, std::env::consts::ARCH, data_directory).as_bytes()),
        BundleMember::doctor_report(doctor.as_bytes()),
        BundleMember::sanitized_crash_records_with_omissions(crash.render().as_bytes(), crash.omissions()),
    ])
}

const COMPATIBILITY_INPUTS_SCOPE: &str = "Cargo.lock,Cargo.toml,crates/positron/Cargo.toml,api/positron/v1/positron.proto,api/positron/v1/http.json,configuration/schema.json";
pub(crate) const COMPATIBILITY_INPUTS: [(&str, &[u8]); 6] = [
    ("Cargo.lock", include_bytes!("../../../../Cargo.lock")),
    ("Cargo.toml", include_bytes!("../../../../Cargo.toml")),
    (
        "crates/positron/Cargo.toml",
        include_bytes!("../../Cargo.toml"),
    ),
    (
        "api/positron/v1/positron.proto",
        include_bytes!("../../../../api/positron/v1/positron.proto"),
    ),
    (
        "api/positron/v1/http.json",
        include_bytes!("../../../../api/positron/v1/http.json"),
    ),
    (
        "configuration/schema.json",
        include_bytes!("../../../../configuration/schema.json"),
    ),
];

/// Locally reproducible compatibility evidence for exactly the declared six
/// inputs. It is not a complete source-tree or release-build identity.
pub(crate) fn compatibility_manifest_evidence() -> Result<String, ()> {
    let schema_digest = positron_api::generated::SchemaDigest::canonical().as_str();
    let configuration_schema_digest = hex(include_bytes!("../../../../configuration/schema.json"))?;
    let compatibility_inputs_sha256 = compatibility_inputs_sha256()?;
    Ok(format!(
        "compatibility_manifest_version=1\nproduct=positron\nproduct_version={}\napi_package=positron.v1\napi_schema_digest={schema_digest}\nconfiguration_schema_digest={configuration_schema_digest}\nstorage_catalog_readable_format_epochs={},{}\nstorage_catalog_writable_format_epochs={},{}\nquery_contract=not_shipped\nreceiver_contract=not_shipped\ncrd_contract=not_shipped\noperator_contract=not_shipped\nbackup_contract=not_shipped\nmigration_graph=not_shipped\ncompatibility_inputs_sha256={compatibility_inputs_sha256}\ncompatibility_inputs_scope={COMPATIBILITY_INPUTS_SCOPE}\nsource_build_state=not_captured\nsource_build_evidence_scope=unavailable\nsource_build_evidence_owner=release_pipeline\n",
        env!("CARGO_PKG_VERSION"),
        positron_kernel::FormatEpoch::CATALOG_V1.value(),
        positron_kernel::FormatEpoch::CATALOG_V2.value(),
        positron_kernel::FormatEpoch::CATALOG_V1.value(),
        positron_kernel::FormatEpoch::CATALOG_V2.value(),
    ))
}

/// Product identity states the unavailable source-build provenance owner
/// instead of inferring it from compatibility inputs.
pub(crate) fn product_identity_evidence() -> Result<String, ()> {
    let compatibility_inputs_sha256 = compatibility_inputs_sha256()?;
    Ok(format!(
        "product=positron\nproduct_version={}\nproduct_identity_source=workspace_package\napi_package=positron.v1\nschema_digest={}\ncatalog_writable_format_epochs={},{}\ncompatibility_inputs_sha256={compatibility_inputs_sha256}\ncompatibility_inputs_scope={COMPATIBILITY_INPUTS_SCOPE}\nsource_build_state=not_captured\nsource_build_evidence_scope=unavailable\nsource_build_evidence_owner=release_pipeline\n",
        env!("CARGO_PKG_VERSION"),
        positron_api::generated::SchemaDigest::canonical().as_str(),
        positron_kernel::FormatEpoch::CATALOG_V1.value(),
        positron_kernel::FormatEpoch::CATALOG_V2.value(),
    ))
}

fn compatibility_inputs_sha256() -> Result<String, ()> {
    let mut digest = Sha256::new();
    for (scope, bytes) in COMPATIBILITY_INPUTS {
        digest.update(scope.as_bytes());
        digest.update([0]);
        digest.update(u64::try_from(bytes.len()).map_err(|_| ())?.to_be_bytes());
        digest.update(bytes);
    }
    encode_bytes(&digest.finalize())
}

fn finding_code(report: &str) -> &str {
    report
        .lines()
        .find_map(|line| line.strip_prefix("finding_code="))
        .unwrap_or("DOCTOR_REPORT_UNAVAILABLE")
}

fn report_field<'a>(report: &'a str, key: &str) -> Option<&'a str> {
    report.lines().find_map(|line| {
        line.strip_prefix(key)
            .and_then(|value| value.strip_prefix('='))
    })
}

/// A signed bundle already holds the sole Storage Kernel authority through
/// `InstanceBootstrap::reopen`. Re-acquiring it for the CLI's standalone
/// offline verifier would manufacture a storage-lock failure, so this report
/// uses only the already-opened authenticated bootstrap, Catalog, and
/// governor authorities.
fn owned_bundle_doctor_report(facts: DoctorRuntimeFacts, resources: ResourceSnapshot) -> String {
    let pressure = match resources.disk_pressure() {
        DiskPressureState::Healthy => "healthy",
        DiskPressureState::SoftPressure => "soft",
        DiskPressureState::HardPressure => "hard",
    };
    let verified = facts.key_custody_verified() && facts.catalog_bootstrap_verified();
    let mut report = format!(
        "report_version=1\nmode=offline_owned_bundle\nstatus=inspection_partial\nfinding_code=DOCTOR_BUNDLE_OWNER_VERIFIED\nseverity={}\nevidence_scope=exclusive_primary_data_volume_ownership\nkey_custody={}\ncatalog_bootstrap={}\ncatalog_generation={}\nsafe_command={}\n",
        if verified { "info" } else { "error" },
        if facts.key_custody_verified() {
            "verified"
        } else {
            "unavailable"
        },
        if facts.catalog_bootstrap_verified() {
            "verified"
        } else {
            "unavailable"
        },
        facts.catalog_generation(),
        if verified {
            "none"
        } else {
            "inspect_storage_without_mutation"
        },
    );
    report.push_str("finding_code=DOCTOR_CONFIGURATION_RESOLVED\nseverity=info\nevidence_scope=effective_configuration\nsafe_command=none\n");
    report.push_str("finding_code=DOCTOR_INTEGRITY_FRONTIERS_UNAVAILABLE_OWNED_BUNDLE\nseverity=info\nevidence_scope=offline_integrity_verifier\ninspection_state=not_run_while_bundle_ownership_is_held\nsafe_command=positron_doctor_offline_after_bundle\n");
    report.push_str(&format!("finding_code=DOCTOR_STORAGE_CAPACITY_OBSERVED\nseverity=info\nevidence_scope=temporary_offline_resource_authority\nusable_disk_bytes={}\ndisk_pressure={pressure}\nsafe_command=none\n", resources.usable_disk_bytes()));
    report.push_str("finding_code=DOCTOR_GOVERNOR_RUNTIME_UNAVAILABLE_OFFLINE\nseverity=info\nevidence_scope=runtime_resource_governor\nruntime_state=not_observable_offline\nsafe_command=start_positron_for_live_governor_status\n");
    for (code, owner, command) in [
        (
            "DOCTOR_MAINTENANCE_RUNTIME_UNAVAILABLE_OFFLINE",
            "maintenance_runtime",
            "start_positron_for_maintenance_status",
        ),
        (
            "DOCTOR_OPERATIONS_LEASES_UNAVAILABLE_OFFLINE",
            "durable_operation_runtime",
            "start_positron_for_operations_status",
        ),
        (
            "DOCTOR_LISTENERS_UNAVAILABLE_OFFLINE",
            "listener_runtime",
            "start_positron_for_listener_status",
        ),
        (
            "DOCTOR_HEALTH_UNAVAILABLE_OFFLINE",
            "process_health_runtime",
            "start_positron_for_process_health",
        ),
    ] {
        report.push_str(&format!("finding_code={code}\nseverity=info\nevidence_scope={owner}\nruntime_state=not_observable_offline\nsafe_command={command}\n"));
    }
    let backup = facts.backup_repository().label();
    report.push_str(&format!("finding_code=DOCTOR_BACKUP_REPOSITORY_NOT_CONFIGURED\nseverity=warning\nevidence_scope=authenticated_catalog_backup_binding\nbackup_repository={backup}\nsafe_command=configure_backup_repository\n"));
    report
}

const fn key_unavailable_doctor_report() -> &'static str {
    "report_version=1\nmode=offline\nstatus=key_unavailable\nfinding_code=DOCTOR_KEY_UNAVAILABLE\nseverity=error\nevidence_scope=primary_data_volume\n"
}

pub(crate) fn diagnostics_claim(output_limit: usize) -> Result<WorkClaim, BundleFailure> {
    let bounded_bytes = u64::try_from(output_limit)
        .ok()
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or(BundleFailure::Arguments)?;
    WorkClaim::system_diagnostics(ResourceAmounts::new([
        bounded_bytes,
        0,
        1,
        0,
        0,
        0,
        0,
        1,
        1,
        1,
        0,
    ]))
    .map_err(|_| BundleFailure::Arguments)
}

fn authenticated_inspection<T>(
    paths: &BootstrapPaths,
    output_limit: usize,
    collect: impl FnOnce(
        positron_kernel::ExportManifestSigner,
        String,
        String,
    ) -> Result<T, BundleFailure>,
) -> Result<T, BundleFailure> {
    let input = io::stdin();
    if input.is_terminal() {
        return Err(BundleFailure::Arguments);
    }
    let mut credential = Zeroizing::new(String::new());
    input
        .take(1025)
        .read_to_string(&mut credential)
        .map_err(|_| BundleFailure::AuthenticationRejected)?;
    let bearer = credential.trim_end_matches(['\r', '\n']);
    if credential.len() > 1024 || bearer.is_empty() {
        return Err(BundleFailure::Arguments);
    }
    let credential =
        PresentedCredential::parse(bearer).map_err(|_| BundleFailure::AuthenticationRejected)?;
    let instance =
        InstanceBootstrap::reopen(paths).map_err(|_| BundleFailure::InspectionUnavailable)?;
    let actor = instance
        .attribute(
            credential,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
        .map_err(|_| BundleFailure::AuthenticationRejected)?;
    let reservation = instance
        .resource_governor()
        .reserve(diagnostics_claim(output_limit)?)
        .map_err(|_| BundleFailure::InspectionUnavailable)?;
    let facts = instance
        .doctor_runtime_facts(actor)
        .map_err(|_| BundleFailure::InspectionUnavailable)?;
    let owned_report = owned_bundle_doctor_report(
        facts,
        instance
            .resource_governor()
            .inspect()
            .map_err(|_| BundleFailure::InspectionUnavailable)?,
    );
    let signer = instance
        .support_bundle_manifest_signer(actor)
        .map_err(|_| BundleFailure::InspectionUnavailable)?;
    let operational = format!(
        "inspection_mode=offline\nkey_custody={}\ncatalog_bootstrap={}\ncatalog_generation={}\nbackup_repository={}\n",
        if facts.key_custody_verified() {
            "verified"
        } else {
            "unavailable"
        },
        if facts.catalog_bootstrap_verified() {
            "verified"
        } else {
            "unavailable"
        },
        facts.catalog_generation(),
        facts.backup_repository().label(),
    );
    let collected = collect(signer, operational, owned_report);
    drop(reservation);
    collected
}

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
                    .map_err(|_| BundleFailure::Arguments)?
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
                    );
                },
                "--log-window-seconds" => {
                    log_window = Duration::from_secs(
                        arguments
                            .next()
                            .ok_or(BundleFailure::Arguments)?
                            .parse()
                            .map_err(|_| BundleFailure::Arguments)?,
                    );
                },
                "--max-source-files" => {
                    source_file_limit = arguments
                        .next()
                        .ok_or(BundleFailure::Arguments)?
                        .parse()
                        .map_err(|_| BundleFailure::Arguments)?;
                },
                _ => return Err(BundleFailure::Arguments),
            }
        }
        let config = config.ok_or(BundleFailure::Arguments)?;
        let output = output.ok_or(BundleFailure::Arguments)?;
        if (control_path.is_some() || credential_stdin || !offline_key_unavailable)
            && (!credential_stdin || offline_key_unavailable)
            || output_limit < TAR_RECORD
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

    fn deadline_exceeded(&self, started: Instant) -> bool {
        self.elapsed_limit.is_zero() || started.elapsed() > self.elapsed_limit
    }

    pub(super) fn remaining_time(&self, started: Instant) -> Option<Duration> {
        (!self.deadline_exceeded(started))
            .then(|| self.elapsed_limit.checked_sub(started.elapsed()))
            .flatten()
            .filter(|remaining| !remaining.is_zero())
    }
}

#[derive(Clone, Copy)]
pub(crate) enum BundleFailure {
    Arguments,
    AuthenticationRejected,
    InspectionUnavailable,
    OutputUnavailable,
    DeadlineExceeded,
}
impl BundleFailure {
    const fn exit_code(self) -> u8 {
        match self {
            Self::Arguments => EXIT_USAGE,
            Self::AuthenticationRejected
            | Self::InspectionUnavailable
            | Self::OutputUnavailable => EXIT_FAILURE,
            Self::DeadlineExceeded => EXIT_FAILURE,
        }
    }
    const fn render(self) -> &'static str {
        match self {
            Self::Arguments => {
                "report_version=1\nstatus=invalid_arguments\nfinding_code=SUPPORT_BUNDLE_ARGUMENTS_INVALID\nseverity=error\n"
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
