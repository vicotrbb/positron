use sha2::{Digest, Sha256};
use std::{
    io::{self, IsTerminal, Read},
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, Instant},
};

use positron_config::{ConfigurationInputs, resolve};
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_kernel::{MountQualification, ResourceAmounts, WorkClaim};
use positron_runtime::{
    BootstrapPaths, InstanceBootstrap, OfflineIntegrityFailure, verify_offline_integrity,
};
use zeroize::Zeroizing;

mod crash_record;
mod crypto;
mod output;
mod privacy;

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

pub(super) fn run(
    arguments: impl Iterator<Item = String>,
    environment: impl IntoIterator<Item = (String, String)>,
) -> ExitCode {
    match execute(arguments, environment) {
        Ok(report) => {
            print!("{report}");
            ExitCode::SUCCESS
        },
        Err(failure) => {
            print!("{}", failure.render());
            ExitCode::from(failure.exit_code())
        },
    }
}

fn execute(
    arguments: impl Iterator<Item = String>,
    environment: impl IntoIterator<Item = (String, String)>,
) -> Result<String, BundleFailure> {
    let options = BundleOptions::parse(arguments)?;
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
    let limits =
        BundleLimits::new(14, options.output_limit).map_err(|_| BundleFailure::Arguments)?;
    let started = Instant::now();
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
                    SupportBundle::build_authenticated_for_explicit_plaintext(
                        members,
                        limits,
                        ManifestAuthentication::UnsignedKeyUnavailableOffline,
                    )
                } else {
                    SupportBundle::build_authenticated(
                        members,
                        limits,
                        ManifestAuthentication::UnsignedKeyUnavailableOffline,
                    )
                }
                .map_err(|_| BundleFailure::OutputUnavailable)?;
                write_bundle(&bundle, &options, started)?;
                Ok(bundle)
            },
        )
        .map_err(|_| BundleFailure::InspectionUnavailable)??
    } else {
        authenticated_inspection(&paths, options.output_limit, |signer, operational| {
            let report = offline_doctor_report(&paths, effective.max_registered_tenants());
            let members = canonical_members(&effective, &report, &operational, &options, started)?;
            let bundle = if options.plaintext_warning {
                SupportBundle::build_authenticated_for_explicit_plaintext(
                    members,
                    limits,
                    ManifestAuthentication::Signed(&signer),
                )
            } else {
                SupportBundle::build_authenticated(
                    members,
                    limits,
                    ManifestAuthentication::Signed(&signer),
                )
            }
            .map_err(|_| BundleFailure::OutputUnavailable)?;
            write_bundle(&bundle, &options, started)?;
            Ok(bundle)
        })?
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

fn write_bundle(
    bundle: &SupportBundle,
    options: &BundleOptions,
    started: Instant,
) -> Result<(), BundleFailure> {
    if options.deadline_exceeded(started) {
        return Err(BundleFailure::DeadlineExceeded);
    }
    if options.plaintext_warning {
        bundle
            .write_plaintext_explicitly(&options.output)
            .map_err(|_| BundleFailure::OutputUnavailable)?;
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
            .write_encrypted(&options.output, &ciphertext)
            .map_err(|_| BundleFailure::OutputUnavailable)?;
    }
    if options.deadline_exceeded(started) {
        return Err(BundleFailure::DeadlineExceeded);
    }
    Ok(())
}

fn offline_operational_status(report: &str) -> String {
    let finding = report
        .lines()
        .find_map(|line| line.strip_prefix("finding_code="))
        .map_or("DOCTOR_OFFLINE_INSPECTION_UNAVAILABLE", |finding| finding);
    format!(
        "inspection_mode=offline\noperations=offline_not_running\nintegrity_finding={finding}\n"
    )
}

/// Builds every Release-1 diagnostic family from an authoritative, read-only
/// source. The unavailable log owner is represented as an explicit typed
/// omission, never as a synthetic log line or a scrape of process memory.
fn canonical_members(
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
    let data_directory = pseudonyms.pseudonymize(effective.data_directory());
    let secrets_directory = pseudonyms.pseudonymize(effective.secrets_directory());
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
    let bytes = metadata.map_or(0, |value| value.len());
    let config_digest = hex(configuration.as_bytes());
    Ok(vec![
        BundleMember::effective_configuration(configuration.as_bytes()),
        BundleMember::compatibility_manifest(b"schema_version=1\ncompatibility_manifest=unavailable\n"),
        BundleMember::product_identity(format!("product=positron\nversion={}\napi_identity=unavailable\nformat_epoch=unavailable\n", env!("CARGO_PKG_VERSION")).as_bytes()),
        BundleMember::health_state(format!("doctor_finding={}\n", finding_code(doctor)).as_bytes()),
        BundleMember::operational_telemetry(operational.as_bytes()),
        BundleMember::operational_logs_with_omission(b"availability=not_persisted\n", "operational_log_owner_unavailable"),
        BundleMember::catalog_summary(format!("configuration_digest={config_digest}\ninspection_source=doctor\n").as_bytes()),
        BundleMember::resource_status(operational.as_bytes()),
        BundleMember::maintenance_status(operational.as_bytes()),
        BundleMember::listener_status(operational.as_bytes()),
        BundleMember::backup_repository_status(operational.as_bytes()),
        BundleMember::environment(format!("os={}\narch={}\ndata_directory_identity={}\ndata_directory_metadata_bytes={bytes}\n", std::env::consts::OS, std::env::consts::ARCH, data_directory).as_bytes()),
        BundleMember::doctor_report(doctor.as_bytes()),
        BundleMember::sanitized_crash_records_with_omissions(crash.render().as_bytes(), crash.omissions()),
    ])
}

fn finding_code(report: &str) -> &str {
    report
        .lines()
        .find_map(|line| line.strip_prefix("finding_code="))
        .unwrap_or("DOCTOR_REPORT_UNAVAILABLE")
}

fn offline_doctor_report(paths: &BootstrapPaths, maximum_tenants: u16) -> String {
    match verify_offline_integrity(paths, maximum_tenants) {
        Ok(report) if report.is_verified() => {
            "report_version=1\nmode=offline\nstatus=healthy\nfinding_code=DOCTOR_INTEGRITY_VERIFIED\nseverity=info\nevidence_scope=primary_data_volume\n".to_owned()
        },
        Ok(_) => "report_version=1\nmode=offline\nstatus=fenced\nfinding_code=DOCTOR_INTEGRITY_FENCED\nseverity=error\nevidence_scope=primary_data_volume\n".to_owned(),
        Err(failure) => format!(
            "report_version=1\nmode=offline\nstatus={}\nfinding_code={}\nseverity=error\nevidence_scope=primary_data_volume\n",
            match failure {
                OfflineIntegrityFailure::OwnershipLocked => "storage_locked",
                OfflineIntegrityFailure::BootstrapUnavailable => "bootstrap_unavailable",
                OfflineIntegrityFailure::KeyUnavailable => "key_unavailable",
                OfflineIntegrityFailure::CatalogUnavailable => "catalog_busy",
                OfflineIntegrityFailure::CorruptState => "fenced",
                OfflineIntegrityFailure::CapacityUnavailable => "capacity_unavailable",
                OfflineIntegrityFailure::StorageUnavailable => "storage_unavailable",
            },
            match failure {
                OfflineIntegrityFailure::OwnershipLocked => "DOCTOR_STORAGE_LOCKED",
                OfflineIntegrityFailure::BootstrapUnavailable => "DOCTOR_BOOTSTRAP_UNAVAILABLE",
                OfflineIntegrityFailure::KeyUnavailable => "DOCTOR_KEY_UNAVAILABLE",
                OfflineIntegrityFailure::CatalogUnavailable => "DOCTOR_CATALOG_BUSY",
                OfflineIntegrityFailure::CorruptState => "DOCTOR_INTEGRITY_FENCED",
                OfflineIntegrityFailure::CapacityUnavailable => "DOCTOR_CAPACITY_UNAVAILABLE",
                OfflineIntegrityFailure::StorageUnavailable => "DOCTOR_STORAGE_UNAVAILABLE",
            },
        ),
    }
}

const fn key_unavailable_doctor_report() -> &'static str {
    "report_version=1\nmode=offline\nstatus=key_unavailable\nfinding_code=DOCTOR_KEY_UNAVAILABLE\nseverity=error\nevidence_scope=primary_data_volume\n"
}

fn diagnostics_claim(output_limit: usize) -> Result<WorkClaim, BundleFailure> {
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
    collect: impl FnOnce(positron_kernel::ExportManifestSigner, String) -> Result<T, BundleFailure>,
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
    let collected = collect(signer, operational);
    drop(reservation);
    collected
}

struct BundleOptions {
    config: PathBuf,
    output: PathBuf,
    recipients: Vec<String>,
    plaintext_warning: bool,
    offline_key_unavailable: bool,
    output_limit: usize,
    elapsed_limit: Duration,
    log_window: Duration,
    source_file_limit: usize,
}

impl BundleOptions {
    fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, BundleFailure> {
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
        if (!offline_key_unavailable && !credential_stdin)
            || (offline_key_unavailable && credential_stdin)
            || output_limit < TAR_RECORD
            || log_window.is_zero()
            || source_file_limit == 0
            || (plaintext_warning && !recipients.is_empty())
            || (!plaintext_warning && recipients.is_empty())
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
        })
    }

    fn deadline_exceeded(&self, started: Instant) -> bool {
        self.elapsed_limit.is_zero() || started.elapsed() > self.elapsed_limit
    }
}

#[derive(Clone, Copy)]
enum BundleFailure {
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

#[derive(Clone, Copy)]
enum Class {
    EffectiveConfiguration,
    CompatibilityManifest,
    ProductIdentity,
    HealthState,
    OperationalTelemetry,
    OperationalLogs,
    CatalogSummary,
    ResourceStatus,
    MaintenanceStatus,
    ListenerStatus,
    BackupRepositoryStatus,
    Environment,
    Doctor,
    CrashRecords,
}
impl Class {
    const fn path(self) -> &'static str {
        match self {
            Self::EffectiveConfiguration => "effective-configuration.txt",
            Self::CompatibilityManifest => "compatibility-manifest.txt",
            Self::ProductIdentity => "product-identity.txt",
            Self::HealthState => "health-state.txt",
            Self::OperationalTelemetry => "operational-telemetry.txt",
            Self::OperationalLogs => "operational-logs.txt",
            Self::CatalogSummary => "catalog-summary.txt",
            Self::ResourceStatus => "resource-status.txt",
            Self::MaintenanceStatus => "maintenance-status.txt",
            Self::ListenerStatus => "listener-status.txt",
            Self::BackupRepositoryStatus => "backup-repository-status.txt",
            Self::Environment => "environment.txt",
            Self::Doctor => "doctor-report.txt",
            Self::CrashRecords => "sanitized-crash-records.txt",
        }
    }
}

/// Closed input: a caller cannot choose an archive name or classification.
pub(crate) struct BundleMember {
    class: Option<Class>,
    bytes: Vec<u8>,
    omissions: Vec<&'static str>,
}
impl BundleMember {
    fn typed(class: Class, bytes: &[u8]) -> Self {
        Self {
            class: Some(class),
            bytes: bytes.to_vec(),
            omissions: Vec::new(),
        }
    }
    pub(crate) fn effective_configuration(bytes: &[u8]) -> Self {
        Self::typed(Class::EffectiveConfiguration, bytes)
    }
    pub(crate) fn compatibility_manifest(bytes: &[u8]) -> Self {
        Self::typed(Class::CompatibilityManifest, bytes)
    }
    pub(crate) fn product_identity(bytes: &[u8]) -> Self {
        Self::typed(Class::ProductIdentity, bytes)
    }
    pub(crate) fn health_state(bytes: &[u8]) -> Self {
        Self::typed(Class::HealthState, bytes)
    }
    pub(crate) fn operational_telemetry(bytes: &[u8]) -> Self {
        Self::typed(Class::OperationalTelemetry, bytes)
    }
    pub(crate) fn operational_logs(bytes: &[u8]) -> Self {
        Self::typed(Class::OperationalLogs, bytes)
    }
    fn operational_logs_with_omission(bytes: &[u8], omission: &'static str) -> Self {
        let mut member = Self::operational_logs(bytes);
        member.omissions.push(omission);
        member
    }
    pub(crate) fn catalog_summary(bytes: &[u8]) -> Self {
        Self::typed(Class::CatalogSummary, bytes)
    }
    pub(crate) fn resource_status(bytes: &[u8]) -> Self {
        Self::typed(Class::ResourceStatus, bytes)
    }
    pub(crate) fn maintenance_status(bytes: &[u8]) -> Self {
        Self::typed(Class::MaintenanceStatus, bytes)
    }
    pub(crate) fn listener_status(bytes: &[u8]) -> Self {
        Self::typed(Class::ListenerStatus, bytes)
    }
    pub(crate) fn backup_repository_status(bytes: &[u8]) -> Self {
        Self::typed(Class::BackupRepositoryStatus, bytes)
    }
    pub(crate) fn environment(bytes: &[u8]) -> Self {
        Self::typed(Class::Environment, bytes)
    }
    pub(crate) fn doctor_report(bytes: &[u8]) -> Self {
        Self::typed(Class::Doctor, bytes)
    }
    pub(crate) fn sanitized_crash_records(bytes: &[u8]) -> Self {
        Self::typed(Class::CrashRecords, bytes)
    }
    fn sanitized_crash_records_with_omissions(bytes: &[u8], omissions: &[&'static str]) -> Self {
        let mut member = Self::sanitized_crash_records(bytes);
        member.omissions.extend_from_slice(omissions);
        member
    }
    #[cfg(test)]
    pub(crate) fn sanitized_crash_record(record: crash_record::SanitizedCrashRecord) -> Self {
        Self::sanitized_crash_records(record.render().as_bytes())
    }
    #[cfg(test)]
    pub(crate) fn unclassified(bytes: &[u8]) -> Self {
        Self {
            class: None,
            bytes: bytes.to_vec(),
            omissions: Vec::new(),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct BundleLimits {
    count: usize,
    bytes: usize,
}

/// Only native age v1 X25519 recipients are admitted. The bounded typed set
/// rejects passphrases, SSH recipients, plugins, and malformed input before
/// an archive is created.
pub(crate) struct AgeRecipients(Vec<age::x25519::Recipient>);

impl AgeRecipients {
    pub(crate) fn parse<I, S>(values: I) -> Result<Self, ()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut recipients = Vec::new();
        for value in values {
            if recipients.len() == 16 {
                return Err(());
            }
            recipients.push(value.as_ref().parse().map_err(|_| ())?);
        }
        (!recipients.is_empty())
            .then_some(Self(recipients))
            .ok_or(())
    }

    #[cfg(test)]
    pub(crate) fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, ()> {
        crypto::encrypt(&self.0, plaintext, usize::MAX)
    }
    pub(crate) fn encrypt_bounded(&self, plaintext: &[u8], limit: usize) -> Result<Vec<u8>, ()> {
        crypto::encrypt(&self.0, plaintext, limit)
    }
}
impl BundleLimits {
    pub(crate) fn new(count: usize, bytes: usize) -> Result<Self, ()> {
        (count > 0 && bytes >= TAR_RECORD)
            .then_some(Self { count, bytes })
            .ok_or(())
    }
}

pub(crate) struct RedactionReport {
    unknown: usize,
    omissions: Vec<&'static str>,
    plaintext_warning: bool,
}

pub(crate) enum ManifestAuthentication<'a> {
    Signed(&'a positron_kernel::ExportManifestSigner),
    UnsignedKeyUnavailableOffline,
}
impl RedactionReport {
    pub(crate) const fn excluded_unknown_members(&self) -> usize {
        self.unknown
    }
    pub(crate) fn declared_omissions(&self) -> &[&'static str] {
        &self.omissions
    }
    pub(crate) const fn plaintext_warning(&self) -> bool {
        self.plaintext_warning
    }
}

/// A standard ustar archive. Its manifest binds every admitted member and the
/// redaction report; the writer never receives raw unclassified input.
pub(crate) struct SupportBundle {
    archive: Vec<u8>,
    manifest: Vec<u8>,
    report: RedactionReport,
    count: usize,
    maximum_archive_bytes: usize,
}
impl SupportBundle {
    #[cfg(test)]
    pub(crate) fn build(
        input: impl IntoIterator<Item = BundleMember>,
        limits: BundleLimits,
    ) -> Result<Self, ()> {
        Self::build_with_plaintext_policy(input, limits, false, "not_applied")
    }
    #[cfg(test)]
    pub(crate) fn build_for_explicit_plaintext(
        input: impl IntoIterator<Item = BundleMember>,
        limits: BundleLimits,
    ) -> Result<Self, ()> {
        Self::build_with_plaintext_policy(input, limits, true, "not_applied")
    }
    pub(crate) fn build_authenticated(
        input: impl IntoIterator<Item = BundleMember>,
        limits: BundleLimits,
        authentication: ManifestAuthentication<'_>,
    ) -> Result<Self, ()> {
        match authentication {
            ManifestAuthentication::Signed(signer) => {
                let bundle = Self::build_with_plaintext_policy(input, limits, false, "signed")?;
                // The signature is over the canonical manifest bytes retained
                // in the standard tar archive; opaque signer custody remains
                // wholly in Runtime/Kernel.
                let manifest = bundle.manifest_bytes()?;
                let signature = signer.sign(&manifest).map_err(|_| ())?;
                bundle.attach_signature(signature)
            },
            ManifestAuthentication::UnsignedKeyUnavailableOffline => {
                Self::build_with_plaintext_policy(
                    input,
                    limits,
                    false,
                    "unsigned_key_unavailable_offline",
                )
            },
        }
    }
    pub(crate) fn build_authenticated_for_explicit_plaintext(
        input: impl IntoIterator<Item = BundleMember>,
        limits: BundleLimits,
        authentication: ManifestAuthentication<'_>,
    ) -> Result<Self, ()> {
        match authentication {
            ManifestAuthentication::Signed(signer) => {
                let bundle = Self::build_with_plaintext_policy(input, limits, true, "signed")?;
                let signature = signer.sign(&bundle.manifest_bytes()?).map_err(|_| ())?;
                bundle.attach_signature(signature)
            },
            ManifestAuthentication::UnsignedKeyUnavailableOffline => {
                Self::build_with_plaintext_policy(
                    input,
                    limits,
                    true,
                    "unsigned_key_unavailable_offline",
                )
            },
        }
    }
    fn build_with_plaintext_policy(
        input: impl IntoIterator<Item = BundleMember>,
        limits: BundleLimits,
        plaintext_warning: bool,
        signature_state: &'static str,
    ) -> Result<Self, ()> {
        let mut selected = Vec::new();
        let mut unknown = 0;
        let mut omissions = Vec::new();
        // Reserve two metadata members (manifest plus Redaction Report) before
        // admitting content. This makes the byte bound deterministic rather
        // than discovering metadata overflow after source selection.
        let mut projected = FOOTER.saturating_add(BLOCK.saturating_mul(4));
        for member in input {
            let Some(class) = member.class else {
                unknown += 1;
                continue;
            };
            for omission in member.omissions {
                once(&mut omissions, omission);
            }
            if selected.len() == limits.count {
                once(&mut omissions, "member_count_limit");
                continue;
            }
            let next = BLOCK + blocks(member.bytes.len());
            if projected.saturating_add(next) > limits.bytes {
                once(&mut omissions, "archive_byte_limit");
                continue;
            };
            projected += next;
            selected.push((class, member.bytes));
        }
        if unknown != 0 {
            once(&mut omissions, "unknown_member_class");
        }
        let report = RedactionReport {
            unknown,
            omissions,
            plaintext_warning,
        };
        let redaction = format!(
            "policy_version={POLICY}\nexcluded_unknown_members={}\nomissions={}\nencryption={}\nplaintext_export_warning={}\nsignature={signature_state}\n",
            report.unknown,
            report.omissions.join(","),
            if plaintext_warning {
                "plaintext_explicit"
            } else {
                "not_applied"
            },
            plaintext_warning
        );
        let mut manifest = format!(
            "format=positron-support-bundle-tar-v1\nredaction_policy_version={POLICY}\narchive_byte_limit={}\n",
            limits.bytes
        );
        for (class, bytes) in &selected {
            manifest.push_str(&format!(
                "member={} bytes={} sha256={}\n",
                class.path(),
                bytes.len(),
                hex(bytes)
            ));
        }
        manifest.push_str(&format!(
            "redaction_report_sha256={}\n",
            hex(redaction.as_bytes())
        ));
        let meta = (BLOCK + blocks(manifest.len())).saturating_add(BLOCK + blocks(redaction.len()));
        if projected.saturating_add(meta) > limits.bytes {
            return Err(());
        }
        let mut archive = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut archive);
            append(&mut tar, "manifest.txt", manifest.as_bytes()).map_err(|_| ())?;
            append(&mut tar, "redaction-report.txt", redaction.as_bytes()).map_err(|_| ())?;
            for (class, bytes) in &selected {
                append(&mut tar, class.path(), bytes).map_err(|_| ())?;
            }
            tar.finish().map_err(|_| ())?;
        }
        (archive.len() <= limits.bytes)
            .then_some(Self {
                archive,
                manifest: manifest.into_bytes(),
                report,
                count: selected.len(),
                maximum_archive_bytes: limits.bytes,
            })
            .ok_or(())
    }
    pub(crate) const fn included_member_count(&self) -> usize {
        self.count
    }
    pub(crate) fn redaction_report(&self) -> &RedactionReport {
        &self.report
    }
    pub(crate) fn archive(&self) -> &[u8] {
        &self.archive
    }
    /// Verifies the archive that is actually handed to an operator.  The
    /// signature authenticates the canonical manifest; every data member is
    /// then checked against that manifest before it can be trusted.
    #[cfg(test)]
    pub(crate) fn verify_signed_archive(
        archive: &[u8],
        expected: positron_kernel::BootstrapIntegrityIdentity,
    ) -> Result<(), ()> {
        const MAX_ARCHIVE: usize = 1_048_576;
        if archive.len() > MAX_ARCHIVE {
            return Err(());
        }
        let mut entries = tar::Archive::new(archive);
        let mut manifest = None;
        let mut signature = None;
        let mut members = Vec::new();
        for entry in entries.entries().map_err(|_| ())? {
            let entry = entry.map_err(|_| ())?;
            let path = entry.path().map_err(|_| ())?.into_owned();
            let path = path.to_str().ok_or(())?;
            if !matches!(
                path,
                "manifest.txt"
                    | "manifest-signature.txt"
                    | "redaction-report.txt"
                    | "effective-configuration.txt"
                    | "compatibility-manifest.txt"
                    | "product-identity.txt"
                    | "health-state.txt"
                    | "operational-telemetry.txt"
                    | "operational-logs.txt"
                    | "catalog-summary.txt"
                    | "resource-status.txt"
                    | "maintenance-status.txt"
                    | "listener-status.txt"
                    | "backup-repository-status.txt"
                    | "environment.txt"
                    | "doctor-report.txt"
                    | "sanitized-crash-records.txt"
            ) {
                return Err(());
            }
            let mut bytes = Vec::new();
            use std::io::Read as _;
            entry.take(42_496).read_to_end(&mut bytes).map_err(|_| ())?;
            match path {
                "manifest.txt" if manifest.is_none() => manifest = Some(bytes),
                "manifest-signature.txt" if signature.is_none() => signature = Some(bytes),
                "manifest.txt" | "manifest-signature.txt" => return Err(()),
                _ => members.push((path.to_owned(), bytes)),
            }
        }
        let manifest = manifest.ok_or(())?;
        let signature = signature.ok_or(())?;
        let signature = std::str::from_utf8(&signature).map_err(|_| ())?;
        let mut fields = signature.lines();
        let key = fields
            .next()
            .ok_or(())?
            .strip_prefix("integrity_identity=")
            .ok_or(())?;
        let bytes = fields
            .next()
            .ok_or(())?
            .strip_prefix("signature=")
            .ok_or(())?;
        if fields.next().is_some() || key != encode_bytes(&expected.public_key()) {
            return Err(());
        }
        let signature = positron_kernel::ExportManifestSignature::new(expected, decode_64(bytes)?)
            .map_err(|_| ())?;
        signature.verify(expected, &manifest).map_err(|_| ())?;
        for line in std::str::from_utf8(&manifest).map_err(|_| ())?.lines() {
            let Some(rest) = line.strip_prefix("member=") else {
                continue;
            };
            let mut fields = rest.split_whitespace();
            let path = fields.next().ok_or(())?;
            let count = fields
                .next()
                .and_then(|value| value.strip_prefix("bytes="))
                .ok_or(())?
                .parse::<usize>()
                .map_err(|_| ())?;
            let digest = fields
                .next()
                .and_then(|value| value.strip_prefix("sha256="))
                .ok_or(())?;
            if fields.next().is_some() {
                return Err(());
            }
            let actual = members
                .iter()
                .find(|(actual, _)| actual == path)
                .ok_or(())?;
            if actual.1.len() != count || digest != hex(&actual.1) {
                return Err(());
            }
        }
        Ok(())
    }
    fn manifest_bytes(&self) -> Result<Vec<u8>, ()> {
        Ok(self.manifest.clone())
    }
    fn attach_signature(
        mut self,
        signature: positron_kernel::ExportManifestSignature,
    ) -> Result<Self, ()> {
        let evidence = format!(
            "integrity_identity={}\nsignature={}\n",
            encode_bytes(&signature.integrity_identity().public_key()),
            encode_bytes(&signature.bytes())
        );
        let mut rebuilt = Vec::new();
        let mut source = tar::Archive::new(self.archive.as_slice());
        let entries = source.entries().map_err(|_| ())?;
        {
            let mut target = tar::Builder::new(&mut rebuilt);
            for entry in entries {
                let entry = entry.map_err(|_| ())?;
                let path = entry.path().map_err(|_| ())?.into_owned();
                let mut bytes = Vec::new();
                use std::io::Read as _;
                entry.take(42_496).read_to_end(&mut bytes).map_err(|_| ())?;
                append(&mut target, path.to_str().ok_or(())?, &bytes).map_err(|_| ())?;
            }
            append(&mut target, "manifest-signature.txt", evidence.as_bytes()).map_err(|_| ())?;
            target.finish().map_err(|_| ())?;
        }
        if rebuilt.len() > self.maximum_archive_bytes {
            return Err(());
        }
        self.archive = rebuilt;
        Ok(self)
    }

    pub(crate) fn write_plaintext_explicitly(&self, path: &std::path::Path) -> Result<(), ()> {
        output::write_new_owner_only(path, &self.archive)
    }
    pub(crate) fn write_encrypted(
        &self,
        path: &std::path::Path,
        ciphertext: &[u8],
    ) -> Result<(), ()> {
        output::write_new_owner_only(path, ciphertext)
    }
}
fn append(tar: &mut tar::Builder<&mut Vec<u8>>, path: &str, bytes: &[u8]) -> io::Result<()> {
    let mut h = tar::Header::new_ustar();
    h.set_size(u64::try_from(bytes.len()).map_err(|_| io::Error::other("large"))?);
    h.set_mode(0o600);
    h.set_mtime(0);
    h.set_uid(0);
    h.set_gid(0);
    h.set_cksum();
    tar.append_data(&mut h, path, bytes)
}
fn blocks(n: usize) -> usize {
    n.saturating_add(BLOCK - 1) / BLOCK * BLOCK
}
fn once(v: &mut Vec<&'static str>, value: &'static str) {
    if !v.contains(&value) {
        v.push(value);
    }
}
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(64);
    for b in Sha256::digest(bytes) {
        use std::fmt::Write as _;
        let _ignored = write!(&mut s, "{b:02x}");
    }
    s
}

fn encode_bytes(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write as _;
        let _ignored = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
fn decode_64(value: &str) -> Result<[u8; 64], ()> {
    if value.len() != 128 {
        return Err(());
    }
    let mut result = [0_u8; 64];
    for (slot, pair) in result.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *slot = (hex_digit(pair[0]).ok_or(())? << 4) | hex_digit(pair[1]).ok_or(())?;
    }
    Ok(result)
}

#[cfg(test)]
const fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{AgeRecipients, BundleLimits, BundleMember, BundleOptions, SupportBundle};
    use std::io::Read;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn canonical_allowlist_admits_typed_configuration_and_crash_families() {
        let bundle = SupportBundle::build(
            [
                BundleMember::effective_configuration(b"local_key_file = <redacted>"),
                BundleMember::sanitized_crash_records(b"finding_code=PROCESS_EXIT"),
            ],
            BundleLimits::new(2, 12_000).expect("bounded fixture limits"),
        )
        .expect("typed canonical families are exportable");
        let rendered = String::from_utf8_lossy(bundle.archive());
        assert!(rendered.contains("effective-configuration.txt"));
        assert!(rendered.contains("sanitized-crash-records.txt"));
    }

    #[test]
    fn plaintext_bundle_uses_the_canonical_explicit_warning_flag() {
        let parsed = BundleOptions::parse(
            [
                "bundle",
                "create",
                "--config",
                "positron.toml",
                "--output",
                "bundle.tar",
                "--allow-plaintext-bundle",
                "--credential-stdin",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        let Ok(options) = parsed else {
            panic!("canonical plaintext flag must parse");
        };
        assert!(options.plaintext_warning);
        assert!(options.recipients.is_empty());
    }
    #[test]
    fn closed_allowlist_excludes_secret_and_telemetry_canaries_and_declares_a_deterministic_bound()
    {
        let bundle = SupportBundle::build(
            [
                BundleMember::doctor_report(b"finding=storage_available"),
                BundleMember::operational_telemetry(b"phase=serving"),
                BundleMember::unclassified(b"tenant-telemetry-canary"),
                BundleMember::unclassified(b"api-key-secret-canary"),
            ],
            BundleLimits::new(2, 12_000).expect("limits"),
        )
        .expect("bundle");
        assert_eq!(bundle.included_member_count(), 2);
        assert_eq!(bundle.redaction_report().excluded_unknown_members(), 2);
        assert!(
            !bundle
                .archive()
                .windows(23)
                .any(|v| v == b"tenant-telemetry-canary")
        );
        assert!(
            !bundle
                .archive()
                .windows(21)
                .any(|v| v == b"api-key-secret-canary")
        );
        assert!(
            bundle
                .redaction_report()
                .declared_omissions()
                .contains(&"unknown_member_class")
        );
    }

    #[test]
    fn archive_bound_omits_later_allowlisted_members_and_declares_truncation() {
        let payload = [b'x'; 6_000];
        let bundle = SupportBundle::build(
            [
                BundleMember::doctor_report(&payload),
                BundleMember::operational_telemetry(&payload),
            ],
            BundleLimits::new(2, 15_000).expect("limits"),
        )
        .expect("bounded archive");
        assert_eq!(bundle.included_member_count(), 1);
        assert!(
            bundle
                .redaction_report()
                .declared_omissions()
                .contains(&"archive_byte_limit")
        );
        assert!(bundle.archive().len() <= 15_000);
    }

    #[test]
    fn offline_key_unavailability_is_declared_in_the_redaction_report() {
        let bundle = SupportBundle::build_authenticated(
            [BundleMember::doctor_report(b"finding=key_unavailable")],
            BundleLimits::new(1, 12_000).expect("limits"),
            super::ManifestAuthentication::UnsignedKeyUnavailableOffline,
        )
        .expect("offline bundle remains exportable with an explicit reason");
        assert!(
            bundle
                .archive()
                .windows(b"signature=unsigned_key_unavailable_offline".len())
                .any(|entry| entry == b"signature=unsigned_key_unavailable_offline")
        );
    }

    #[test]
    fn native_age_recipient_parser_rejects_malformed_and_empty_recipient_sets() {
        assert!(AgeRecipients::parse(std::iter::empty::<&str>()).is_err());
        assert!(AgeRecipients::parse(["not-an-age-recipient"]).is_err());
    }

    #[test]
    fn native_age_x25519_encryption_round_trips_the_standard_archive() {
        let identity = age::x25519::Identity::generate();
        let recipients =
            AgeRecipients::parse([identity.to_public().to_string()]).expect("recipient");
        let encrypted = recipients.encrypt(b"support-bundle-tar").expect("encrypt");
        let decryptor = age::Decryptor::new(&encrypted[..]).expect("age envelope");
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .expect("recipient decrypts");
        let mut decrypted = Vec::new();
        reader
            .read_to_end(&mut decrypted)
            .expect("read decrypted archive");
        assert_eq!(decrypted, b"support-bundle-tar");
    }

    #[test]
    fn ciphertext_budget_rejects_age_header_and_payload_overflow() {
        let identity = age::x25519::Identity::generate();
        let recipients =
            AgeRecipients::parse([identity.to_public().to_string()]).expect("recipient");
        assert!(recipients.encrypt_bounded(b"archive", 16).is_err());
    }

    #[test]
    fn explicit_plaintext_export_is_owner_only_and_never_overwrites() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("positron-support-{nonce}.tar"));
        let bundle = SupportBundle::build_for_explicit_plaintext(
            [BundleMember::doctor_report(b"safe")],
            BundleLimits::new(1, 12_000).expect("limits"),
        )
        .expect("bundle");
        bundle
            .write_plaintext_explicitly(&path)
            .expect("new owner-only output");
        assert!(bundle.redaction_report().plaintext_warning());
        assert!(
            bundle
                .archive()
                .windows(b"plaintext_export_warning=true".len())
                .any(|entry| entry == b"plaintext_export_warning=true")
        );
        assert_eq!(fs::read(&path).expect("archive"), bundle.archive());
        assert!(bundle.write_plaintext_explicitly(&path).is_err());
        #[cfg(unix)]
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(
                &fs::metadata(&path).expect("metadata").permissions()
            ) & 0o777,
            0o600
        );
        fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn pseudonyms_are_stable_within_one_bundle_and_separate_across_bundles() {
        let first = super::privacy::Pseudonymizer::new();
        let second = super::privacy::Pseudonymizer::new();
        assert_eq!(
            first.pseudonymize("tenant-a"),
            first.pseudonymize("tenant-a")
        );
        assert_ne!(
            first.pseudonymize("tenant-a"),
            first.pseudonymize("tenant-b")
        );
        assert_ne!(
            first.pseudonymize("tenant-a"),
            second.pseudonymize("tenant-a")
        );
    }

    #[test]
    fn sanitized_crash_record_excludes_panic_payload_and_caps_backtrace_identity() {
        let record = super::crash_record::SanitizedCrashRecord::new(
            "serving",
            "catalog_unavailable",
            "catalog",
        )
        .expect("typed crash record");
        let rendered = record.render();
        assert!(rendered.contains("phase=serving"));
        assert!(rendered.contains("finding_code=catalog_unavailable"));
        assert!(!rendered.contains("panic_payload"));
        assert!(rendered.len() <= 512);
        let bundle = SupportBundle::build(
            [BundleMember::sanitized_crash_record(record)],
            BundleLimits::new(1, 12_000).expect("limits"),
        )
        .expect("bundle");
        assert!(
            bundle
                .archive()
                .windows(b"catalog_unavailable".len())
                .any(|entry| entry == b"catalog_unavailable")
        );
    }

    #[test]
    fn captured_backtrace_is_persisted_only_as_a_safe_fingerprint()
    -> Result<(), Box<dyn std::error::Error>> {
        let record = super::crash_record::SanitizedCrashRecord::new(
            "draining",
            "joined_task_panic",
            "serving_loop",
        )
        .map_err(|_| "typed crash record")?
        .with_backtrace(&std::backtrace::Backtrace::force_capture());
        let rendered = record.render();
        assert!(rendered.contains("backtrace_identity=sha256-"));
        assert!(!rendered.contains("backtrace::"));
        assert!(!rendered.contains("joined task panic payload"));
        Ok(())
    }

    #[test]
    fn persisted_crash_record_reopens_as_bounded_sanitized_support_input()
    -> Result<(), Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!("positron-crash-record-{nonce}"));
        fs::create_dir_all(&root)?;
        super::capture_process_failure(&root, "starting", "runtime_startup_failed", "runtime")
            .map_err(|_| "capture failed")?;
        let readout = super::crash_record::CrashRecordStore::under_data_directory(&root)
            .read_recent(
                std::time::Duration::from_secs(60),
                1,
                512,
                SystemTime::now(),
            )
            .map_err(|_| "readout failed")?;
        let rendered = readout.render();
        assert!(rendered.contains("finding_code=runtime_startup_failed"));
        assert!(!rendered.contains("panic_payload"));
        assert!(!rendered.contains(root.to_string_lossy().as_ref()));
        #[cfg(unix)]
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(
                &fs::metadata(
                    root.join("diagnostics/crash-records")
                        .read_dir()?
                        .next()
                        .ok_or("record missing")??
                        .path()
                )?
                .permissions()
            ) & 0o777,
            0o600,
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn joined_task_panic_capture_reopens_only_owned_safe_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let marker = "joined-task-panic-private-canary";
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!("positron-joined-panic-{nonce}"));
        fs::create_dir_all(&root)?;
        super::capture_process_failure_with_catalog_generation(
            &root,
            "draining",
            "joined_task_panicked",
            "runtime",
            Some(7),
        )
        .map_err(|_| "capture failed")?;
        let rendered = super::crash_record::CrashRecordStore::under_data_directory(&root)
            .read_recent(
                std::time::Duration::from_secs(60),
                1,
                384,
                SystemTime::now(),
            )
            .map_err(|_| "readout failed")?
            .render();
        assert!(rendered.contains("phase=draining"));
        assert!(rendered.contains("finding_code=joined_task_panicked"));
        assert!(rendered.contains("catalog_generation=7"));
        assert!(rendered.contains("backtrace_identity="));
        assert!(!rendered.contains(marker));
        assert!(!rendered.contains("panic_payload"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn crash_readout_declares_file_count_truncation_without_exporting_unread_records()
    -> Result<(), Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!("positron-crash-bound-{nonce}"));
        fs::create_dir_all(&root)?;
        super::capture_process_failure(&root, "starting", "first_failure", "runtime")
            .map_err(|_| "first capture")?;
        super::capture_process_failure(&root, "starting", "second_failure", "runtime")
            .map_err(|_| "second capture")?;
        let readout = super::crash_record::CrashRecordStore::under_data_directory(&root)
            .read_recent(
                std::time::Duration::from_secs(60),
                1,
                512,
                SystemTime::now(),
            )
            .map_err(|_| "bounded readout")?;
        let rendered = readout.render();
        assert!(rendered.contains("first_failure") || rendered.contains("second_failure"));
        assert!(readout.omissions().contains(&"crash_record_file_limit"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn crash_readout_declares_records_outside_the_log_window()
    -> Result<(), Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!("positron-crash-window-{nonce}"));
        fs::create_dir_all(&root)?;
        super::capture_process_failure(&root, "starting", "window_failure", "runtime")
            .map_err(|_| "capture")?;
        let later = SystemTime::now()
            .checked_add(std::time::Duration::from_secs(60))
            .ok_or("clock")?;
        let readout = super::crash_record::CrashRecordStore::under_data_directory(&root)
            .read_recent(std::time::Duration::from_secs(1), 4, 512, later)
            .map_err(|_| "readout")?;
        assert_eq!(readout.render(), "record_count=0\n");
        assert!(readout.omissions().contains(&"crash_record_log_window"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn elapsed_deadline_prevents_plaintext_output_creation()
    -> Result<(), Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let output = std::env::temp_dir().join(format!("positron-support-deadline-{nonce}.tar"));
        let bundle = SupportBundle::build_for_explicit_plaintext(
            [BundleMember::doctor_report(b"safe")],
            BundleLimits::new(1, 12_000).map_err(|_| "limits")?,
        )
        .map_err(|_| "bundle")?;
        let options = super::BundleOptions {
            config: std::path::PathBuf::from("unused"),
            output: output.clone(),
            recipients: Vec::new(),
            plaintext_warning: true,
            offline_key_unavailable: true,
            output_limit: 12_000,
            elapsed_limit: std::time::Duration::from_secs(1),
            log_window: std::time::Duration::from_secs(1),
            source_file_limit: 1,
        };
        let started = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(2))
            .ok_or("clock")?;
        assert!(matches!(
            super::write_bundle(&bundle, &options, started),
            Err(super::BundleFailure::DeadlineExceeded)
        ));
        assert!(!output.exists());
        Ok(())
    }

    #[test]
    fn authorized_runtime_signer_authenticates_the_final_archive_and_detects_member_tampering()
    -> Result<(), Box<dyn std::error::Error>> {
        use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
        use positron_kernel::MountQualification;
        use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};

        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!("positron-support-signature-{nonce}"));
        let data = root.join("data");
        let secrets = root.join("secrets");
        fs::create_dir(&root)?;
        fs::create_dir(&data)?;
        fs::create_dir(&secrets)?;
        #[cfg(unix)]
        fs::set_permissions(
            &secrets,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )?;
        let paths = BootstrapPaths::new(&data, &secrets, MountQualification::LocalHost)?;
        drop(InstanceBootstrap::initialize(
            &paths,
            InitializationPlan::non_interactive(),
        )?);
        let claim = InstanceBootstrap::claim(&paths)?;
        let instance = InstanceBootstrap::reopen(&paths)?;
        let actor = instance.attribute(
            PresentedCredential::parse(claim.secret())?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )?;
        let signer = instance.support_bundle_manifest_signer(actor)?;
        let bundle = SupportBundle::build_authenticated(
            [BundleMember::doctor_report(b"finding=degraded")],
            BundleLimits::new(1, 12_000).expect("limits"),
            super::ManifestAuthentication::Signed(&signer),
        )
        .map_err(|_| "bundle creation")?;
        SupportBundle::verify_signed_archive(bundle.archive(), signer.identity())
            .map_err(|_| "archive verification")?;

        let mut tampered = bundle.archive().to_vec();
        let location = tampered
            .windows(b"finding=degraded".len())
            .position(|window| window == b"finding=degraded")
            .ok_or("doctor member is present")?;
        tampered[location] = b'F';
        assert!(SupportBundle::verify_signed_archive(&tampered, signer.identity()).is_err());

        drop(instance);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn signature_attachment_cannot_bypass_the_final_archive_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
        use positron_kernel::MountQualification;
        use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};

        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!("positron-support-bound-{nonce}"));
        let data = root.join("data");
        let secrets = root.join("secrets");
        fs::create_dir(&root)?;
        fs::create_dir(&data)?;
        fs::create_dir(&secrets)?;
        #[cfg(unix)]
        fs::set_permissions(
            &secrets,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )?;
        let paths = BootstrapPaths::new(&data, &secrets, MountQualification::LocalHost)?;
        drop(InstanceBootstrap::initialize(
            &paths,
            InitializationPlan::non_interactive(),
        )?);
        let claim = InstanceBootstrap::claim(&paths)?;
        let instance = InstanceBootstrap::reopen(&paths)?;
        let actor = instance.attribute(
            PresentedCredential::parse(claim.secret())?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )?;
        let signer = instance.support_bundle_manifest_signer(actor)?;
        let payload = vec![b'x'; 6_000];
        assert!(
            SupportBundle::build_authenticated(
                [BundleMember::doctor_report(&payload)],
                BundleLimits::new(1, 10_240).expect("minimum tar bound"),
                super::ManifestAuthentication::Signed(&signer),
            )
            .is_err()
        );
        drop(instance);
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
