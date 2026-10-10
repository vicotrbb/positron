use std::time::Duration;

use super::super::{
    DEFAULT_ELAPSED_LIMIT, DEFAULT_LOG_WINDOW, DEFAULT_SOURCE_FILES, MAX_OUTPUT_LIMIT, TAR_RECORD,
    crypto,
};

#[derive(Clone, Copy)]
pub(crate) enum Class {
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
    pub(crate) const ALL: [Self; 14] = [
        Self::EffectiveConfiguration,
        Self::CompatibilityManifest,
        Self::ProductIdentity,
        Self::HealthState,
        Self::OperationalTelemetry,
        Self::OperationalLogs,
        Self::CatalogSummary,
        Self::ResourceStatus,
        Self::MaintenanceStatus,
        Self::ListenerStatus,
        Self::BackupRepositoryStatus,
        Self::Environment,
        Self::Doctor,
        Self::CrashRecords,
    ];
    pub(crate) const fn path(self) -> &'static str {
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
    pub(crate) const fn report_name(self) -> &'static str {
        match self {
            Self::EffectiveConfiguration => "effective_configuration",
            Self::CompatibilityManifest => "compatibility_manifest",
            Self::ProductIdentity => "product_identity",
            Self::HealthState => "health_state",
            Self::OperationalTelemetry => "operational_telemetry",
            Self::OperationalLogs => "operational_logs",
            Self::CatalogSummary => "catalog_summary",
            Self::ResourceStatus => "resource_status",
            Self::MaintenanceStatus => "maintenance_status",
            Self::ListenerStatus => "listener_status",
            Self::BackupRepositoryStatus => "backup_repository_status",
            Self::Environment => "environment",
            Self::Doctor => "doctor",
            Self::CrashRecords => "sanitized_crash_records",
        }
    }
}

/// Closed input: a caller cannot choose an archive name or classification.
pub(crate) struct BundleMember {
    pub(crate) class: Option<Class>,
    pub(crate) bytes: Vec<u8>,
    pub(crate) omissions: Vec<&'static str>,
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
    pub(crate) fn operational_logs_with_omission(bytes: &[u8], omission: &'static str) -> Self {
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
    pub(crate) fn sanitized_crash_records_with_omissions(
        bytes: &[u8],
        omissions: &[&'static str],
    ) -> Self {
        let mut member = Self::sanitized_crash_records(bytes);
        member.omissions.extend_from_slice(omissions);
        member
    }
    #[cfg(test)]
    pub(crate) fn sanitized_crash_record(
        record: super::super::crash_record::SanitizedCrashRecord,
    ) -> Self {
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
    pub(crate) count: usize,
    pub(crate) bytes: usize,
    pub(crate) elapsed_limit: Duration,
    pub(crate) log_window: Duration,
    pub(crate) source_file_limit: usize,
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
        (count > 0 && count <= 14 && (TAR_RECORD..=MAX_OUTPUT_LIMIT).contains(&bytes))
            .then_some(Self {
                count,
                bytes,
                elapsed_limit: DEFAULT_ELAPSED_LIMIT,
                log_window: DEFAULT_LOG_WINDOW,
                source_file_limit: DEFAULT_SOURCE_FILES,
            })
            .ok_or(())
    }
    pub(crate) const fn with_elapsed_limit(mut self, elapsed_limit: Duration) -> Self {
        self.elapsed_limit = elapsed_limit;
        self
    }
    pub(crate) const fn with_source_limits(
        mut self,
        log_window: Duration,
        source_file_limit: usize,
    ) -> Self {
        self.log_window = log_window;
        self.source_file_limit = source_file_limit;
        self
    }
}

pub(crate) struct RedactionReport {
    pub(crate) unknown: usize,
    pub(crate) omissions: Vec<&'static str>,
    pub(crate) plaintext_warning: bool,
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
