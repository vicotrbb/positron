use sha2::{Digest, Sha256};
use std::{io, time::Duration};

#[cfg(test)]
use super::crash_record;
use super::privacy::IdentifierRetention;
use super::{BLOCK, DEFAULT_ELAPSED_LIMIT, FOOTER, POLICY, TAR_RECORD, crypto, output};

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
    #[cfg(test)]
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
    const fn report_name(self) -> &'static str {
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
    pub(super) class: Option<Class>,
    pub(super) bytes: Vec<u8>,
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
    pub(super) fn operational_logs_with_omission(bytes: &[u8], omission: &'static str) -> Self {
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
    pub(super) fn sanitized_crash_records_with_omissions(
        bytes: &[u8],
        omissions: &[&'static str],
    ) -> Self {
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
    elapsed_limit: Duration,
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
            .then_some(Self {
                count,
                bytes,
                elapsed_limit: DEFAULT_ELAPSED_LIMIT,
            })
            .ok_or(())
    }
    pub(super) const fn with_elapsed_limit(mut self, elapsed_limit: Duration) -> Self {
        self.elapsed_limit = elapsed_limit;
        self
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
        Self::build_with_export_policy(
            input,
            limits,
            false,
            "not_applied",
            "not_applied",
            IdentifierRetention::Ephemeral,
        )
    }
    #[cfg(test)]
    pub(crate) fn build_for_explicit_plaintext(
        input: impl IntoIterator<Item = BundleMember>,
        limits: BundleLimits,
    ) -> Result<Self, ()> {
        Self::build_with_export_policy(
            input,
            limits,
            true,
            "plaintext_explicit",
            "not_applied",
            IdentifierRetention::Ephemeral,
        )
    }
    #[cfg(test)]
    pub(crate) fn build_authenticated(
        input: impl IntoIterator<Item = BundleMember>,
        limits: BundleLimits,
        authentication: ManifestAuthentication<'_>,
    ) -> Result<Self, ()> {
        Self::build_authenticated_with_retention(
            input,
            limits,
            authentication,
            IdentifierRetention::Ephemeral,
        )
    }
    pub(crate) fn build_authenticated_with_retention(
        input: impl IntoIterator<Item = BundleMember>,
        limits: BundleLimits,
        authentication: ManifestAuthentication<'_>,
        identifier_retention: IdentifierRetention,
    ) -> Result<Self, ()> {
        match authentication {
            ManifestAuthentication::Signed(signer) => {
                let bundle = Self::build_with_export_policy(
                    input,
                    limits,
                    false,
                    "age_x25519",
                    "signed",
                    identifier_retention,
                )?;
                // The signature is over the canonical manifest bytes retained
                // in the standard tar archive; opaque signer custody remains
                // wholly in Runtime/Kernel.
                let manifest = bundle.manifest_bytes()?;
                let signature = signer.sign(&manifest).map_err(|_| ())?;
                bundle.attach_signature(signature)
            },
            ManifestAuthentication::UnsignedKeyUnavailableOffline => {
                Self::build_with_export_policy(
                    input,
                    limits,
                    false,
                    "age_x25519",
                    "unsigned_key_unavailable_offline",
                    identifier_retention,
                )
            },
        }
    }
    pub(crate) fn build_authenticated_for_explicit_plaintext_with_retention(
        input: impl IntoIterator<Item = BundleMember>,
        limits: BundleLimits,
        authentication: ManifestAuthentication<'_>,
        identifier_retention: IdentifierRetention,
    ) -> Result<Self, ()> {
        match authentication {
            ManifestAuthentication::Signed(signer) => {
                let bundle = Self::build_with_export_policy(
                    input,
                    limits,
                    true,
                    "plaintext_explicit",
                    "signed",
                    identifier_retention,
                )?;
                let signature = signer.sign(&bundle.manifest_bytes()?).map_err(|_| ())?;
                bundle.attach_signature(signature)
            },
            ManifestAuthentication::UnsignedKeyUnavailableOffline => {
                Self::build_with_export_policy(
                    input,
                    limits,
                    true,
                    "plaintext_explicit",
                    "unsigned_key_unavailable_offline",
                    identifier_retention,
                )
            },
        }
    }
    fn build_with_export_policy(
        input: impl IntoIterator<Item = BundleMember>,
        limits: BundleLimits,
        plaintext_warning: bool,
        encryption_state: &'static str,
        signature_state: &'static str,
        identifier_retention: IdentifierRetention,
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
        let included_classes = selected
            .iter()
            .map(|(class, _)| class.report_name())
            .collect::<Vec<_>>()
            .join(",");
        let report = RedactionReport {
            unknown,
            omissions,
            plaintext_warning,
        };
        let redaction = format!(
            "policy_version={POLICY}\nincluded_classes={included_classes}\nidentifier_pseudonymization={}\nretained_identifier_classes={}\nmember_count_limit={}\narchive_byte_limit={}\nelapsed_time_limit_seconds={}\nexcluded_unknown_members={}\nomissions={}\nencryption={encryption_state}\nplaintext_export_warning={}\nsignature={signature_state}\n",
            identifier_retention.pseudonymization_value(),
            identifier_retention.report_value(),
            limits.count,
            limits.bytes,
            limits.elapsed_limit.as_secs(),
            report.unknown,
            report.omissions.join(","),
            plaintext_warning
        );
        let mut manifest = format!(
            "format=positron-support-bundle-tar-v1\nredaction_policy_version={POLICY}\narchive_byte_limit={}\nretained_identifier_classes={}\n",
            limits.bytes,
            identifier_retention.report_value(),
        );
        for (class, bytes) in &selected {
            manifest.push_str(&format!(
                "member={} bytes={} sha256={}\n",
                class.path(),
                bytes.len(),
                hex(bytes)?
            ));
        }
        manifest.push_str(&format!(
            "redaction_report_sha256={}\n",
            hex(redaction.as_bytes())?
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
        if fields.next().is_some() || key != encode_bytes(&expected.public_key())? {
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
            if actual.1.len() != count || digest != hex(&actual.1)? {
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
            encode_bytes(&signature.integrity_identity().public_key())?,
            encode_bytes(&signature.bytes())?
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

    #[cfg(test)]
    pub(super) fn write_plaintext_explicitly(
        &self,
        destination: &output::OutputDestination,
    ) -> Result<(), ()> {
        output::write_new_owner_only(destination, &self.archive)
    }
    pub(super) fn write_plaintext_explicitly_before_publication(
        &self,
        destination: &output::OutputDestination,
        publication_permitted: impl FnOnce() -> bool,
    ) -> Result<(), output::PublicationFailure> {
        output::write_new_owner_only_before_publication(
            destination,
            &self.archive,
            publication_permitted,
        )
    }
    #[cfg(test)]
    pub(super) fn write_plaintext_explicitly_with_after_close_hook(
        &self,
        destination: &output::OutputDestination,
        after_close: impl FnOnce(),
    ) -> Result<(), ()> {
        output::write_new_owner_only_with_after_close_hook(destination, &self.archive, after_close)
    }
    #[cfg(test)]
    pub(super) fn write_plaintext_explicitly_with_after_close_deadline_hook(
        &self,
        destination: &output::OutputDestination,
        after_close: impl FnOnce(),
        publication_permitted: impl FnOnce() -> bool,
    ) -> Result<(), output::PublicationFailure> {
        output::write_new_owner_only_with_after_close_deadline_hook(
            destination,
            &self.archive,
            after_close,
            publication_permitted,
        )
    }
    #[cfg(test)]
    pub(super) fn write_encrypted(
        &self,
        destination: &output::OutputDestination,
        ciphertext: &[u8],
    ) -> Result<(), ()> {
        output::write_new_owner_only(destination, ciphertext)
    }
    pub(super) fn write_encrypted_before_publication(
        &self,
        destination: &output::OutputDestination,
        ciphertext: &[u8],
        publication_permitted: impl FnOnce() -> bool,
    ) -> Result<(), output::PublicationFailure> {
        output::write_new_owner_only_before_publication(
            destination,
            ciphertext,
            publication_permitted,
        )
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
pub(crate) fn hex(bytes: &[u8]) -> Result<String, ()> {
    let mut s = String::with_capacity(64);
    for b in Sha256::digest(bytes) {
        use std::fmt::Write as _;
        write!(&mut s, "{b:02x}").map_err(|_| ())?;
    }
    Ok(s)
}

pub(crate) fn encode_bytes(bytes: &[u8]) -> Result<String, ()> {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").map_err(|_| ())?;
    }
    Ok(encoded)
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
