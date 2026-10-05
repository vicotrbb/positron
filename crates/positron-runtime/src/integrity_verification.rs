use positron_kernel::{
    IntegrityQuarantineFinding, IntegrityVerificationOutcome, IntegrityVerificationReport,
};

use crate::{BootstrapPaths, InstanceBootstrap};

/// Bounded, machine-renderable evidence from one offline verification pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineIntegrityVerification {
    reports: Vec<IntegrityVerificationReport>,
    findings: Vec<IntegrityQuarantineFinding>,
}

impl OfflineIntegrityVerification {
    pub(crate) fn new(
        reports: Vec<IntegrityVerificationReport>,
        findings: Vec<IntegrityQuarantineFinding>,
    ) -> Self {
        Self { reports, findings }
    }

    #[must_use]
    pub fn reports(&self) -> &[IntegrityVerificationReport] {
        &self.reports
    }

    /// Durable quarantine evidence from the same read-only Catalog snapshot.
    #[must_use]
    pub fn findings(&self) -> &[IntegrityQuarantineFinding] {
        &self.findings
    }

    /// An offline invocation is complete only when every registered sealed
    /// scope reached a terminal result. A fenced result is terminal evidence,
    /// never a successful verification claim.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.reports
            .iter()
            .all(|report| report.outcome() != IntegrityVerificationOutcome::Incomplete)
    }

    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.is_complete()
            && self
                .reports
                .iter()
                .all(|report| report.outcome() == IntegrityVerificationOutcome::Verified)
    }
}

/// Typed offline-verification failure. It carries no storage, credential, or
/// decrypted-record detail because it is rendered by an operator report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfflineIntegrityFailure {
    BootstrapUnavailable,
    KeyUnavailable,
    CatalogUnavailable,
    CorruptState,
    CapacityUnavailable,
    StorageUnavailable,
}

/// Verifies every registered immutable segment scope without creating or
/// repairing bootstrap, Catalog, ledger, or quarantine state.
pub fn verify_offline_integrity(
    paths: &BootstrapPaths,
    max_registered_tenants: u16,
) -> Result<OfflineIntegrityVerification, OfflineIntegrityFailure> {
    InstanceBootstrap::verify_offline_integrity(paths, max_registered_tenants)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::{OfflineIntegrityFailure, verify_offline_integrity};
    use crate::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
    use positron_kernel::MountQualification;

    #[test]
    fn offline_verification_reads_healthy_instance_without_changing_any_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root()?;
        let paths = BootstrapPaths::new(
            &root.join("data"),
            &root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
        let before = file_tree(&root)?;
        let report = verify_offline_integrity(&paths, 2)
            .map_err(|failure| format!("offline verification failed: {failure:?}"))?;
        let after = file_tree(&root)?;

        assert!(report.is_complete());
        assert!(report.is_verified());
        assert_eq!(
            after, before,
            "offline verification must not create, repair, or publish"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn offline_corruption_report_preserves_damaged_bytes_without_quarantine()
    -> Result<(), Box<dyn std::error::Error>> {
        use positron_domain::routing::SignalKind;
        use positron_kernel::{ActiveSegmentLedger, Catalog, SegmentScope};

        let root = temporary_root()?;
        let paths = BootstrapPaths::new(
            &root.join("data"),
            &root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
        let instance = InstanceBootstrap::reopen(&paths)?;
        let catalog = Catalog::open(
            &instance._authority,
            instance.instance,
            instance.key.catalog_secret(instance.instance)?,
        )?;
        let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, instance.logs_shard);
        let identity = positron_governance::Identity::open(&catalog.pin()?)?;
        let key = crate::services::tenant_segment_key(&instance, &identity, scope)
            .map_err(|failure| format!("segment key unavailable: {failure:?}"))?;
        ActiveSegmentLedger::open(&instance._authority, &catalog, scope, key)?.seal()?;
        drop(catalog);
        drop(instance);

        let sealed = fs::read_dir(root.join("data/segments/sealed"))?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .next()
            .ok_or("sealed segment")?;
        fs::write(sealed, b"corrupt")?;
        let before = file_tree(&root)?;
        let report = verify_offline_integrity(&paths, 2)
            .map_err(|failure| format!("offline verification failed: {failure:?}"))?;
        assert!(!report.is_verified());
        assert!(
            report.reports().iter().any(|item| item.outcome()
                == positron_kernel::IntegrityVerificationOutcome::Fenced),
            "offline corruption is a non-mutating fenced fact, never a quarantine publication"
        );
        assert_eq!(file_tree(&root)?, before);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn offline_missing_key_reports_typed_failure_without_bootstrap_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root()?;
        let paths = BootstrapPaths::new(
            &root.join("data"),
            &root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
        fs::remove_file(root.join("secrets/local-root-key.v1"))?;
        let before = file_tree(&root)?;
        assert_eq!(
            verify_offline_integrity(&paths, 2),
            Err(OfflineIntegrityFailure::KeyUnavailable)
        );
        assert_eq!(file_tree(&root)?, before);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn offline_verification_of_missing_root_never_creates_bootstrap_artifacts()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root()?;
        let paths = BootstrapPaths::new(
            &root.join("data"),
            &root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        let before = file_tree(&root)?;
        assert_eq!(
            verify_offline_integrity(&paths, 2),
            Err(OfflineIntegrityFailure::BootstrapUnavailable)
        );
        assert_eq!(file_tree(&root)?, before);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn temporary_root() -> Result<PathBuf, std::io::Error> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "positron-offline-integrity-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("data"))?;
        fs::create_dir_all(root.join("secrets"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join("secrets"), fs::Permissions::from_mode(0o700))?;
        }
        Ok(root)
    }

    fn file_tree(root: &Path) -> Result<Vec<(PathBuf, Vec<u8>)>, std::io::Error> {
        let mut entries = Vec::new();
        collect_files(root, root, &mut entries)?;
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(entries)
    }

    fn collect_files(
        root: &Path,
        current: &Path,
        entries: &mut Vec<(PathBuf, Vec<u8>)>,
    ) -> Result<(), std::io::Error> {
        for entry in fs::read_dir(current)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                collect_files(root, &path, entries)?;
            } else {
                let relative = path
                    .strip_prefix(root)
                    .map_err(std::io::Error::other)?
                    .to_owned();
                // The volume acquisition lease is the only intentional
                // filesystem side effect of offline exclusivity.
                if relative != Path::new("data/.positron-volume.lock") {
                    entries.push((relative, fs::read(&path)?));
                }
            }
        }
        Ok(())
    }
}
