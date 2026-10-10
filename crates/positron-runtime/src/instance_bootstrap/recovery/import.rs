//! Authenticated offline restoration and exclusive local root publication.
use super::*;

impl crate::instance_bootstrap::InstanceBootstrap {
    /// Offline recovery requires exclusive data ownership, owner-only artifact custody,
    /// and externally pinned identity. Existing or corrupt roots are never overwritten.
    pub fn import_recovery_bundle(
        paths: &crate::instance_bootstrap::BootstrapPaths,
        path: &Path,
        pin: RecoveryIdentity,
        unlock: RecoveryUnlock<'_>,
    ) -> Result<InitializedInstance, RecoveryFailure> {
        use positron_kernel::{BootstrapArtifact, BootstrapObjectPurpose};
        let (volume, access) = paths
            .storage
            .acquire()
            .map_err(|_| RecoveryFailure::Storage)?;
        let layout = access.layout().map_err(|_| RecoveryFailure::Storage)?;
        if layout.unknown_or_unsafe() {
            return Err(RecoveryFailure::Storage);
        }
        let authority = crate::instance_bootstrap::resources::establish_system_diagnostics(
            volume,
            crate::instance_bootstrap::DEFAULT_MAX_REGISTERED_TENANTS,
        )
        .map_err(|_| RecoveryFailure::Admission)?;
        let session = RecoverySession::admit(&authority, mode(&unlock))?;
        let path = paths
            .storage
            .recovery_bundle_location(path)
            .map_err(|_| RecoveryFailure::Storage)?;
        let ciphertext = session.read(&path)?;
        let digest = session.bundle_digest(&ciphertext)?;
        let initialized = access
            .read(BootstrapArtifact::Initialized)
            .map_err(|_| RecoveryFailure::Storage)?;
        let custody = session.import(&ciphertext, unlock, pin, &access, |custody| {
            let record = crate::instance_bootstrap::operation::support::decode_record(
                custody,
                BootstrapObjectPurpose::Initialized,
                &initialized,
            )
            .map_err(|_| RecoveryFailure::Authentication)?;
            crate::instance_bootstrap::operation::support::require_key_identity(
                &record,
                custody.bootstrap_identity(),
            )
            .map_err(|_| RecoveryFailure::Authentication)?;
            if record.instance != pin.instance()
                || record.integrity_fingerprint != pin.integrity().fingerprint()
            {
                return Err(RecoveryFailure::Authentication);
            }
            let secret = custody
                .catalog_secret(record.instance)
                .map_err(|_| RecoveryFailure::Authentication)?;
            let view = Catalog::read_current_view(&authority, record.instance, secret)
                .map_err(|_| RecoveryFailure::Authentication)?;
            let (_, governance) = view
                .snapshot()
                .governance_object()
                .map_err(|_| RecoveryFailure::Authentication)?;
            if governance.integrity_public_key() != pin.integrity().public_key()
                || governance.integrity_key_fingerprint() != pin.integrity().fingerprint()
            {
                return Err(RecoveryFailure::Authentication);
            }
            let signer = custody
                .export_manifest_signer(record.instance, governance.protected_integrity_key())
                .map_err(|_| RecoveryFailure::Authentication)?;
            if signer.identity() != pin.integrity() {
                return Err(RecoveryFailure::Authentication);
            }
            view.verify_audit_chain(pin.integrity().public_key(), None)
                .map_err(|_| RecoveryFailure::Authentication)?;
            drop(view);
            let catalog = Catalog::open(
                &authority,
                record.instance,
                custody
                    .catalog_secret(record.instance)
                    .map_err(|_| RecoveryFailure::Authentication)?,
            )
            .map_err(|_| RecoveryFailure::Storage)?;
            super::super::local_rotation::validate_recovery_route(
                &authority,
                &catalog,
                custody,
                record.instance,
            )
            .map_err(|_| RecoveryFailure::Authentication)?;
            let time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| RecoveryFailure::Storage)?
                .as_secs();
            publish_event(
                &catalog,
                custody,
                record.administrator,
                None,
                RecoveryEvent {
                    action: RecoveryBundleAction::ImportPrepared,
                    pin,
                    digest,
                    time,
                },
            )
        })?;
        drop(custody);
        drop(session);
        drop(authority);
        drop(access);
        let instance = Self::reopen(paths).map_err(|_| RecoveryFailure::Storage)?;
        let _session =
            RecoverySession::admit(&instance._authority, RecoveryProtection::Recipients)?;
        let catalog = instance.recovery_catalog()?;
        let time = instance
            .operation_time_seconds()
            .map_err(|_| RecoveryFailure::Storage)?;
        instance.record_recovery(
            &catalog,
            None,
            RecoveryBundleAction::Imported,
            pin,
            digest,
            time,
        )?;
        drop(catalog);
        drop(_session);
        Ok(instance)
    }
}
