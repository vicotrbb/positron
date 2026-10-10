//! Offline owner-controlled recovery composed from Kernel custody and Catalog publication.
use super::InitializedInstance;
use positron_governance::{RecoveryBundleAction, recovery_bundle_audit_intent};
use positron_kernel::{
    BootstrapIntegrityIdentity, Catalog, CatalogObject, CatalogProposal, RecoveryFailure,
    RecoveryIdentity, RecoveryMetadata, RecoveryPassphrase, RecoveryProtection, RecoveryRecipients,
    RecoverySession, RecoveryUnlock, TransactionId,
};
use std::path::Path;
mod import;
mod state;
pub use state::RecoveryReadiness;
use state::{BundleReference, VerifiedBundle};

fn mode(unlock: &RecoveryUnlock<'_>) -> RecoveryProtection {
    match unlock {
        RecoveryUnlock::Identity(_) | RecoveryUnlock::IdentityFile(_) => {
            RecoveryProtection::Recipients
        },
        RecoveryUnlock::Passphrase(_) | RecoveryUnlock::InteractivePassphrase(_) => {
            RecoveryProtection::Passphrase
        },
    }
}
impl InitializedInstance {
    pub(super) fn recovery_predecessor_is_absent(
        &self,
        snapshot: &positron_kernel::CatalogSnapshot,
    ) -> Result<bool, RecoveryFailure> {
        Ok(VerifiedBundle::find(snapshot)?
            .is_some_and(|bundle| bundle.predecessor.is_none() && !bundle.retiring))
    }
    fn recovery_catalog(&self) -> Result<Catalog<'_>, RecoveryFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| RecoveryFailure::Custody)?;
        Catalog::open(&self._authority, self.instance, secret).map_err(|_| RecoveryFailure::Storage)
    }
    /// Returns externally pinnable recovery trust while exclusive owner custody is held.
    pub fn recovery_identity(&self) -> Result<RecoveryIdentity, RecoveryFailure> {
        let _session = RecoverySession::admit(&self._authority, RecoveryProtection::Recipients)?;
        let catalog = self.recovery_catalog()?;
        let snapshot = catalog.pin().map_err(|_| RecoveryFailure::Storage)?;
        let (_, governance) = snapshot
            .governance_object()
            .map_err(|_| RecoveryFailure::Authentication)?;
        let integrity = BootstrapIntegrityIdentity::from_pinned(
            governance.integrity_public_key(),
            governance.integrity_key_fingerprint(),
        )
        .map_err(|_| RecoveryFailure::Authentication)?;
        if integrity.fingerprint() != self.integrity_key_fingerprint {
            return Err(RecoveryFailure::Authentication);
        }
        RecoveryIdentity::new(
            self.instance,
            self.key
                .active_root_identity()
                .map_err(|_| RecoveryFailure::Authentication)?,
            integrity,
        )
    }
    pub fn create_recovery_bundle(
        &self,
        path: &Path,
        recipients: &RecoveryRecipients,
    ) -> Result<(), RecoveryFailure> {
        self.create_recovery(
            path,
            RecoveryProtection::Recipients,
            |session, pin, protected, time| {
                session.create(&self.key, pin, protected, recipients, time)
            },
        )
    }
    pub fn create_passphrase_recovery_bundle(
        &self,
        path: &Path,
        passphrase: &RecoveryPassphrase,
    ) -> Result<(), RecoveryFailure> {
        self.create_recovery(
            path,
            RecoveryProtection::Passphrase,
            |session, pin, protected, time| {
                session.create_passphrase(&self.key, pin, protected, passphrase, time)
            },
        )
    }
    /// Acquires the complete recovery grant before invoking protected terminal input.
    pub fn create_interactive_recovery_bundle(
        &self,
        path: &Path,
        read: impl FnOnce() -> Result<RecoveryPassphrase, RecoveryFailure>,
    ) -> Result<(), RecoveryFailure> {
        self.create_recovery(
            path,
            RecoveryProtection::Passphrase,
            |session, pin, protected, time| {
                let passphrase = read()?;
                session.create_passphrase(&self.key, pin, protected, &passphrase, time)
            },
        )
    }
    fn create_recovery(
        &self,
        path: &Path,
        protection: RecoveryProtection,
        create: impl FnOnce(
            &RecoverySession<'_>,
            RecoveryIdentity,
            &[u8],
            u64,
        ) -> Result<Vec<u8>, RecoveryFailure>,
    ) -> Result<(), RecoveryFailure> {
        let session = RecoverySession::admit(&self._authority, protection)?;
        let path = self
            .bootstrap_storage
            .recovery_bundle_location(path)
            .map_err(|_| RecoveryFailure::Storage)?;
        let catalog = self.recovery_catalog()?;
        let snapshot = catalog.pin().map_err(|_| RecoveryFailure::Storage)?;
        let (_, governance) = snapshot
            .governance_object()
            .map_err(|_| RecoveryFailure::Authentication)?;
        let pin = RecoveryIdentity::new(
            self.instance,
            self.key
                .active_root_identity()
                .map_err(|_| RecoveryFailure::Authentication)?,
            BootstrapIntegrityIdentity::from_pinned(
                governance.integrity_public_key(),
                self.integrity_key_fingerprint,
            )
            .map_err(|_| RecoveryFailure::Authentication)?,
        )?;
        let time = self
            .operation_time_seconds()
            .map_err(|_| RecoveryFailure::Storage)?;
        let ciphertext = create(&session, pin, governance.protected_integrity_key(), time)?;
        session.write_new(&path, &ciphertext)?;
        self.record_recovery(
            &catalog,
            None,
            RecoveryBundleAction::Created,
            pin,
            session.bundle_digest(&ciphertext)?,
            time,
        )?;
        // Creation intentionally carries no readiness proof. Inspection requires decryption.
        Ok(())
    }
    pub fn inspect_recovery_bundle(
        &self,
        path: &Path,
        unlock: RecoveryUnlock<'_>,
    ) -> Result<RecoveryMetadata, RecoveryFailure> {
        let protection = mode(&unlock);
        let pin = self.recovery_identity()?;
        let session = RecoverySession::admit(&self._authority, protection)?;
        let path = self
            .bootstrap_storage
            .recovery_bundle_location(path)
            .map_err(|_| RecoveryFailure::Storage)?;
        let ciphertext = session.read(&path)?;
        session.inspect(&ciphertext, unlock, pin)
    }
    pub fn verify_recovery_bundle(
        &self,
        path: &Path,
        unlock: RecoveryUnlock<'_>,
    ) -> Result<RecoveryMetadata, RecoveryFailure> {
        let protection = mode(&unlock);
        let pin = self.recovery_identity()?;
        let session = RecoverySession::admit(&self._authority, protection)?;
        let path = self
            .bootstrap_storage
            .recovery_bundle_location(path)
            .map_err(|_| RecoveryFailure::Storage)?;
        let catalog = self.recovery_catalog()?;
        let time = self
            .operation_time_seconds()
            .map_err(|_| RecoveryFailure::Storage)?;
        let ciphertext = match session.read(&path) {
            Ok(bytes) => bytes,
            Err(failure) => {
                self.record_recovery(
                    &catalog,
                    None,
                    RecoveryBundleAction::VerificationRejected,
                    pin,
                    [0; 32],
                    time,
                )?;
                return Err(failure);
            },
        };
        let digest = session.bundle_digest(&ciphertext)?;
        let metadata = match session.verify(&self.key, &ciphertext, unlock, pin) {
            Ok(metadata) => metadata,
            Err(failure) => {
                self.record_recovery(
                    &catalog,
                    None,
                    RecoveryBundleAction::VerificationRejected,
                    pin,
                    digest,
                    time,
                )?;
                return Err(failure);
            },
        };
        let snapshot = catalog.pin().map_err(|_| RecoveryFailure::Storage)?;
        let previous = VerifiedBundle::find(&snapshot)?;
        if previous.as_ref().is_some_and(|value| value.retiring) {
            return Err(RecoveryFailure::InvalidInput);
        }
        let current = BundleReference { path, digest };
        if previous.as_ref().is_some_and(|value| {
            value.predecessor.is_some()
                && (value.current.digest != digest || value.current.path != current.path)
        }) {
            return Err(RecoveryFailure::InvalidInput);
        }
        let predecessor = previous.and_then(|value| {
            if value.current.digest == digest && value.current.path == current.path {
                value.predecessor
            } else {
                Some(value.current)
            }
        });
        let action = if predecessor.is_some() {
            RecoveryBundleAction::ReplacementVerified
        } else {
            RecoveryBundleAction::Verified
        };
        let verified = VerifiedBundle {
            pin,
            current,
            predecessor,
            retiring: false,
        };
        self.record_recovery(&catalog, Some(&verified), action, pin, digest, time)?;
        Ok(metadata)
    }
    /// Retires one predecessor only after rechecking the verified replacement.
    /// A Catalog-published prepare record allows restart to finish an interrupted unlink.
    pub fn retire_recovery_predecessor(&self) -> Result<(), RecoveryFailure> {
        if self.backup_key_recovery_readiness()? != RecoveryReadiness::Verified {
            return Err(RecoveryFailure::Authentication);
        }
        let session = RecoverySession::admit(&self._authority, RecoveryProtection::Recipients)?;
        let catalog = self.recovery_catalog()?;
        let snapshot = catalog.pin().map_err(|_| RecoveryFailure::Storage)?;
        let mut verified = VerifiedBundle::find(&snapshot)?.ok_or(RecoveryFailure::InvalidInput)?;
        let predecessor = verified
            .predecessor
            .clone()
            .ok_or(RecoveryFailure::InvalidInput)?;
        let path = self
            .bootstrap_storage
            .recovery_bundle_location(&predecessor.path)
            .map_err(|_| RecoveryFailure::Storage)?;
        let time = self
            .operation_time_seconds()
            .map_err(|_| RecoveryFailure::Storage)?;
        let resumed = verified.retiring;
        if !resumed {
            // Validate the predecessor before durably authorizing an exact-object unlink.
            let bytes = session.read(&path)?;
            if session.bundle_digest(&bytes)? != predecessor.digest {
                return Err(RecoveryFailure::Authentication);
            }
            verified.retiring = true;
            self.record_recovery(
                &catalog,
                Some(&verified),
                RecoveryBundleAction::RetirementPrepared,
                verified.pin,
                predecessor.digest,
                time,
            )?;
        }
        match session.retire(&path, predecessor.digest) {
            Ok(()) => {},
            Err(RecoveryFailure::Missing) if resumed => {},
            Err(failure) => return Err(failure),
        }
        verified.predecessor = None;
        verified.retiring = false;
        self.record_recovery(
            &catalog,
            Some(&verified),
            RecoveryBundleAction::Retired,
            verified.pin,
            predecessor.digest,
            time,
        )
    }
    /// Revalidates the durable verification against current custody and the exact separate artifact.
    pub fn backup_key_recovery_readiness(&self) -> Result<RecoveryReadiness, RecoveryFailure> {
        let session = RecoverySession::admit(&self._authority, RecoveryProtection::Recipients)?;
        let Ok(access) = self.bootstrap_storage.inspect() else {
            return Ok(RecoveryReadiness::IndependentRecoveryRequired);
        };
        let Ok(custody) = access.open_key() else {
            return Ok(RecoveryReadiness::IndependentRecoveryRequired);
        };
        let Ok(custody) = super::local_rotation::reopen_active_route(
            &self._authority,
            &self.bootstrap_storage,
            self.instance,
            custody,
        ) else {
            return Ok(RecoveryReadiness::IndependentRecoveryRequired);
        };
        if custody.identity()
            != self
                .key
                .active_root_identity()
                .map_err(|_| RecoveryFailure::Authentication)?
        {
            return Ok(RecoveryReadiness::IndependentRecoveryRequired);
        }
        let catalog = self.recovery_catalog()?;
        let snapshot = catalog.pin().map_err(|_| RecoveryFailure::Storage)?;
        let Some(verified) = VerifiedBundle::find(&snapshot)? else {
            return Ok(RecoveryReadiness::IndependentRecoveryRequired);
        };
        if verified.pin.instance() != self.instance
            || verified.pin.root()
                != self
                    .key
                    .active_root_identity()
                    .map_err(|_| RecoveryFailure::Authentication)?
            || verified.pin.integrity().fingerprint() != self.integrity_key_fingerprint
        {
            return Ok(RecoveryReadiness::IndependentRecoveryRequired);
        }
        let Ok(path) = self
            .bootstrap_storage
            .recovery_bundle_location(&verified.current.path)
        else {
            return Ok(RecoveryReadiness::IndependentRecoveryRequired);
        };
        let Ok(ciphertext) = session.read(&path) else {
            return Ok(RecoveryReadiness::IndependentRecoveryRequired);
        };
        if session.bundle_digest(&ciphertext)? != verified.current.digest {
            return Ok(RecoveryReadiness::IndependentRecoveryRequired);
        }
        Ok(RecoveryReadiness::Verified)
    }
    fn record_recovery(
        &self,
        catalog: &Catalog<'_>,
        replacement: Option<&VerifiedBundle>,
        action: RecoveryBundleAction,
        pin: RecoveryIdentity,
        digest: [u8; 32],
        time: u64,
    ) -> Result<(), RecoveryFailure> {
        publish_event(
            catalog,
            &self.key,
            self.administrator,
            replacement,
            RecoveryEvent {
                action,
                pin,
                digest,
                time,
            },
        )
    }
}
struct RecoveryEvent {
    action: RecoveryBundleAction,
    pin: RecoveryIdentity,
    digest: [u8; 32],
    time: u64,
}
fn publish_event(
    catalog: &Catalog<'_>,
    custody: &positron_kernel::BootstrapKeyCustody,
    actor: positron_domain::identity::PrincipalId,
    replacement: Option<&VerifiedBundle>,
    event: RecoveryEvent,
) -> Result<(), RecoveryFailure> {
    let snapshot = catalog.pin().map_err(|_| RecoveryFailure::Storage)?;
    let mut objects = Vec::with_capacity(snapshot.object_identities().count() + 1);
    for id in snapshot.object_identities() {
        let bytes = snapshot
            .object(id)
            .map_err(|_| RecoveryFailure::Storage)?
            .ok_or(RecoveryFailure::Storage)?;
        if replacement.is_some() && bytes.starts_with(b"POSREC01") {
            continue;
        }
        objects.push(CatalogObject::new(bytes.to_vec()).map_err(|_| RecoveryFailure::Storage)?);
    }
    if let Some(replacement) = replacement {
        objects
            .push(CatalogObject::new(replacement.encode()?).map_err(|_| RecoveryFailure::Storage)?);
    }
    let transaction = TransactionId::new(
        custody
            .random_identifier()
            .map_err(|_| RecoveryFailure::Custody)?,
    )
    .map_err(|_| RecoveryFailure::Storage)?;
    let proposal = CatalogProposal::new(
        transaction,
        snapshot.format_epoch().ok_or(RecoveryFailure::Storage)?,
        objects,
    )
    .map_err(|_| RecoveryFailure::Storage)?;
    let audit = recovery_bundle_audit_intent(
        actor,
        event.action,
        event.pin.instance().to_bytes(),
        event.pin.root().fingerprint(),
        event.digest,
        event.time,
    )
    .map_err(|_| RecoveryFailure::Storage)?;
    catalog
        .commit(snapshot.identity(), proposal, Some(audit))
        .map_err(|_| RecoveryFailure::Storage)?;
    Ok(())
}

#[cfg(fuzzing)]
pub(crate) fn fuzz_recovery_catalog_state(data: &[u8]) {
    if let Err(failure) = state::fuzz_state(data) {
        panic!("fixed recovery metadata fixture failed: {failure}");
    }
}
