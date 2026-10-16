//! Repository recovery proof is scoped to the authenticated root and registration inventory.
use super::*;
use positron_kernel::key_provider::KeyEnvelope;

pub(crate) struct BackupRootRetirementProof {
    pub(crate) registrations: [u8; 32],
    pub(crate) target: [u8; 32],
}

pub(crate) fn registration_digest(
    basis: &positron_kernel::CatalogSnapshot,
) -> Result<[u8; 32], LocalKeyRotationFailure> {
    let mut hash = Sha256::new();
    hash.update(b"positron.backup-root-retirement.registrations.v1\0");
    for address in basis.object_identities() {
        let bytes = basis
            .object(address)
            .map_err(|_| LocalKeyRotationFailure::Storage)?
            .ok_or(LocalKeyRotationFailure::Authentication)?;
        if positron_backup::BackupRepositoryRegistration::decode(bytes)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?
            .is_some()
        {
            hash.update(address.to_bytes());
        }
    }
    Ok(hash.finalize().into())
}

impl InitializedInstance {
    /// The authenticated journal supplies routes only after committed cutover.
    /// Both routes were independently unwrapped and compared with the stable
    /// SYSTEM KEK during preparation and activation; no root key is exported.
    pub(crate) fn backup_migration_envelopes(
        &self,
    ) -> Result<(KeyEnvelope, KeyEnvelope), LocalKeyRotationFailure> {
        let session = RootRewrapSession::admit_provider(&self._authority)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        let catalog = self.rotation_catalog(&session)?;
        let basis = catalog
            .pin()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        let state = State::find(&basis)?.ok_or(LocalKeyRotationFailure::InvalidInput)?;
        if state.cancelled
            || state.successor.is_some()
            || state.instance != self.instance
            || state.anchor != self.key.bootstrap_identity()
        {
            return Err(LocalKeyRotationFailure::Busy);
        }
        let source = state
            .predecessor
            .as_ref()
            .ok_or(LocalKeyRotationFailure::InvalidInput)?;
        let decode = |route: &Route| {
            KeyEnvelope::decode(&route.envelope)
                .map_err(|_| LocalKeyRotationFailure::Authentication)
        };
        let access = self
            .bootstrap_storage
            .inspect()
            .map_err(|_| LocalKeyRotationFailure::Custody)?;
        for route in [source, &state.active] {
            if decode(route)?.identity().family()
                == positron_kernel::key_provider::ProviderFamily::LocalFile
            {
                session
                    .verify_local_backup_root_envelope(
                        &access,
                        &self.key,
                        self.instance,
                        route.epoch,
                        &route.envelope,
                    )
                    .map_err(|_| LocalKeyRotationFailure::Authentication)?;
            }
        }
        let source = decode(source)?;
        let target = decode(&state.active)?;
        super::cutover::confirm_state(&catalog, &state)?;
        Ok((source, target))
    }
}
