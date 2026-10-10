//! Catalog authorization precedes exact custody removal and route pruning.
use super::*;
use crate::instance_bootstrap::{BackupRepositoryInspection, RecoveryReadiness};

impl InitializedInstance {
    pub fn retire_local_key_predecessor(&self) -> Result<(), LocalKeyRotationFailure> {
        let session = RootRewrapSession::admit(&self._authority)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        if self
            .backup_key_recovery_readiness()
            .map_err(|_| LocalKeyRotationFailure::Custody)?
            != RecoveryReadiness::Verified
        {
            return Err(LocalKeyRotationFailure::Custody);
        }
        let catalog = self.rotation_catalog(&session)?;
        let basis = catalog
            .pin()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        let mut state = State::find(&basis)?.ok_or(LocalKeyRotationFailure::InvalidInput)?;
        if state.instance != self.instance
            || state.anchor != self.key.bootstrap_identity()
            || state.active.identity
                != self
                    .key
                    .active_root_identity()
                    .map_err(|_| LocalKeyRotationFailure::Custody)?
            || state.active.epoch
                != self
                    .key
                    .active_root_epoch()
                    .map_err(|_| LocalKeyRotationFailure::Custody)?
            || state.successor.is_some()
        {
            return Err(LocalKeyRotationFailure::Authentication);
        }
        super::cutover::confirm_state(&catalog, &state)?;
        let recovery_predecessor_absent = self
            .recovery_predecessor_is_absent(&basis)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        BackupRepositoryInspection::from_authenticated_catalog(&basis)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let Some(predecessor) = state.predecessor.clone() else {
            if !recovery_predecessor_absent {
                self.publish_rotation(
                    &catalog,
                    &basis,
                    &state,
                    CatalogRootRotationStage::RetirementRefused,
                    self.rotation_transaction()?,
                )?;
                return Err(LocalKeyRotationFailure::Busy);
            }
            catalog
                .confirm_current_publication()
                .map_err(|_| LocalKeyRotationFailure::Storage)?;
            return Ok(());
        };
        let access = self
            .bootstrap_storage
            .inspect()
            .map_err(|_| LocalKeyRotationFailure::Custody)?;
        let predecessor_route = positron_kernel::RootPredecessorEnvelope::new(
            predecessor.identity,
            predecessor.epoch,
            &predecessor.envelope,
        )
        .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        session
            .verify_retirement_routes(
                &access,
                &self.key,
                self.instance,
                &predecessor_route,
                state.retiring,
            )
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        if !state.retiring {
            session
                .verify_predecessor_custody(&access, predecessor.epoch, predecessor.identity)
                .map_err(|_| LocalKeyRotationFailure::Custody)?;
        }
        if !recovery_predecessor_absent {
            self.publish_rotation(
                &catalog,
                &basis,
                &state,
                CatalogRootRotationStage::RetirementRefused,
                self.rotation_transaction()?,
            )?;
            return Err(LocalKeyRotationFailure::Busy);
        }
        let guard = match positron_kernel::ActiveSegmentLedger::guard_local_root_retirement(
            &self._authority,
            &catalog,
        ) {
            Ok(guard) => guard,
            Err(failure)
                if failure.code() == positron_kernel::LedgerFailureCode::ConcurrentWriter =>
            {
                self.publish_rotation(
                    &catalog,
                    &basis,
                    &state,
                    CatalogRootRotationStage::RetirementRefused,
                    self.rotation_transaction()?,
                )?;
                return Err(LocalKeyRotationFailure::Busy);
            },
            Err(failure)
                if failure.code()
                    == positron_kernel::LedgerFailureCode::ResourceAdmissionRefused =>
            {
                return Err(LocalKeyRotationFailure::LimitExceeded);
            },
            Err(_) => return Err(LocalKeyRotationFailure::Authentication),
        };
        if guard.catalog_basis().identity() != basis.identity() {
            return Err(LocalKeyRotationFailure::Busy);
        }
        let _references = match self
            .maintenance_coordinator()
            .guard_root_retirement_references(&session, &catalog, &basis)
        {
            Ok(guard) => guard,
            Err(positron_kernel::MaintenanceFailure::ConcurrentAccess) => {
                self.publish_rotation(
                    &catalog,
                    &basis,
                    &state,
                    CatalogRootRotationStage::RetirementRefused,
                    self.rotation_transaction()?,
                )?;
                return Err(LocalKeyRotationFailure::Busy);
            },
            Err(_) => return Err(LocalKeyRotationFailure::Busy),
        };
        let prepared = if !state.retiring {
            let verified =
                if super::root_verification_audit::confirm_existing(&catalog, &basis, &state)? {
                    basis.clone()
                } else {
                    self.publish_rotation(
                        &catalog,
                        &basis,
                        &state,
                        CatalogRootRotationStage::Verified,
                        self.rotation_transaction()?,
                    )?
                };
            state.retiring = true;
            state.transaction = self.rotation_transaction()?;
            self.publish_rotation(
                &catalog,
                &verified,
                &state,
                CatalogRootRotationStage::RetirementPrepared,
                state.transaction,
            )?
        } else {
            super::cutover::confirm_state(&catalog, &state)?;
            basis.clone()
        };
        session
            .retire_predecessor_custody(&access, &self.key, self.instance, &predecessor_route, true)
            .map_err(|_| LocalKeyRotationFailure::Custody)?;
        let current = catalog
            .pin()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        if current.identity() != prepared.identity()
            || State::find(&current)?.as_ref() != Some(&state)
        {
            return Err(LocalKeyRotationFailure::Busy);
        }
        state.predecessor = None;
        state.retiring = false;
        state.transaction = self.rotation_transaction()?;
        self.publish_rotation(
            &catalog,
            &prepared,
            &state,
            CatalogRootRotationStage::Completed,
            state.transaction,
        )
        .map(|_| ())
    }
}
