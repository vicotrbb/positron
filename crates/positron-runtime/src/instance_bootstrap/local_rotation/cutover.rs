//! Catalog publication selects the verified live provider and restart route.
use super::*;
impl InitializedInstance {
    pub fn activate_local_key_rotation(
        &self,
    ) -> Result<LocalKeyRotationStatus, LocalKeyRotationFailure> {
        self.activate_local_key_rotation_for_operation(None)
    }
    pub(crate) fn activate_local_key_rotation_for_operation(
        &self,
        context: Option<RootMigrationContext<'_>>,
    ) -> Result<LocalKeyRotationStatus, LocalKeyRotationFailure> {
        let session = RootRewrapSession::admit_provider(&self._authority)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        let mut catalog = self.rotation_catalog_for_operation(&session, context)?;
        let snapshot = catalog
            .pin()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        let mut state = match State::find(&snapshot) {
            Ok(Some(state)) => state,
            Ok(None) => return Err(LocalKeyRotationFailure::InvalidInput),
            Err(failure) => {
                self.key
                    .invalidate_for_rotation()
                    .map_err(|_| LocalKeyRotationFailure::Custody)?;
                return Err(failure);
            },
        };
        if state.cancelled {
            return Err(LocalKeyRotationFailure::Busy);
        }
        if state.instance != self.instance || state.anchor != self.key.bootstrap_identity() {
            self.key
                .invalidate_for_rotation()
                .map_err(|_| LocalKeyRotationFailure::Custody)?;
            return Err(LocalKeyRotationFailure::Authentication);
        }
        let mut source_receipt = self
            .key
            .root_admission_receipt()
            .map_err(|_| LocalKeyRotationFailure::Custody)?;
        if source_receipt.requires_reconfirmation()
            && source_receipt.identity() == state.active.identity
            && source_receipt.epoch() == state.active.epoch
        {
            confirm_state(&catalog, &state)?;
            drop(catalog);
            session
                .confirm_active_provider(&self.key, state.active.identity, state.active.epoch)
                .map_err(|_| LocalKeyRotationFailure::Custody)?;
            catalog = self.rotation_catalog_for_operation(&session, context)?;
            if catalog
                .pin()
                .map_err(|_| LocalKeyRotationFailure::Storage)?
                .identity()
                != snapshot.identity()
            {
                return Err(LocalKeyRotationFailure::Busy);
            }
            source_receipt = self
                .key
                .root_admission_receipt()
                .map_err(|_| LocalKeyRotationFailure::Custody)?;
        }
        let destination = state.successor.as_ref().unwrap_or(&state.active);
        let destination_envelope =
            positron_kernel::key_provider::KeyEnvelope::decode(&destination.envelope)
                .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        if destination_envelope.identity().family()
            != positron_kernel::key_provider::ProviderFamily::LocalFile
        {
            return Err(LocalKeyRotationFailure::InvalidInput);
        }
        let Some(route) = state.successor.take() else {
            if let Err(failure) = confirm_state(&catalog, &state) {
                self.key
                    .invalidate_for_rotation()
                    .map_err(|_| LocalKeyRotationFailure::Custody)?;
                return Err(failure);
            }
            if self
                .key
                .active_root_identity()
                .map_err(|_| LocalKeyRotationFailure::Custody)?
                == state.active.identity
            {
                session
                    .confirm_active_provider(&self.key, state.active.identity, state.active.epoch)
                    .map_err(|_| LocalKeyRotationFailure::Authentication)?;
            } else {
                drop(catalog);
                let access = self
                    .bootstrap_storage
                    .inspect()
                    .map_err(|_| LocalKeyRotationFailure::Custody)?;
                let active = session
                    .open_successor(&access, state.active.epoch)
                    .map_err(|_| LocalKeyRotationFailure::Custody)?;
                if active.identity() != state.active.identity {
                    return Err(LocalKeyRotationFailure::Authentication);
                }
                let activation = session
                    .prepare_activation(
                        &self.key,
                        active,
                        self.instance,
                        state.active.epoch,
                        &state.active.envelope,
                    )
                    .map_err(|_| LocalKeyRotationFailure::Authentication)?;
                let catalog = self.rotation_catalog_for_operation(&session, context)?;
                let current = catalog
                    .pin()
                    .map_err(|_| LocalKeyRotationFailure::Storage)?;
                if current.identity() != snapshot.identity()
                    || self
                        .key
                        .root_admission_receipt()
                        .map_err(|_| LocalKeyRotationFailure::Custody)?
                        != source_receipt
                {
                    return Err(LocalKeyRotationFailure::Busy);
                }
                confirm_state(&catalog, &state)?;
                activation
                    .activate(&self.key)
                    .map_err(|_| LocalKeyRotationFailure::Custody)?;
            }
            return Ok(state.status());
        };
        drop(catalog);
        let access = self
            .bootstrap_storage
            .inspect()
            .map_err(|_| LocalKeyRotationFailure::Custody)?;
        let successor = session
            .open_successor(&access, route.epoch)
            .map_err(|_| LocalKeyRotationFailure::Custody)?;
        if successor.identity() != route.identity {
            return Err(LocalKeyRotationFailure::Authentication);
        }
        session
            .publish_successor_routes(&access, &self.key, &successor, self.instance, route.epoch)
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        let activation = session
            .prepare_activation(
                &self.key,
                successor,
                self.instance,
                route.epoch,
                &route.envelope,
            )
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let catalog = self.rotation_catalog_for_operation(&session, context)?;
        let current = catalog
            .pin()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        if current.identity() != snapshot.identity()
            || self
                .key
                .root_admission_receipt()
                .map_err(|_| LocalKeyRotationFailure::Custody)?
                != source_receipt
        {
            return Err(LocalKeyRotationFailure::Busy);
        }
        state.predecessor = Some(std::mem::replace(&mut state.active, route));
        state.transaction = match context {
            Some(context) => context.transaction(CatalogRootRotationStage::Cutover)?,
            None => self.rotation_transaction()?,
        };
        if let Err(failure) = self.publish_rotation_for_operation(
            &catalog,
            &snapshot,
            &state,
            CatalogRootRotationStage::Cutover,
            state.transaction,
            context,
        ) {
            // Durability confirmation refreshes the exact authenticated committed
            // state before synchronizing it. A visible cutover must not leave the
            // predecessor provider serving new root envelopes after a sync error.
            let visible = catalog
                .pin()
                .map_err(|_| LocalKeyRotationFailure::Storage)?;
            if State::find(&visible)?.as_ref() == Some(&state) {
                drop(catalog);
                let activation = activation
                    .revalidate(&self.key, self.instance)
                    .map_err(|_| LocalKeyRotationFailure::Custody)?;
                let catalog = self.rotation_catalog_for_operation(&session, context)?;
                if catalog
                    .pin()
                    .map_err(|_| LocalKeyRotationFailure::Storage)?
                    .identity()
                    != visible.identity()
                {
                    return Err(LocalKeyRotationFailure::Busy);
                }
                activation
                    .activate(&self.key)
                    .map_err(|_| LocalKeyRotationFailure::Custody)?;
                self.record_catalog_generation(visible.number());
            }
            return Err(failure);
        }
        activation
            .activate(&self.key)
            .map_err(|_| LocalKeyRotationFailure::Custody)?;
        Ok(state.status())
    }
}
pub(crate) fn reopen_active_route(
    authority: &positron_kernel::StorageKernelResourceAuthority,
    storage: &positron_kernel::InstanceBootstrapStorage,
    instance: positron_kernel::InstanceId,
    key: positron_kernel::BootstrapKeyCustody,
) -> Result<positron_kernel::BootstrapKeyCustody, LocalKeyRotationFailure> {
    let session =
        RootRewrapSession::admit(authority).map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
    let secret = key
        .catalog_secret(instance)
        .map_err(|_| LocalKeyRotationFailure::Custody)?;
    let catalog =
        Catalog::open(authority, instance, secret).map_err(|_| LocalKeyRotationFailure::Storage)?;
    let snapshot = catalog
        .pin()
        .map_err(|_| LocalKeyRotationFailure::Storage)?;
    let native = key
        .active_provider_identity()
        .map_err(|_| LocalKeyRotationFailure::Custody)?
        .family()
        != positron_kernel::key_provider::ProviderFamily::LocalFile;
    let Some(state) = State::find(&snapshot)? else {
        if native {
            return Err(LocalKeyRotationFailure::Authentication);
        }
        return Ok(key);
    };
    if state.instance != instance || state.anchor != key.bootstrap_identity() {
        return Err(LocalKeyRotationFailure::Authentication);
    }
    confirm_state(&catalog, &state)?;
    if state.active.identity
        == key
            .active_root_identity()
            .map_err(|_| LocalKeyRotationFailure::Custody)?
    {
        if state.active.epoch
            != key
                .active_root_epoch()
                .map_err(|_| LocalKeyRotationFailure::Custody)?
        {
            return Err(LocalKeyRotationFailure::Authentication);
        }
        if native
            && session
                .active_system_envelope(&key, instance)
                .map_err(|_| LocalKeyRotationFailure::Authentication)?
                != state.active.envelope
        {
            return Err(LocalKeyRotationFailure::Authentication);
        }
        return Ok(key);
    }
    if native {
        return Err(LocalKeyRotationFailure::Authentication);
    }
    let access = storage
        .inspect()
        .map_err(|_| LocalKeyRotationFailure::Custody)?;
    let active = session
        .open_successor(&access, state.active.epoch)
        .map_err(|_| LocalKeyRotationFailure::Custody)?;
    if active.identity() != state.active.identity {
        return Err(LocalKeyRotationFailure::Authentication);
    }
    session
        .open_system(
            active,
            instance,
            state.anchor,
            state.active.epoch,
            &state.active.envelope,
        )
        .map_err(|_| LocalKeyRotationFailure::Authentication)
}

pub(super) fn confirm_state(
    catalog: &Catalog<'_>,
    state: &State,
) -> Result<(), LocalKeyRotationFailure> {
    let committed = catalog
        .confirm_committed_transaction(state.transaction)
        .map_err(|_| LocalKeyRotationFailure::Storage)?
        .ok_or(LocalKeyRotationFailure::Authentication)?;
    if State::find(committed.snapshot())?.as_ref() != Some(state) {
        return Err(LocalKeyRotationFailure::Authentication);
    }
    Ok(())
}
