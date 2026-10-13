//! Cross-provider phases reuse the authenticated root rotation Catalog owner.
use super::*;
use positron_kernel::key_provider::{KeyEnvelope, NativeRootConfiguration, ProviderKeyUri};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyProviderMigrationStatus {
    active: ProviderKeyUri,
    source: ProviderKeyUri,
    target: Option<ProviderKeyUri>,
    rotation: LocalKeyRotationStatus,
}
impl KeyProviderMigrationStatus {
    pub fn active_provider(&self) -> &ProviderKeyUri {
        &self.active
    }
    pub fn source_provider(&self) -> &ProviderKeyUri {
        &self.source
    }
    pub fn target_provider(&self) -> Option<&ProviderKeyUri> {
        self.target.as_ref()
    }
    pub fn rotation(&self) -> LocalKeyRotationStatus {
        self.rotation
    }
}
fn identity(route: &Route) -> Result<ProviderKeyUri, LocalKeyRotationFailure> {
    KeyEnvelope::decode(&route.envelope)
        .map(|envelope| envelope.identity().clone())
        .map_err(|_| LocalKeyRotationFailure::Authentication)
}
fn status(state: &State) -> Result<KeyProviderMigrationStatus, LocalKeyRotationFailure> {
    let active = identity(&state.active)?;
    Ok(KeyProviderMigrationStatus {
        source: state
            .migration_source
            .clone()
            .or(state.predecessor.as_ref().map(identity).transpose()?)
            .unwrap_or_else(|| active.clone()),
        target: state
            .successor
            .as_ref()
            .map(identity)
            .transpose()?
            .or_else(|| state.migration_source.as_ref().map(|_| active.clone())),
        active,
        rotation: state.status(),
    })
}
impl InitializedInstance {
    pub fn key_provider_migration_status(
        &self,
    ) -> Result<KeyProviderMigrationStatus, LocalKeyRotationFailure> {
        let session = RootRewrapSession::admit_provider(&self._authority)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        let catalog = self.rotation_catalog(&session)?;
        self.key_provider_migration_status_from_catalog(&catalog)
    }
    pub(crate) fn key_provider_migration_status_from_catalog(
        &self,
        catalog: &Catalog<'_>,
    ) -> Result<KeyProviderMigrationStatus, LocalKeyRotationFailure> {
        let snapshot = catalog
            .pin()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        if let Some(state) = State::find(&snapshot)? {
            if state.instance != self.instance || state.anchor != self.key.bootstrap_identity() {
                return Err(LocalKeyRotationFailure::Authentication);
            }
            status(&state)
        } else {
            let active = self
                .key
                .active_provider_identity()
                .map_err(|_| LocalKeyRotationFailure::Custody)?;
            Ok(KeyProviderMigrationStatus {
                source: active.clone(),
                target: None,
                active,
                rotation: LocalKeyRotationStatus {
                    active_epoch: self
                        .key
                        .active_root_epoch()
                        .map_err(|_| LocalKeyRotationFailure::Custody)?,
                    successor_epoch: None,
                    predecessor_epoch: None,
                    phase: LocalKeyRotationPhase::Active,
                },
            })
        }
    }
    /// Verifies native target custody before publishing any migration intent.
    /// A committed prepared envelope is immutable across retries and restarts.
    pub fn begin_key_provider_migration(
        &self,
        configuration: NativeRootConfiguration,
    ) -> Result<KeyProviderMigrationStatus, LocalKeyRotationFailure> {
        self.begin_key_provider_migration_for_operation(configuration, None)
    }
    pub(crate) fn begin_key_provider_migration_for_operation(
        &self,
        configuration: NativeRootConfiguration,
        context: Option<RootMigrationContext<'_>>,
    ) -> Result<KeyProviderMigrationStatus, LocalKeyRotationFailure> {
        let session = RootRewrapSession::admit_provider(&self._authority)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        let catalog = self.rotation_catalog_for_operation(&session, context)?;
        let snapshot = catalog
            .pin()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        if let Some(state) = State::find(&snapshot)? {
            if state.instance != self.instance || state.anchor != self.key.bootstrap_identity() {
                return Err(LocalKeyRotationFailure::Authentication);
            }
            if state.cancelled {
                return Err(LocalKeyRotationFailure::Busy);
            }
            if let Some(successor) = state.successor.as_ref() {
                if identity(successor)? != *configuration.identity() {
                    return Err(LocalKeyRotationFailure::Busy);
                }
                super::cutover::confirm_state(&catalog, &state)?;
                return status(&state);
            }
            if state.predecessor.is_some() || state.retiring {
                return Err(LocalKeyRotationFailure::Busy);
            }
        }
        let source_receipt = self
            .key
            .root_admission_receipt()
            .map_err(|_| LocalKeyRotationFailure::Custody)?;
        drop(catalog);
        let active_epoch = source_receipt.epoch();
        let successor_epoch = active_epoch
            .checked_add(1)
            .ok_or(LocalKeyRotationFailure::LimitExceeded)?;
        let provider = session
            .native_provider(configuration)
            .map_err(|failure| provider_failure(failure, LocalKeyRotationFailure::Custody))?;
        let migration = session
            .prepare_provider_migration_blocking(
                &self.key,
                provider,
                self.instance,
                successor_epoch,
            )
            .map_err(|failure| {
                provider_failure(failure, LocalKeyRotationFailure::Authentication)
            })?;
        // Native I/O holds no Catalog/custody lock; the exact basis is refreshed
        // before installing the verified route.
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
        let state = State {
            instance: self.instance,
            transaction: match context {
                Some(context) => context.transaction(CatalogRootRotationStage::Started)?,
                None => self.rotation_transaction()?,
            },
            anchor: self.key.bootstrap_identity(),
            active: Route {
                epoch: active_epoch,
                identity: source_receipt.identity(),
                envelope: session
                    .active_system_envelope(&self.key, self.instance)
                    .map_err(|_| LocalKeyRotationFailure::Authentication)?,
            },
            successor: Some(Route {
                epoch: successor_epoch,
                identity: migration.root_identity(),
                envelope: migration.envelope().to_vec(),
            }),
            predecessor: None,
            retiring: false,
            cancelled: false,
            provider_format: true,
            migration_source: Some(
                self.key
                    .active_provider_identity()
                    .map_err(|_| LocalKeyRotationFailure::Custody)?,
            ),
        };
        self.publish_rotation_for_operation(
            &catalog,
            &snapshot,
            &state,
            CatalogRootRotationStage::Started,
            state.transaction,
            context,
        )?;
        status(&state)
    }
    #[cfg(test)]
    pub(in crate::instance_bootstrap) fn with_native_migration_fixture_payload<T>(
        &self,
        provider: &ProviderKeyUri,
        fixture: impl FnOnce(&[u8]) -> T,
    ) -> Result<T, LocalKeyRotationFailure> {
        let session = RootRewrapSession::admit_provider(&self._authority)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        session
            .with_native_fixture_system_payload(&self.key, self.instance, provider, fixture)
            .map_err(|_| LocalKeyRotationFailure::Custody)
    }
}

impl InitializedInstance {
    /// Commits the independently verified prepared target as the new-write route.
    pub fn activate_key_provider_migration(
        &self,
        configuration: NativeRootConfiguration,
    ) -> Result<KeyProviderMigrationStatus, LocalKeyRotationFailure> {
        self.activate_key_provider_migration_for_operation(configuration, None)
    }
    pub(crate) fn activate_key_provider_migration_for_operation(
        &self,
        configuration: NativeRootConfiguration,
        context: Option<RootMigrationContext<'_>>,
    ) -> Result<KeyProviderMigrationStatus, LocalKeyRotationFailure> {
        let session = RootRewrapSession::admit_provider(&self._authority)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        let catalog = self.rotation_catalog_for_operation(&session, context)?;
        let snapshot = catalog
            .pin()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        let mut state = State::find(&snapshot)?.ok_or(LocalKeyRotationFailure::InvalidInput)?;
        if state.instance != self.instance || state.anchor != self.key.bootstrap_identity() {
            return Err(LocalKeyRotationFailure::Authentication);
        }
        super::cutover::confirm_state(&catalog, &state)?;
        if state.cancelled {
            return Err(LocalKeyRotationFailure::Busy);
        }
        let source_receipt = self
            .key
            .root_admission_receipt()
            .map_err(|_| LocalKeyRotationFailure::Custody)?;
        let Some(target) = state.successor.clone() else {
            if identity(&state.active)? != *configuration.identity() {
                return Err(LocalKeyRotationFailure::Authentication);
            }
            let current_is_active = source_receipt.identity() == state.active.identity
                && source_receipt.epoch() == state.active.epoch;
            let current_is_predecessor = state.predecessor.as_ref().is_some_and(|route| {
                route.identity == source_receipt.identity() && route.epoch == source_receipt.epoch()
            });
            if !current_is_active && !current_is_predecessor {
                return Err(LocalKeyRotationFailure::Authentication);
            }
            drop(catalog);
            let provider = session
                .native_provider(configuration)
                .map_err(|failure| provider_failure(failure, LocalKeyRotationFailure::Custody))?;
            let activation = session
                .prepare_provider_activation(
                    &self.key,
                    provider,
                    self.instance,
                    state.active.epoch,
                    &state.active.envelope,
                )
                .map_err(|failure| {
                    provider_failure(failure, LocalKeyRotationFailure::Authentication)
                })?;
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
            super::cutover::confirm_state(&catalog, &state)?;
            activation
                .activate(&self.key)
                .map_err(|_| LocalKeyRotationFailure::Custody)?;
            return status(&state);
        };
        if identity(&target)? != *configuration.identity() {
            return Err(LocalKeyRotationFailure::Authentication);
        }
        drop(catalog);
        let provider = session
            .native_provider(configuration)
            .map_err(|failure| provider_failure(failure, LocalKeyRotationFailure::Custody))?;
        let activation = session
            .prepare_provider_activation(
                &self.key,
                provider,
                self.instance,
                target.epoch,
                &target.envelope,
            )
            .map_err(|failure| {
                provider_failure(failure, LocalKeyRotationFailure::Authentication)
            })?;
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
        let access = self
            .bootstrap_storage
            .inspect()
            .map_err(|_| LocalKeyRotationFailure::Custody)?;
        session
            .publish_provider_routes(
                &access,
                &self.key,
                self.instance,
                target.identity,
                target.epoch,
                &target.envelope,
            )
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        state.successor = None;
        state.predecessor = Some(std::mem::replace(&mut state.active, target));
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
            let visible = catalog
                .pin()
                .map_err(|_| LocalKeyRotationFailure::Storage)?;
            if State::find(&visible)?.as_ref() == Some(&state) {
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
        status(&state)
    }
}

impl InitializedInstance {
    /// Cancellation preserves both immutable routes. After cutover, new writes
    /// continue through the committed destination; no predecessor rollback occurs.
    pub fn cancel_key_provider_migration(
        &self,
    ) -> Result<KeyProviderMigrationStatus, LocalKeyRotationFailure> {
        self.set_key_provider_migration_cancelled(true, None)
    }
    pub fn resume_key_provider_migration(
        &self,
    ) -> Result<KeyProviderMigrationStatus, LocalKeyRotationFailure> {
        self.set_key_provider_migration_cancelled(false, None)
    }
    fn set_key_provider_migration_cancelled(
        &self,
        cancelled: bool,
        context: Option<RootMigrationContext<'_>>,
    ) -> Result<KeyProviderMigrationStatus, LocalKeyRotationFailure> {
        let session = RootRewrapSession::admit_provider(&self._authority)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        let catalog = self.rotation_catalog_for_operation(&session, context)?;
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
        {
            return Err(LocalKeyRotationFailure::Authentication);
        }
        if state.retiring || state.successor.is_none() && state.predecessor.is_none() {
            return Err(LocalKeyRotationFailure::InvalidInput);
        }
        super::cutover::confirm_state(&catalog, &state)?;
        if state.cancelled == cancelled {
            return status(&state);
        }
        if state.migration_source.is_none() {
            state.migration_source = Some(identity(
                state.predecessor.as_ref().unwrap_or(&state.active),
            )?);
        }
        state.provider_format = true;
        state.cancelled = cancelled;
        let stage = if cancelled {
            CatalogRootRotationStage::Cancelled
        } else {
            CatalogRootRotationStage::Resumed
        };
        state.transaction = match context {
            Some(context) => context.transaction(stage)?,
            None => self.rotation_transaction()?,
        };
        self.publish_rotation_for_operation(
            &catalog,
            &basis,
            &state,
            if cancelled {
                CatalogRootRotationStage::Cancelled
            } else {
                CatalogRootRotationStage::Resumed
            },
            state.transaction,
            context,
        )?;
        status(&state)
    }
    pub(crate) fn set_key_provider_migration_cancelled_for_operation(
        &self,
        cancelled: bool,
        context: RootMigrationContext<'_>,
    ) -> Result<KeyProviderMigrationStatus, LocalKeyRotationFailure> {
        self.set_key_provider_migration_cancelled(cancelled, Some(context))
    }
}

pub(super) fn provider_failure(
    failure: positron_kernel::key_provider::KeyProviderFailure,
    fallback: LocalKeyRotationFailure,
) -> LocalKeyRotationFailure {
    if failure == positron_kernel::key_provider::KeyProviderFailure::LimitExceeded {
        LocalKeyRotationFailure::LimitExceeded
    } else {
        fallback
    }
}
