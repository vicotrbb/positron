//! Catalog authorization precedes exact custody removal and route pruning.
use super::*;
use crate::instance_bootstrap::{BackupRepositoryInspection, RecoveryReadiness};

impl InitializedInstance {
    pub fn retire_local_key_predecessor(&self) -> Result<(), LocalKeyRotationFailure> {
        let session = RootRewrapSession::admit_provider(&self._authority)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        if self
            .backup_key_recovery_readiness()
            .map_err(|_| LocalKeyRotationFailure::Custody)?
            != RecoveryReadiness::Verified
        {
            return Err(LocalKeyRotationFailure::Custody);
        }
        self.retire_root_predecessor(&session, None, true, None, None)
    }
    pub fn verify_key_provider_migration(
        &self,
        configuration: positron_kernel::key_provider::NativeRootConfiguration,
    ) -> Result<super::KeyProviderMigrationStatus, LocalKeyRotationFailure> {
        let session = RootRewrapSession::admit_provider(&self._authority)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        let basis = self.provider_retirement_proof(&session, configuration, None)?;
        self.retire_root_predecessor(&session, Some(&basis), false, None, None)?;
        self.key_provider_migration_status()
    }
    pub fn verify_local_key_rotation(
        &self,
    ) -> Result<LocalKeyRotationStatus, LocalKeyRotationFailure> {
        let session = RootRewrapSession::admit_provider(&self._authority)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        if self
            .backup_key_recovery_readiness()
            .map_err(|_| LocalKeyRotationFailure::Custody)?
            != RecoveryReadiness::Verified
        {
            return Err(LocalKeyRotationFailure::Custody);
        }
        self.retire_root_predecessor(&session, None, false, None, None)?;
        self.local_key_rotation_status()
    }
    pub fn retire_key_provider_predecessor(
        &self,
        configuration: positron_kernel::key_provider::NativeRootConfiguration,
    ) -> Result<(), LocalKeyRotationFailure> {
        let session = RootRewrapSession::admit_provider(&self._authority)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        let basis = self.provider_retirement_proof(&session, configuration, None)?;
        self.retire_root_predecessor(&session, Some(&basis), true, None, None)
    }
    pub(crate) fn verify_or_retire_key_provider_for_operation(
        &self,
        configuration: Option<positron_kernel::key_provider::NativeRootConfiguration>,
        context: RootMigrationContext<'_>,
        execution: &positron_kernel::MaintenanceExecution<'_>,
        retire: bool,
    ) -> Result<(), LocalKeyRotationFailure> {
        let session = RootRewrapSession::admit_provider(&self._authority)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        let basis = if let Some(configuration) = configuration {
            Some(self.provider_retirement_proof(&session, configuration, Some(context))?)
        } else {
            if self
                .backup_key_recovery_readiness()
                .map_err(|_| LocalKeyRotationFailure::Custody)?
                != RecoveryReadiness::Verified
            {
                return Err(LocalKeyRotationFailure::Custody);
            }
            None
        };
        let binding = positron_kernel::RootProviderMigrationBinding::from_execution(execution)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        if binding.operation_id() != context.operation.to_bytes() {
            return Err(LocalKeyRotationFailure::Authentication);
        }
        self.retire_root_predecessor(
            &session,
            basis.as_ref(),
            retire,
            Some(context),
            Some((execution, binding)),
        )
    }
    fn provider_retirement_proof(
        &self,
        session: &RootRewrapSession<'_>,
        configuration: positron_kernel::key_provider::NativeRootConfiguration,
        context: Option<RootMigrationContext<'_>>,
    ) -> Result<positron_kernel::CatalogSnapshot, LocalKeyRotationFailure> {
        let catalog = self.rotation_catalog_for_operation(session, context)?;
        let mut basis = catalog
            .pin()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        let state = State::find(&basis)?.ok_or(LocalKeyRotationFailure::InvalidInput)?;
        if state.cancelled {
            return Err(LocalKeyRotationFailure::Busy);
        }
        let active = positron_kernel::key_provider::KeyEnvelope::decode(&state.active.envelope)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        if state.instance != self.instance
            || state.anchor != self.key.bootstrap_identity()
            || active.identity() != configuration.identity()
            || state.successor.is_some()
        {
            return Err(LocalKeyRotationFailure::Authentication);
        }
        super::cutover::confirm_state(&catalog, &state)?;
        if self.reclaim_terminal_migration_references(session, &catalog)? {
            basis = catalog
                .pin()
                .map_err(|_| LocalKeyRotationFailure::Storage)?;
            if State::find(&basis)?.as_ref() != Some(&state) {
                return Err(LocalKeyRotationFailure::Busy);
            }
        }
        drop(catalog);
        let access = self
            .bootstrap_storage
            .inspect()
            .map_err(|_| LocalKeyRotationFailure::Custody)?;
        let recovered = session
            .open_provider_recovery(
                &access,
                configuration,
                positron_kernel::key_provider::KeyCacheLease::default(),
            )
            .map_err(|failure| {
                super::provider_migration::provider_failure(
                    failure,
                    LocalKeyRotationFailure::Custody,
                )
            })?;
        session
            .verify_provider_recovery(&self.key, &recovered, self.instance)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        drop(recovered);
        Ok(basis)
    }
    fn retire_root_predecessor(
        &self,
        session: &RootRewrapSession<'_>,
        native_proof: Option<&positron_kernel::CatalogSnapshot>,
        retire: bool,
        context: Option<RootMigrationContext<'_>>,
        own_execution: Option<(
            &positron_kernel::MaintenanceExecution<'_>,
            positron_kernel::RootProviderMigrationBinding,
        )>,
    ) -> Result<(), LocalKeyRotationFailure> {
        let catalog = self.rotation_catalog_for_operation(session, context)?;
        let mut basis = catalog
            .pin()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        if native_proof.is_some_and(|proof| proof.identity() != basis.identity()) {
            return Err(LocalKeyRotationFailure::Busy);
        }
        let mut state = State::find(&basis)?.ok_or(LocalKeyRotationFailure::InvalidInput)?;
        if state.cancelled {
            return Err(LocalKeyRotationFailure::Busy);
        }
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
        if native_proof.is_none()
            && self.reclaim_terminal_migration_references(session, &catalog)?
        {
            basis = catalog
                .pin()
                .map_err(|_| LocalKeyRotationFailure::Storage)?;
            if State::find(&basis)?.as_ref() != Some(&state) {
                return Err(LocalKeyRotationFailure::Busy);
            }
        }
        let recovery_predecessor_absent = if native_proof.is_some() {
            self.provider_recovery_references_are_absent(&catalog, &basis)
                .map_err(|_| LocalKeyRotationFailure::Authentication)?
        } else {
            self.recovery_predecessor_is_absent(&basis)
                .map_err(|_| LocalKeyRotationFailure::Authentication)?
        };
        BackupRepositoryInspection::from_authenticated_catalog(&basis)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let Some(predecessor) = state.predecessor.clone() else {
            if !recovery_predecessor_absent {
                self.publish_rotation_for_operation(
                    &catalog,
                    &basis,
                    &state,
                    CatalogRootRotationStage::RetirementRefused,
                    self.operation_rotation_transaction(
                        context,
                        CatalogRootRotationStage::RetirementRefused,
                    )?,
                    context,
                )?;
                return Err(if context.is_some() {
                    LocalKeyRotationFailure::RetirementRefused
                } else {
                    LocalKeyRotationFailure::Busy
                });
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
        let source = positron_kernel::key_provider::KeyEnvelope::decode(&predecessor.envelope)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        if !state.retiring
            && source.identity().family()
                == positron_kernel::key_provider::ProviderFamily::LocalFile
        {
            session
                .verify_predecessor_custody(&access, predecessor.epoch, predecessor.identity)
                .map_err(|_| LocalKeyRotationFailure::Custody)?;
        }
        if !recovery_predecessor_absent {
            self.publish_rotation_for_operation(
                &catalog,
                &basis,
                &state,
                CatalogRootRotationStage::RetirementRefused,
                self.operation_rotation_transaction(
                    context,
                    CatalogRootRotationStage::RetirementRefused,
                )?,
                context,
            )?;
            return Err(if context.is_some() {
                LocalKeyRotationFailure::RetirementRefused
            } else {
                LocalKeyRotationFailure::Busy
            });
        }
        let coordinator = self.maintenance_coordinator();
        let references = match own_execution {
            Some((execution, binding)) => coordinator
                .guard_root_retirement_for_migration(session, &catalog, &basis, execution, binding),
            None => coordinator.guard_root_retirement_references(session, &catalog, &basis),
        };
        let _references = match references {
            Ok(guard) => guard,
            Err(
                positron_kernel::MaintenanceFailure::ConcurrentAccess
                | positron_kernel::MaintenanceFailure::PreconditionFailed,
            ) => {
                self.publish_rotation_for_operation(
                    &catalog,
                    &basis,
                    &state,
                    CatalogRootRotationStage::RetirementRefused,
                    self.operation_rotation_transaction(
                        context,
                        CatalogRootRotationStage::RetirementRefused,
                    )?,
                    context,
                )?;
                return Err(if context.is_some() {
                    LocalKeyRotationFailure::RetirementRefused
                } else {
                    LocalKeyRotationFailure::Busy
                });
            },
            Err(_) => return Err(LocalKeyRotationFailure::Busy),
        };
        let guard =
            match positron_kernel::ActiveSegmentLedger::guard_local_root_retirement_with_references(
                &self._authority,
                &catalog,
                &_references,
            ) {
                Ok(guard) => guard,
                Err(failure)
                    if failure.code() == positron_kernel::LedgerFailureCode::ConcurrentWriter =>
                {
                    self.publish_rotation_for_operation(
                        &catalog,
                        &basis,
                        &state,
                        CatalogRootRotationStage::RetirementRefused,
                        self.operation_rotation_transaction(
                            context,
                            CatalogRootRotationStage::RetirementRefused,
                        )?,
                        context,
                    )?;
                    return Err(if context.is_some() {
                        LocalKeyRotationFailure::RetirementRefused
                    } else {
                        LocalKeyRotationFailure::Busy
                    });
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
        let prepared = if !state.retiring {
            let verified =
                if super::root_verification_audit::confirm_existing(&catalog, &basis, &state)? {
                    basis.clone()
                } else {
                    self.publish_rotation_for_operation(
                        &catalog,
                        &basis,
                        &state,
                        CatalogRootRotationStage::Verified,
                        self.operation_rotation_transaction(
                            context,
                            CatalogRootRotationStage::Verified,
                        )?,
                        context,
                    )?
                };
            if !retire {
                return Ok(());
            }
            state.retiring = true;
            state.transaction = self.operation_rotation_transaction(
                context,
                CatalogRootRotationStage::RetirementPrepared,
            )?;
            self.publish_rotation_for_operation(
                &catalog,
                &verified,
                &state,
                CatalogRootRotationStage::RetirementPrepared,
                state.transaction,
                context,
            )?
        } else {
            super::cutover::confirm_state(&catalog, &state)?;
            basis.clone()
        };
        if !retire {
            return Ok(());
        }
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
        state.transaction =
            self.operation_rotation_transaction(context, CatalogRootRotationStage::Completed)?;
        self.publish_rotation_for_operation(
            &catalog,
            &prepared,
            &state,
            CatalogRootRotationStage::Completed,
            state.transaction,
            context,
        )
        .map(|_| ())
    }
    fn reclaim_terminal_migration_references(
        &self,
        session: &RootRewrapSession<'_>,
        catalog: &Catalog<'_>,
    ) -> Result<bool, LocalKeyRotationFailure> {
        match self
            .maintenance_coordinator()
            .reclaim_terminal_records_for_root_retirement(session, catalog)
        {
            Ok(count) => Ok(count != 0),
            // Existing reference guards below audit and refuse retained work.
            Err(positron_kernel::MaintenanceFailure::ConcurrentAccess) => Ok(false),
            Err(positron_kernel::MaintenanceFailure::CatalogUnavailable) => {
                Err(LocalKeyRotationFailure::Storage)
            },
            Err(positron_kernel::MaintenanceFailure::CapacityExceeded) => {
                Err(LocalKeyRotationFailure::LimitExceeded)
            },
            Err(_) => Err(LocalKeyRotationFailure::Authentication),
        }
    }
}
