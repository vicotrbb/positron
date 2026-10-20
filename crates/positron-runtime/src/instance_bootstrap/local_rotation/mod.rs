//! Resumable local-root wrapping through the existing Catalog and custody owners.
use super::InitializedInstance;
use positron_governance::{CatalogRootRotationStage, catalog_root_rotation_audit_intent};
use positron_kernel::{Catalog, CatalogObject, CatalogProposal, RootRewrapSession, TransactionId};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter};

#[cfg(test)]
pub(crate) type BackupRouteRecheckHook = std::sync::Mutex<
    Option<for<'context> fn(&InitializedInstance, RootMigrationContext<'context>)>,
>;

#[derive(Clone, Copy)]
pub(crate) struct RootMigrationContext<'runtime> {
    pub(crate) principal: positron_domain::identity::PrincipalId,
    pub(crate) operation: positron_governance::OperationId,
    pub(crate) catalog_gate: &'runtime std::sync::Mutex<()>,
    #[cfg(test)]
    pub(crate) backup_route_recheck: Option<&'runtime BackupRouteRecheckHook>,
}
impl RootMigrationContext<'_> {
    fn transaction(
        self,
        stage: CatalogRootRotationStage,
    ) -> Result<TransactionId, LocalKeyRotationFailure> {
        let mut hash = Sha256::new();
        hash.update(b"positron.root-provider-migration.publication.v1\0");
        hash.update(self.operation.to_bytes());
        hash.update([match stage {
            CatalogRootRotationStage::Started => 1,
            CatalogRootRotationStage::Cutover => 2,
            CatalogRootRotationStage::Verified => 3,
            CatalogRootRotationStage::RetirementPrepared => 4,
            CatalogRootRotationStage::RetirementRefused => 5,
            CatalogRootRotationStage::Completed => 6,
            CatalogRootRotationStage::Cancelled => 7,
            CatalogRootRotationStage::Resumed => 8,
            CatalogRootRotationStage::Restored => 9,
        }]);
        let digest = hash.finalize();
        let bytes = digest
            .get(..16)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(LocalKeyRotationFailure::Storage)?;
        TransactionId::new(bytes).map_err(|_| LocalKeyRotationFailure::Storage)
    }
}
/// The serving gate and Kernel writer lease have the same lifetime. Dropping
/// this Catalog before native I/O releases both, allowing ingestion to proceed.
struct RootRotationCatalog<'owner> {
    catalog: Catalog<'owner>,
    _gate: Option<std::sync::MutexGuard<'owner, ()>>,
}
impl<'owner> std::ops::Deref for RootRotationCatalog<'owner> {
    type Target = Catalog<'owner>;
    fn deref(&self) -> &Self::Target {
        &self.catalog
    }
}
impl std::ops::DerefMut for RootRotationCatalog<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.catalog
    }
}
mod backup_envelopes;
pub(crate) use backup_envelopes::{BackupRootRetirementProof, registration_digest};
mod cutover;
mod provider_migration;
pub use provider_migration::KeyProviderMigrationStatus;
mod restore;
mod root_retirement;
mod root_verification_audit;
mod state;
pub(crate) use restore::adopt_restored_route;
mod tenant;
mod tenant_migration;
mod tenant_retirement;
mod tenant_verification;
mod tenant_verification_execution;
mod tenant_verification_restart;
pub(crate) use cutover::reopen_active_route;
use state::{Route, State};
pub use tenant::TenantKeyRotationStatus;
pub use tenant_migration::TenantKeyMigrationProgress;
pub use tenant_verification::TenantKeyVerificationProgress;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalKeyRotationFailure {
    Custody,
    Authentication,
    LimitExceeded,
    Storage,
    Busy,
    /// This attempt durably audited refusal of an owned migration phase.
    RetirementRefused,
    InvalidInput,
}
impl Display for LocalKeyRotationFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "local key rotation failed: {self:?}")
    }
}
impl std::error::Error for LocalKeyRotationFailure {}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalKeyRotationPhase {
    Active,
    Prepared,
    Verifying,
    Retiring,
    Cancelled,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalKeyRotationStatus {
    active_epoch: u64,
    successor_epoch: Option<u64>,
    predecessor_epoch: Option<u64>,
    phase: LocalKeyRotationPhase,
}
impl LocalKeyRotationStatus {
    #[must_use]
    pub const fn active_epoch(self) -> u64 {
        self.active_epoch
    }
    #[must_use]
    pub const fn successor_epoch(self) -> Option<u64> {
        self.successor_epoch
    }
    #[must_use]
    pub const fn predecessor_epoch(self) -> Option<u64> {
        self.predecessor_epoch
    }
    #[must_use]
    pub const fn phase(self) -> LocalKeyRotationPhase {
        self.phase
    }
}
impl InitializedInstance {
    fn rotation_catalog_for_operation<'owner>(
        &'owner self,
        session: &RootRewrapSession<'_>,
        context: Option<RootMigrationContext<'owner>>,
    ) -> Result<RootRotationCatalog<'owner>, LocalKeyRotationFailure> {
        let gate = context
            .map(|context| {
                context
                    .catalog_gate
                    .lock()
                    .map_err(|_| LocalKeyRotationFailure::Storage)
            })
            .transpose()?;
        let catalog = self.rotation_catalog(session)?;
        Ok(RootRotationCatalog {
            catalog,
            _gate: gate,
        })
    }
    fn rotation_catalog(
        &self,
        session: &RootRewrapSession<'_>,
    ) -> Result<Catalog<'_>, LocalKeyRotationFailure> {
        let secret = session
            .rotation_catalog_secret(&self.key, self.instance)
            .map_err(|_| LocalKeyRotationFailure::Custody)?;
        Catalog::open(&self._authority, self.instance, secret).map_err(|failure| {
            match failure.code() {
                positron_kernel::CatalogFailureCode::ConcurrentWriter
                | positron_kernel::CatalogFailureCode::StaleGeneration => {
                    LocalKeyRotationFailure::Busy
                },
                positron_kernel::CatalogFailureCode::ResourceAdmissionRefused
                | positron_kernel::CatalogFailureCode::LimitExceeded => {
                    LocalKeyRotationFailure::LimitExceeded
                },
                _ => LocalKeyRotationFailure::Storage,
            }
        })
    }
    pub fn local_key_rotation_status(
        &self,
    ) -> Result<LocalKeyRotationStatus, LocalKeyRotationFailure> {
        let session = RootRewrapSession::admit(&self._authority)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        let catalog = self.rotation_catalog(&session)?;
        let snapshot = catalog
            .pin()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        match State::find(&snapshot)? {
            Some(state)
                if state.instance == self.instance
                    && state.anchor == self.key.bootstrap_identity() =>
            {
                Ok(state.status())
            },
            Some(_) => Err(LocalKeyRotationFailure::Authentication),
            None => Ok(LocalKeyRotationStatus {
                active_epoch: 1,
                successor_epoch: None,
                predecessor_epoch: None,
                phase: LocalKeyRotationPhase::Active,
            }),
        }
    }
    pub fn begin_local_key_rotation(
        &self,
    ) -> Result<LocalKeyRotationStatus, LocalKeyRotationFailure> {
        self.begin_local_key_rotation_for_operation(None)
    }
    pub(crate) fn begin_local_key_rotation_for_operation(
        &self,
        context: Option<RootMigrationContext<'_>>,
    ) -> Result<LocalKeyRotationStatus, LocalKeyRotationFailure> {
        let session = RootRewrapSession::admit_provider(&self._authority)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        let catalog = self.rotation_catalog_for_operation(&session, context)?;
        let snapshot = catalog
            .pin()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        let previous = State::find(&snapshot)?;
        if let Some(state) = previous.as_ref() {
            if state.instance != self.instance || state.anchor != self.key.bootstrap_identity() {
                return Err(LocalKeyRotationFailure::Authentication);
            }
            if state.cancelled {
                return Err(LocalKeyRotationFailure::Busy);
            }
            if let Some(successor) = &state.successor {
                let target =
                    positron_kernel::key_provider::KeyEnvelope::decode(&successor.envelope)
                        .map_err(|_| LocalKeyRotationFailure::Authentication)?;
                if target.identity().family()
                    != positron_kernel::key_provider::ProviderFamily::LocalFile
                {
                    return Err(LocalKeyRotationFailure::Busy);
                }
                cutover::confirm_state(&catalog, state)?;
                return Ok(state.status());
            }
            if state.predecessor.is_some() || state.retiring {
                return Err(LocalKeyRotationFailure::Busy);
            }
        }
        let source_provider = self
            .key
            .active_provider_identity()
            .map_err(|_| LocalKeyRotationFailure::Custody)?;
        let native_source =
            source_provider.family() != positron_kernel::key_provider::ProviderFamily::LocalFile;
        let source_receipt = self
            .key
            .root_admission_receipt()
            .map_err(|_| LocalKeyRotationFailure::Custody)?;
        drop(catalog);
        let access = self
            .bootstrap_storage
            .inspect()
            .map_err(|_| LocalKeyRotationFailure::Custody)?;
        let active_epoch = source_receipt.epoch();
        let successor_epoch = active_epoch
            .checked_add(1)
            .ok_or(LocalKeyRotationFailure::LimitExceeded)?;
        let successor = session
            .prepare_successor(&access, successor_epoch)
            .map_err(|_| LocalKeyRotationFailure::Custody)?;
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
                envelope: if native_source {
                    session.active_system_envelope(&self.key, self.instance)
                } else {
                    session.wrap_system(&self.key, &self.key, self.instance, active_epoch)
                }
                .map_err(|_| LocalKeyRotationFailure::Authentication)?,
            },
            predecessor: None,
            retiring: false,
            cancelled: false,
            provider_format: native_source,
            migration_source: native_source.then_some(source_provider),
            successor: Some(Route {
                epoch: successor_epoch,
                identity: successor.identity(),
                envelope: session
                    .wrap_system(&self.key, &successor, self.instance, successor_epoch)
                    .map_err(|_| LocalKeyRotationFailure::Authentication)?,
            }),
        };
        #[cfg(test)]
        LOCAL_ROTATION_PREPUBLICATION.with(|hook| {
            if let Some(hook) = hook.take() {
                hook(self);
            }
        });
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
        self.publish_rotation_for_operation(
            &catalog,
            &snapshot,
            &state,
            CatalogRootRotationStage::Started,
            state.transaction,
            context,
        )?;
        Ok(state.status())
    }
    fn rotation_transaction(&self) -> Result<TransactionId, LocalKeyRotationFailure> {
        TransactionId::new(
            self.key
                .random_identifier()
                .map_err(|_| LocalKeyRotationFailure::Custody)?,
        )
        .map_err(|_| LocalKeyRotationFailure::Storage)
    }
    fn operation_rotation_transaction(
        &self,
        context: Option<RootMigrationContext<'_>>,
        stage: CatalogRootRotationStage,
    ) -> Result<TransactionId, LocalKeyRotationFailure> {
        match context {
            Some(context) => context.transaction(stage),
            None => self.rotation_transaction(),
        }
    }
    fn publish_rotation_for_operation(
        &self,
        catalog: &Catalog<'_>,
        snapshot: &positron_kernel::CatalogSnapshot,
        state: &State,
        stage: CatalogRootRotationStage,
        transaction: TransactionId,
        context: Option<RootMigrationContext<'_>>,
    ) -> Result<positron_kernel::CatalogSnapshot, LocalKeyRotationFailure> {
        let _copy = catalog
            .reserve_catalog_proposal_copy(snapshot)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        let encoded = state.encode()?;
        let object = CatalogObject::new(encoded).map_err(|_| LocalKeyRotationFailure::Storage)?;
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(snapshot.object_count().saturating_add(1))
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        for id in snapshot.object_identities() {
            let bytes = snapshot
                .object(id)
                .map_err(|_| LocalKeyRotationFailure::Storage)?
                .ok_or(LocalKeyRotationFailure::Authentication)?;
            if !state::is_state(bytes) {
                objects.push(
                    CatalogObject::new(bytes.to_vec())
                        .map_err(|_| LocalKeyRotationFailure::Storage)?,
                );
            }
        }
        objects.push(object);
        let route = state.successor.as_ref().unwrap_or(&state.active);
        let intent = if let Some(context) = context {
            positron_governance::catalog_root_migration_audit_intent(
                stage,
                route.identity.key_id(),
                route.epoch,
                context.principal,
                context.operation,
            )
        } else {
            catalog_root_rotation_audit_intent(
                stage,
                route.identity.key_id(),
                route.epoch,
                self.administrator,
            )
        }
        .map_err(|_| LocalKeyRotationFailure::Storage)?;
        let proposal = CatalogProposal::new(
            transaction,
            snapshot
                .format_epoch()
                .ok_or(LocalKeyRotationFailure::Authentication)?,
            objects,
        )
        .map_err(|_| LocalKeyRotationFailure::Storage)?;
        let commit = match catalog.commit(snapshot.identity(), proposal, Some(intent)) {
            Ok(commit) => commit,
            Err(_) if stage == CatalogRootRotationStage::Cutover => {
                match catalog.confirm_committed_transaction(transaction) {
                    Ok(Some(commit)) => commit,
                    Ok(None) => return Err(LocalKeyRotationFailure::Storage),
                    Err(_) => {
                        self.key
                            .invalidate_for_rotation()
                            .map_err(|_| LocalKeyRotationFailure::Custody)?;
                        return Err(LocalKeyRotationFailure::Storage);
                    },
                }
            },
            Err(_) => return Err(LocalKeyRotationFailure::Storage),
        };
        self.record_catalog_generation(commit.number());
        Ok(commit.snapshot().clone())
    }
}

/// Recovery may restore only the exact active route authenticated by Catalog.
pub(super) fn validate_recovery_route(
    authority: &positron_kernel::StorageKernelResourceAuthority,
    catalog: &Catalog<'_>,
    custody: &positron_kernel::BootstrapKeyCustody,
    instance: positron_kernel::InstanceId,
) -> Result<(), LocalKeyRotationFailure> {
    let session =
        RootRewrapSession::admit(authority).map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
    let basis = catalog
        .pin()
        .map_err(|_| LocalKeyRotationFailure::Storage)?;
    let epoch = custody
        .active_root_epoch()
        .map_err(|_| LocalKeyRotationFailure::Authentication)?;
    let identity = custody
        .active_root_identity()
        .map_err(|_| LocalKeyRotationFailure::Authentication)?;
    match State::find(&basis)? {
        Some(state) => {
            if state.instance != instance
                || state.anchor != custody.bootstrap_identity()
                || state.active.identity != identity
                || state.active.epoch != epoch
            {
                return Err(LocalKeyRotationFailure::Authentication);
            }
            let canonical = session
                .wrap_system(custody, custody, instance, epoch)
                .map_err(|_| LocalKeyRotationFailure::Authentication)?;
            if canonical != state.active.envelope {
                return Err(LocalKeyRotationFailure::Authentication);
            }
            cutover::confirm_state(catalog, &state)?;
        },
        None if epoch == 1 && identity == custody.bootstrap_identity() => {},
        None => return Err(LocalKeyRotationFailure::Authentication),
    }
    Ok(())
}

#[cfg(fuzzing)]
pub(crate) use state::fuzz_key_provider_migration_stateful;

#[cfg(test)]
thread_local! { static LOCAL_ROTATION_PREPUBLICATION: std::cell::Cell<Option<fn(&InitializedInstance)>> = const { std::cell::Cell::new(None) }; }
#[cfg(test)]
pub(in crate::instance_bootstrap) fn with_local_rotation_prepublication_hook<T>(
    hook: fn(&InitializedInstance),
    action: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<fn(&InitializedInstance)>);
    impl Drop for Restore {
        fn drop(&mut self) {
            LOCAL_ROTATION_PREPUBLICATION.with(|slot| slot.set(self.0));
        }
    }
    let _restore = Restore(LOCAL_ROTATION_PREPUBLICATION.with(|slot| slot.replace(Some(hook))));
    action()
}
