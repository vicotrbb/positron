//! Resumable local-root wrapping through the existing Catalog and custody owners.
use super::InitializedInstance;
use positron_governance::{CatalogRootRotationStage, catalog_root_rotation_audit_intent};
use positron_kernel::{Catalog, CatalogObject, CatalogProposal, RootRewrapSession, TransactionId};
use std::fmt::{Display, Formatter};
mod cutover;
mod root_retirement;
mod root_verification_audit;
mod state;
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
    fn rotation_catalog(
        &self,
        session: &RootRewrapSession<'_>,
    ) -> Result<Catalog<'_>, LocalKeyRotationFailure> {
        let secret = session
            .rotation_catalog_secret(&self.key, self.instance)
            .map_err(|_| LocalKeyRotationFailure::Custody)?;
        Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| LocalKeyRotationFailure::Storage)
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
        let session = RootRewrapSession::admit(&self._authority)
            .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
        let catalog = self.rotation_catalog(&session)?;
        let snapshot = catalog
            .pin()
            .map_err(|_| LocalKeyRotationFailure::Storage)?;
        let previous = State::find(&snapshot)?;
        if let Some(state) = previous.as_ref() {
            if state.instance != self.instance || state.anchor != self.key.bootstrap_identity() {
                return Err(LocalKeyRotationFailure::Authentication);
            }
            if state.successor.is_some() {
                return Ok(state.status());
            }
            if state.predecessor.is_some() || state.retiring {
                return Err(LocalKeyRotationFailure::Busy);
            }
        }
        let access = self
            .bootstrap_storage
            .inspect()
            .map_err(|_| LocalKeyRotationFailure::Custody)?;
        let active_epoch = self
            .key
            .active_root_epoch()
            .map_err(|_| LocalKeyRotationFailure::Custody)?;
        let successor_epoch = active_epoch
            .checked_add(1)
            .ok_or(LocalKeyRotationFailure::LimitExceeded)?;
        let successor = session
            .prepare_successor(&access, successor_epoch)
            .map_err(|_| LocalKeyRotationFailure::Custody)?;
        let state = State {
            instance: self.instance,
            transaction: self.rotation_transaction()?,
            anchor: self.key.bootstrap_identity(),
            active: Route {
                epoch: active_epoch,
                identity: self
                    .key
                    .active_root_identity()
                    .map_err(|_| LocalKeyRotationFailure::Custody)?,
                envelope: session
                    .wrap_system(&self.key, &self.key, self.instance, active_epoch)
                    .map_err(|_| LocalKeyRotationFailure::Authentication)?,
            },
            predecessor: None,
            retiring: false,
            successor: Some(Route {
                epoch: successor_epoch,
                identity: successor.identity(),
                envelope: session
                    .wrap_system(&self.key, &successor, self.instance, successor_epoch)
                    .map_err(|_| LocalKeyRotationFailure::Authentication)?,
            }),
        };
        self.publish_rotation(
            &catalog,
            &snapshot,
            &state,
            CatalogRootRotationStage::Started,
            state.transaction,
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
    fn publish_rotation(
        &self,
        catalog: &Catalog<'_>,
        snapshot: &positron_kernel::CatalogSnapshot,
        state: &State,
        stage: CatalogRootRotationStage,
        transaction: TransactionId,
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
            if !bytes.starts_with(state::MAGIC) {
                objects.push(
                    CatalogObject::new(bytes.to_vec())
                        .map_err(|_| LocalKeyRotationFailure::Storage)?,
                );
            }
        }
        objects.push(object);
        let route = state.successor.as_ref().unwrap_or(&state.active);
        let intent = catalog_root_rotation_audit_intent(
            stage,
            route.identity.key_id(),
            route.epoch,
            self.administrator,
        )
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
