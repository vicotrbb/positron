//! Exclusive offline ownership composes real Drain, Backup and Catalog evidence.
use super::{UpgradeFailure, UpgradeReleasePlan};
use crate::{BootstrapPaths, InitializedInstance, InstanceBootstrap, ServiceHandle};
use positron_config::EffectiveConfiguration;
use positron_governance::{
    AdministrativeIdempotencyKey, BackupVerificationParameters, DurableOperation,
    DurableOperationAdministration as Administration, DurableOperationKind, DurableOperationStatus,
    OperationId, UpgradeDrainEvidence, UpgradeStage,
};
use positron_kernel::release_manifest::VerifiedReleaseManifest;
use positron_kernel::{Catalog, TransactionId};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Instant};

mod admission;
mod installed;
mod reference;
mod snapshot;

/// No service or instance handle escapes this owner, and no listeners are bound.
pub struct OfflineUpgradeSession {
    instance: Arc<InitializedInstance>,
    services: ServiceHandle,
    id: OperationId,
}
impl OfflineUpgradeSession {
    pub fn status(&self) -> Result<DurableOperation, UpgradeFailure> {
        Administration::inspect(&open(&self.instance)?, self.id)
            .map_err(persistence)?
            .ok_or(UpgradeFailure::InvalidRequest)
    }
    /// Stops between admitted provider turns at the caller deadline. An
    /// in-flight turn keeps its existing provider bound; unfinished durable
    /// work remains resumable and never fabricates a terminal outcome.
    pub fn advance(&mut self, deadline: Instant) -> Result<DurableOperation, UpgradeFailure> {
        let operation = self.status()?;
        if operation.status().is_terminal()
            || operation.upgrade_stage() != Some(UpgradeStage::Snapshot)
            || Instant::now() >= deadline
        {
            return Ok(operation);
        }
        if now(&self.instance)? < operation.updated_at_unix_seconds() {
            return Ok(operation);
        }
        self.verify_frontiers()?;
        if operation.upgrade_snapshot_evidence().is_some() {
            return self.advance_stage(UpgradeStage::Publishing);
        }
        let snapshot = self.snapshot_operation(&operation, deadline)?;
        if snapshot.status() != DurableOperationStatus::Succeeded {
            return if snapshot.status().is_terminal() {
                Err(UpgradeFailure::SnapshotUnavailable)
            } else {
                self.status()
            };
        }
        if Instant::now() >= deadline {
            return self.status();
        }
        let verification = self.verification_operation(&operation, &snapshot, deadline)?;
        if verification.status() != DurableOperationStatus::Succeeded {
            return if verification.status().is_terminal() {
                Err(UpgradeFailure::VerificationFailed)
            } else {
                self.status()
            };
        }
        self.record_snapshot(snapshot.operation_id(), verification.operation_id())
    }
    /// The outer deployment owner verifies actual target artifact bytes before
    /// this publication. This method binds its authenticated manifest identity.
    pub fn publish(
        &mut self,
        target: &VerifiedReleaseManifest,
    ) -> Result<DurableOperation, UpgradeFailure> {
        let operation = self.status()?;
        let parameters = operation
            .upgrade_parameters()
            .ok_or(UpgradeFailure::InvalidRequest)?;
        let artifact = UpgradeReleasePlan::native_artifact(target)?;
        let version = target.manifest().version;
        if target.digest() != parameters.target().manifest_digest()
            || artifact.sha256 != parameters.target().artifact_digest()
            || [version.major, version.minor, version.patch] != parameters.target().version()
            || target.manifest().compatibility.persistent.writable_epoch
                != parameters.format_epoch()
        {
            return Err(UpgradeFailure::ArtifactMismatch);
        }
        if operation.upgrade_stage() == Some(UpgradeStage::AwaitingRestart) {
            return Ok(operation);
        }
        if operation.status() != DurableOperationStatus::Running
            || operation.upgrade_stage() != Some(UpgradeStage::Publishing)
        {
            return Err(UpgradeFailure::UnsafeState);
        }
        self.verify_frontiers()?;
        self.advance_stage(UpgradeStage::AwaitingRestart)
    }
    pub fn cancel(
        &mut self,
        key: AdministrativeIdempotencyKey,
        revision: u64,
    ) -> Result<DurableOperation, UpgradeFailure> {
        for stage in [b"snapshot".as_slice(), b"verification".as_slice()] {
            if self
                .child(child_key(self.id, stage)?)?
                .is_some_and(|operation| !operation.status().is_terminal())
            {
                return Err(UpgradeFailure::SnapshotUnavailable);
            }
        }
        let catalog = open(&self.instance)?;
        let actor = actor(&catalog, &self.instance, self.id)?;
        Administration::cancel_upgrade(
            &catalog,
            actor,
            self.id,
            key,
            revision,
            now(&self.instance)?,
        )
        .map_err(persistence)
    }
    pub fn fail(&mut self) -> Result<DurableOperation, UpgradeFailure> {
        let catalog = open(&self.instance)?;
        let actor = actor(&catalog, &self.instance, self.id)?;
        Administration::fail_upgrade(&catalog, actor, self.id, now(&self.instance)?)
            .map_err(persistence)
    }
    /// Explicitly selects the measured original artifact while storage remains
    /// quiescent. Installation stays with the deployment owner.
    pub fn rollback(
        &mut self,
        source: &VerifiedReleaseManifest,
        artifact: &std::path::Path,
        key: AdministrativeIdempotencyKey,
        revision: u64,
    ) -> Result<DurableOperation, UpgradeFailure> {
        let operation = self.status()?;
        if !operation.upgrade_rollback_available() && operation.upgrade_rollback_key() != Some(key)
        {
            return Err(UpgradeFailure::UnsafeState);
        }
        let parameters = operation
            .upgrade_parameters()
            .ok_or(UpgradeFailure::InvalidRequest)?;
        let expected = parameters.source();
        let candidate = UpgradeReleasePlan::native_artifact(source)?;
        let version = source.manifest().version;
        if source.digest() != expected.manifest_digest()
            || candidate.sha256 != expected.artifact_digest()
            || [version.major, version.minor, version.patch] != expected.version()
            || source.manifest().compatibility.persistent.writable_epoch
                != parameters.format_epoch()
        {
            return Err(UpgradeFailure::ArtifactMismatch);
        }
        super::UpgradeArtifactIdentity::measure(
            &self.instance,
            artifact,
            candidate.sha256,
            candidate.size,
        )?;
        self.verify_frontiers()?;
        let catalog = open(&self.instance)?;
        let actor = actor(&catalog, &self.instance, self.id)?;
        Administration::rollback_upgrade(
            &catalog,
            actor,
            self.id,
            key,
            revision,
            now(&self.instance)?,
        )
        .map_err(persistence)
    }
    /// Supplies the existing fresh-target Restore API; never rewrites live data.
    pub fn rollback_snapshot(
        &self,
    ) -> Result<Option<BackupVerificationParameters>, UpgradeFailure> {
        let operation = self.status()?;
        let Some(snapshot) = operation.upgrade_snapshot_evidence() else {
            return Ok(None);
        };
        let parameters = operation
            .upgrade_parameters()
            .ok_or(UpgradeFailure::UnsafeState)?;
        BackupVerificationParameters::new(
            parameters.backup().repository(),
            parameters.backup().registration_identity(),
            snapshot.operation_id().to_bytes(),
            snapshot.receipt().manifest(),
        )
        .map(Some)
        .map_err(persistence)
    }
    fn child(
        &self,
        key: AdministrativeIdempotencyKey,
    ) -> Result<Option<DurableOperation>, UpgradeFailure> {
        Administration::inspect_by_idempotency(&open(&self.instance)?, key).map_err(persistence)
    }
    fn advance_stage(&self, stage: UpgradeStage) -> Result<DurableOperation, UpgradeFailure> {
        let catalog = open(&self.instance)?;
        let actor = actor(&catalog, &self.instance, self.id)?;
        Administration::advance_upgrade(&catalog, actor, self.id, stage, now(&self.instance)?)
            .map_err(persistence)
    }
    fn verify_frontiers(&self) -> Result<(), UpgradeFailure> {
        let record = self
            .instance
            .graceful_shutdown_record()
            .map_err(|_| UpgradeFailure::DrainIncomplete)?
            .ok_or(UpgradeFailure::DrainIncomplete)?;
        self.instance
            .verify_graceful_shutdown_frontiers(&record)
            .map_err(|_| UpgradeFailure::DrainIncomplete)
    }
}
fn open(instance: &InitializedInstance) -> Result<Catalog<'_>, UpgradeFailure> {
    Catalog::open(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| UpgradeFailure::PersistenceUnavailable)?,
    )
    .map_err(|_| UpgradeFailure::PersistenceUnavailable)
}
fn actor(
    catalog: &Catalog<'_>,
    instance: &InitializedInstance,
    id: OperationId,
) -> Result<positron_governance::AuthorizedContext, UpgradeFailure> {
    let security = instance
        .retention_time
        .security_time_seconds()
        .map_err(|_| UpgradeFailure::SnapshotUnavailable)?;
    Administration::resume_upgrade_actor(catalog, id, security).map_err(persistence)
}

fn now(instance: &InitializedInstance) -> Result<u64, UpgradeFailure> {
    instance
        .retention_time
        .governance_now_seconds()
        .map_err(|_| UpgradeFailure::SnapshotUnavailable)
}
fn persistence(failure: positron_governance::DurableOperationFailure) -> UpgradeFailure {
    use positron_governance::DurableOperationFailure;
    match failure {
        DurableOperationFailure::Unauthorized => UpgradeFailure::AuthenticationFailed,
        DurableOperationFailure::InvalidInput
        | DurableOperationFailure::UnknownOperation
        | DurableOperationFailure::IdempotencyConflict => UpgradeFailure::InvalidRequest,
        DurableOperationFailure::CapacityExceeded => UpgradeFailure::CapacityUnavailable,
        DurableOperationFailure::InvalidState
        | DurableOperationFailure::StaleGeneration
        | DurableOperationFailure::CancellationUnavailable => UpgradeFailure::UnsafeState,
        DurableOperationFailure::PersistenceUnavailable
        | DurableOperationFailure::CompletedLookupExpired => UpgradeFailure::PersistenceUnavailable,
    }
}
fn child_key(
    id: OperationId,
    stage: &[u8],
) -> Result<AdministrativeIdempotencyKey, UpgradeFailure> {
    let mut hash = Sha256::new();
    hash.update(b"positron.upgrade.child.v1\0");
    hash.update(id.to_bytes());
    hash.update(stage);
    let digest = hash.finalize();
    let bytes = digest
        .get(..16)
        .ok_or(UpgradeFailure::UnsafeState)?
        .try_into()
        .map_err(|_| UpgradeFailure::UnsafeState)?;
    AdministrativeIdempotencyKey::new(bytes).map_err(|_| UpgradeFailure::InvalidRequest)
}
