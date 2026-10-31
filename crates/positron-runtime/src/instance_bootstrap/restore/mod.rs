//! Offline fresh-target restore; ownership and native resources live until drop.
use super::*;
use positron_backup::{
    BackupManifest, BackupPublisher, BackupRegistryVerification, BackupRepositoryRegistration,
    BackupSnapshotReader, BackupSnapshotVerification, ObjectId, Repository, RepositoryIdentity,
};
use positron_governance::{
    AdministrativeIdempotencyKey, BackupRestoreParameters, BackupVerificationParameters,
    DurableOperation, DurableOperationAdministration, DurableOperationRequest, Identity,
    TenantAdministration,
};
use positron_kernel::{
    BackupCaptureFile, BackupCaptureFileKind, BackupCaptureVerification, BootstrapArtifact,
    BootstrapArtifactAccess, BootstrapKeyCustody, BootstrapObjectPurpose, Catalog,
    NativeAwsResources, RecoveryIdentity, RecoveryProtection, RecoverySession, RecoveryUnlock,
    ResourceAmounts, StorageKernelResourceAuthority, WorkClaim,
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
mod execution;
mod input;
mod preflight;
mod purge;
fn grant_failure(
    stage: BootstrapResourceStage,
    failure: positron_kernel::AdmissionFailure,
) -> BootstrapFailure {
    BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable).with_resource_context(
        BootstrapResourceContext::new(
            stage,
            BootstrapResourceReason::ResourceAdmissionRefused,
            None,
        )
        .with_dimension(failure.limiting_dimension())
        .with_admission(failure),
    )
}
fn failure() -> BootstrapFailure {
    BootstrapFailure::new(BootstrapFailureCode::CorruptState)
}
fn now() -> Result<u64, BootstrapFailure> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| failure())
}
/// Exact source and independent recovery input. Target and resolved configuration
/// identities are computed under pinned native ownership, never caller asserted.
pub struct BackupRestoreRequest {
    source: BackupVerificationParameters,
    pin: RecoveryIdentity,
    recovery: RestoreRecovery,
    idempotency: AdministrativeIdempotencyKey,
}
impl BackupRestoreRequest {
    pub fn new(
        source: BackupVerificationParameters,
        pin: RecoveryIdentity,
        bundle: PathBuf,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<Self, BootstrapFailure> {
        if !bundle.is_absolute()
            || source.repository().integrity_fingerprint() != pin.integrity().fingerprint()
        {
            return Err(failure());
        }
        Ok(Self {
            source,
            pin,
            recovery: RestoreRecovery::Bundle(bundle),
            idempotency,
        })
    }
    pub fn provider(
        source: BackupVerificationParameters,
        pin: RecoveryIdentity,
        anchor: positron_kernel::BootstrapKeyIdentity,
        epoch: u64,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<Self, BootstrapFailure> {
        if epoch < 2 || source.repository().integrity_fingerprint() != pin.integrity().fingerprint()
        {
            return Err(failure());
        }
        Ok(Self {
            source,
            pin,
            recovery: RestoreRecovery::Provider { anchor, epoch },
            idempotency,
        })
    }
}
enum RestoreRecovery {
    Bundle(PathBuf),
    Provider {
        anchor: positron_kernel::BootstrapKeyIdentity,
        epoch: u64,
    },
}
enum RestoreUnlock<'a> {
    Bundle(RecoveryUnlock<'a>),
    Provider(positron_kernel::key_provider::NativeRootConfiguration),
}
pub struct BackupRestoreSession {
    authority: StorageKernelResourceAuthority,
    access: BootstrapArtifactAccess,
    custody: BootstrapKeyCustody,
    pin: RecoveryIdentity,
    operation: DurableOperation,
    runtime: tokio::runtime::Runtime,
    repository: Box<dyn Repository>,
    identity: RepositoryIdentity,
    signer: positron_kernel::BackupControlSigner,
    registry: BackupRegistryVerification,
    remote: BackupSnapshotVerification,
    manifest: BackupManifest,
    source_catalog: positron_kernel::CatalogSnapshot,
    recovered_keys: usize,
    files: Vec<BackupCaptureFile>,
    next_file: usize,
    offset: u64,
    record: super::codec::BootstrapRecord,
    native_scopes: Vec<positron_kernel::SegmentScope>,
    native_index: usize,
    native_cursor: Option<positron_kernel::IntegrityScrubContinuation>,
    // Struct fields drop in declaration order; retain the grant through all
    // repository and source-state destruction, including LocalFilesystem.
    resources: Arc<NativeAwsResources>,
}
impl InstanceBootstrap {
    pub fn begin_restore(
        paths: &BootstrapPaths,
        configuration: &positron_config::EffectiveConfiguration,
        request: &BackupRestoreRequest,
        unlock: RecoveryUnlock<'_>,
    ) -> Result<BackupRestoreSession, BootstrapFailure> {
        Self::restore(paths, configuration, request, RestoreUnlock::Bundle(unlock))
    }
    pub fn begin_restore_with_provider(
        paths: &BootstrapPaths,
        configuration: &positron_config::EffectiveConfiguration,
        request: &BackupRestoreRequest,
        provider: positron_kernel::key_provider::NativeRootConfiguration,
    ) -> Result<BackupRestoreSession, BootstrapFailure> {
        Self::restore(
            paths,
            configuration,
            request,
            RestoreUnlock::Provider(provider),
        )
    }
    /// Opens only an already accepted exact restore; never stages a fresh target.
    pub fn inspect_restore(
        paths: &BootstrapPaths,
        configuration: &positron_config::EffectiveConfiguration,
        request: &BackupRestoreRequest,
        unlock: RecoveryUnlock<'_>,
    ) -> Result<DurableOperation, BootstrapFailure> {
        input::PreparedRestore::open(paths, configuration, request, RestoreUnlock::Bundle(unlock))?
            .inspect(request)
    }
    pub fn inspect_restore_with_provider(
        paths: &BootstrapPaths,
        configuration: &positron_config::EffectiveConfiguration,
        request: &BackupRestoreRequest,
        provider: positron_kernel::key_provider::NativeRootConfiguration,
    ) -> Result<DurableOperation, BootstrapFailure> {
        input::PreparedRestore::open(
            paths,
            configuration,
            request,
            RestoreUnlock::Provider(provider),
        )?
        .inspect(request)
    }
}
