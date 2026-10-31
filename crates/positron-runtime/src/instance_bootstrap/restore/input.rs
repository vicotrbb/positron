//! The same pinned offline input recovery precedes inspection and execution.
use super::*;
pub(super) struct PreparedRestore {
    pub authority: StorageKernelResourceAuthority,
    pub access: BootstrapArtifactAccess,
    pub layout: positron_kernel::BootstrapLayout,
    pub resources: Arc<NativeAwsResources>,
    pub runtime: tokio::runtime::Runtime,
    pub repository: Box<dyn Repository>,
    pub identity: RepositoryIdentity,
    pub custody: BootstrapKeyCustody,
    pub parameters: BackupRestoreParameters,
    pub native: ResourceAmounts,
    pub manifest: BackupManifest,
}
impl PreparedRestore {
    pub(super) fn open(
        paths: &BootstrapPaths,
        configuration: &positron_config::EffectiveConfiguration,
        request: &BackupRestoreRequest,
        unlock: RestoreUnlock<'_>,
    ) -> Result<Self, BootstrapFailure> {
        let (volume, access) = paths.storage.acquire().map_err(storage::storage_failure)?;
        let layout = access.layout().map_err(storage::storage_failure)?;
        if layout.unknown_or_unsafe() {
            return Err(failure());
        }
        let target = access
            .restore_target_commitment()
            .map_err(storage::storage_failure)?;
        let configured = positron_kernel::InstanceBootstrapStorage::new(
            Path::new(configuration.data_directory()),
            Path::new(configuration.secrets_directory()),
            positron_kernel::MountQualification::LocalHost,
        )
        .map_err(storage::storage_failure)?;
        if configured
            .inspect()
            .map_err(storage::storage_failure)?
            .restore_target_commitment()
            .map_err(storage::storage_failure)?
            != target
        {
            return Err(failure());
        }
        let authority = resources::establish_system_diagnostics(
            volume,
            configuration.max_registered_tenants(),
        )?;
        let native = crate::services::repository_administration::repository_resources(
            request.source.repository().provider_kind(),
        );
        let amounts = initial_demand(native)?;
        let claim = WorkClaim::backup_repository_read(amounts).map_err(|_| failure())?;
        let resources = NativeAwsResources::new(
            authority
                .governor()
                .reserve(claim)
                .map_err(|failure| {
                    grant_failure(BootstrapResourceStage::RestoreInitialGrant, failure)
                })?
                .transfer(),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .map_err(|_| failure())?;
        let (identity, repository) = runtime
            .block_on(
                crate::services::repository_administration::open_for_recovery(
                    request.pin.instance(),
                    request.source.repository(),
                    resources.clone(),
                ),
            )
            .map_err(|_| failure())?;
        let reader = runtime
            .block_on(BackupSnapshotReader::open(
                repository.as_ref(),
                &identity,
                request.pin.integrity(),
                ObjectId::from_checksum(request.source.manifest_checksum()),
                &resources,
                0,
            ))
            .map_err(|_| failure())?;
        let (custody, recovery_digest) = match (&request.recovery, unlock) {
            (RestoreRecovery::Bundle(bundle), RestoreUnlock::Bundle(unlock)) => {
                let recovery = RecoverySession::admit(
                    &authority,
                    match &unlock {
                        RecoveryUnlock::Identity(_) | RecoveryUnlock::IdentityFile(_) => {
                            RecoveryProtection::Recipients
                        },
                        _ => RecoveryProtection::Passphrase,
                    },
                )
                .map_err(|_| failure())?;
                let location = paths
                    .storage
                    .recovery_bundle_location(bundle)
                    .map_err(storage::storage_failure)?;
                let ciphertext = recovery.read(&location).map_err(|_| failure())?;
                let digest = recovery.bundle_digest(&ciphertext).map_err(|_| failure())?;
                let (_, custody) = recovery
                    .recover_detached(&ciphertext, unlock, request.pin)
                    .map_err(|_| failure())?;
                (custody, digest)
            },
            (
                RestoreRecovery::Provider { anchor, epoch },
                RestoreUnlock::Provider(configuration),
            ) => {
                use sha2::{Digest, Sha256};
                let overlay = runtime
                    .block_on(reader.recovery_overlay(configuration.identity()))
                    .map_err(|_| failure())?
                    .ok_or_else(failure)?;
                let session = positron_kernel::RootRewrapSession::admit_provider(&authority)
                    .map_err(|_| failure())?;
                let provider = session
                    .native_provider(configuration)
                    .map_err(|_| failure())?;
                let encoded = overlay.target().encode();
                let custody = session
                    .open_provider_system_blocking(
                        provider,
                        request.pin.instance(),
                        *anchor,
                        *epoch,
                        &encoded,
                        paths.key_cache_lease,
                    )
                    .map_err(|_| failure())?;
                if custody.active_root_identity().map_err(|_| failure())? != request.pin.root() {
                    return Err(failure());
                }
                let mut hash = Sha256::new();
                hash.update(b"positron-fresh-restore-provider-recovery-v1\0");
                hash.update(anchor.key_id());
                hash.update(anchor.fingerprint());
                hash.update(anchor.created_at_unix_seconds().to_be_bytes());
                hash.update(epoch.to_be_bytes());
                hash.update(encoded);
                (custody, hash.finalize().into())
            },
            _ => return Err(failure()),
        };
        let parameters = BackupRestoreParameters::new(
            request.source,
            target,
            configuration.audit_binding_digest(),
            recovery_digest,
        )
        .map_err(|_| failure())?;
        if !layout.is_empty_instance() {
            let secret = custody
                .catalog_secret(request.pin.instance())
                .map_err(|_| failure())?;
            access
                .verify_restore_target(request.pin.instance(), &secret, parameters.intent_digest())
                .map_err(storage::storage_failure)?;
            // A committed historical successor owns its administrative key even
            // if restore acceptance was interrupted. Inspect without recovery
            // publication before opening a writable Catalog for a retry.
            if Catalog::inspect_restore_origin_intent(&authority, request.pin.instance(), &secret)
                .map_err(|_| failure())?
                .is_some()
            {
                let view = Catalog::read_current_view(&authority, request.pin.instance(), secret)
                    .map_err(|_| failure())?;
                let (capture, _) = reader.manifest().capture_binding().ok_or_else(failure)?;
                if let Some(evidence) = DurableOperationAdministration::inspect_snapshot(
                    view.snapshot(),
                    positron_governance::OperationId::from_bytes(capture).map_err(|_| failure())?,
                )
                .map_err(|_| failure())?
                .and_then(|operation| operation.restored_backup_publication())
                    && evidence.restore_idempotency_key() != request.idempotency.to_bytes()
                {
                    return Err(failure());
                }
            }
        }
        let manifest = reader.manifest().clone();
        drop(reader);
        Ok(PreparedRestore {
            authority,
            access,
            layout,
            resources,
            runtime,
            repository,
            identity,
            custody,
            parameters,
            native,
            manifest,
        })
    }
    pub(super) fn inspect(
        self,
        request: &BackupRestoreRequest,
    ) -> Result<DurableOperation, BootstrapFailure> {
        if self.layout.is_empty_instance() {
            return Err(failure());
        }
        let view = Catalog::read_current_view(
            &self.authority,
            request.pin.instance(),
            self.custody
                .catalog_secret(request.pin.instance())
                .map_err(|_| failure())?,
        )
        .map_err(|_| failure())?;
        let actor =
            Identity::authorize_backup_restore(view.snapshot(), &self.custody, request.pin, now()?)
                .map_err(|_| failure())?;
        let operation = DurableOperationAdministration::inspect_snapshot_by_idempotency(
            view.snapshot(),
            request.idempotency,
        )
        .map_err(|_| failure())?
        .ok_or_else(failure)?;
        if operation.backup_restore_parameters() != Some(self.parameters)
            || operation.request().principal() != actor.principal_id()
        {
            return Err(failure());
        }
        Ok(operation)
    }
}

fn initial_demand(native: ResourceAmounts) -> Result<ResourceAmounts, BootstrapFailure> {
    let peak = BackupCaptureVerification::required_memory_bytes()
        .map_err(|_| failure())?
        .checked_add(BackupPublisher::control_read_memory_bytes())
        .and_then(|bytes| {
            bytes.checked_add(native.get(positron_kernel::ResourceDimension::MemoryBytes))
        })
        .ok_or_else(failure)?;
    let baseline = ResourceAmounts::new([peak, 1, 1, 0, 8, 0, 1, 1, 1, 16, 0]);
    Ok(ResourceAmounts::new(
        positron_kernel::ResourceDimension::ALL
            .map(|dimension| baseline.get(dimension).max(native.get(dimension))),
    ))
}
#[cfg(test)]
#[path = "native_repository_tests.rs"]
mod tests;
