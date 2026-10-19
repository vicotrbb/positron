//! Independent, bounded verification of a published snapshot.
mod checkpoint;
mod report;
mod restore_report;
use super::*;
pub use report::BackupVerificationReport;
pub use restore_report::BackupRestoreReport;

/// A private verification cursor; a receipt alone never marks its work complete.
pub struct BackupSnapshotVerification {
    owner: [u8; 16],
    request: [u8; 32],
    manifest: BackupManifest,
    registry: [u8; 32],
    check: BackupPublicationCheck,
    files: Vec<positron_kernel::BackupCaptureFile>,
    next_file: usize,
    file_object: usize,
    file_offset: u64,
    file_hash: Sha256,
    inventory_verified: bool,
    resumed_inventory: Option<([u8; 32], usize)>,
}
impl std::fmt::Debug for BackupSnapshotVerification {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BackupSnapshotVerification")
            .field("publication_complete", &self.check.complete())
            .field("publication", &self.check)
            .field("inventory_verified", &self.inventory_verified)
            .field("completed_files", &self.next_file)
            .field("file_count", &self.files.len())
            .field("object_index", &self.file_object)
            .field("file_offset", &self.file_offset)
            .finish()
    }
}

impl BackupSnapshotVerification {
    fn start(
        owner: [u8; 16],
        request: [u8; 32],
        manifest: BackupManifest,
        registry: [u8; 32],
        check: BackupPublicationCheck,
    ) -> Self {
        Self {
            owner,
            request,
            manifest,
            registry,
            check,
            files: Vec::new(),
            next_file: 0,
            file_object: 0,
            file_offset: 0,
            file_hash: Sha256::new(),
            inventory_verified: false,
            resumed_inventory: None,
        }
    }
    pub fn complete(&self) -> bool {
        self.check.complete() && self.next_file == self.files.len()
    }
    pub fn manifest(&self) -> &BackupManifest {
        &self.manifest
    }
    pub const fn manifest_checksum(&self) -> [u8; 32] {
        self.check.manifest
    }
    pub const fn registry_generation(&self) -> [u8; 32] {
        self.registry
    }
    pub fn retained_memory_bytes(&self) -> Result<u64, RepositoryFailure> {
        self.manifest
            .retained_memory_bytes()?
            .checked_add(self.check.retained_memory_bytes()?)
            .and_then(|bytes| {
                allocation_bytes::<positron_kernel::BackupCaptureFile>(self.files.capacity())
                    .ok()
                    .and_then(|inventory| bytes.checked_add(inventory))
            })
            .ok_or(RepositoryFailure::LimitExceeded)
    }
}
impl BackupPublisher<'_> {
    /// Source identities come from the independently authenticated portable
    /// Catalog. Their complete digest must equal the signed original context.
    /// Only an exact current signed tombstone permits a missing key reference.
    pub async fn begin_snapshot_restore_verification(
        &self,
        snapshot: [u8; 16],
        owner: [u8; 16],
        request: [u8; 32],
        expected: &[BackupKeyIdentity],
    ) -> Result<BackupSnapshotVerification, RepositoryFailure> {
        if owner == [0; 16] || request == [0; 32] || expected.len() > MAX_KEY_ENVELOPES {
            return Err(RepositoryFailure::InvalidInput);
        }
        self.require_identity().await?;
        let (head, generation, registry) = self.current().await?;
        let generation = generation.ok_or(RepositoryFailure::NotFound)?;
        let receipt = generation
            .snapshots
            .iter()
            .find(|receipt| receipt.snapshot == snapshot)
            .ok_or(RepositoryFailure::NotFound)?;
        let bytes = self.read_control_object(receipt.manifest).await?;
        let manifest = BackupManifest::verify(&bytes, self.identity, self.signer.identity())?;
        if manifest.snapshot != receipt.snapshot
            || manifest.created != receipt.created
            || manifest.retain_until != receipt.retain_until
        {
            return Err(RepositoryFailure::CorruptState);
        }
        let mut expected = expected.to_vec();
        expected.sort_unstable();
        if expected.windows(2).any(|pair| {
            pair.first()
                .zip(pair.get(1))
                .is_some_and(|(left, right)| left.tenant == right.tenant)
        }) || key_identity_context(expected.iter().copied()) != manifest.key_context
        {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        let references = generation
            .keys
            .iter()
            .filter(|key| key.context == manifest.key_context)
            .collect::<Vec<_>>();
        if references.iter().any(|key| {
            !expected.iter().any(|identity| {
                identity.tenant == key.tenant
                    && identity.epoch == key.epoch
                    && identity.fingerprint == key.fingerprint
            })
        }) {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        let mut keys = Vec::new();
        for identity in expected {
            if generation
                .tombstones
                .iter()
                .any(|tombstone| tombstone.tenant() == identity.tenant)
            {
                continue;
            }
            let reference = references
                .iter()
                .find(|key| {
                    key.tenant == identity.tenant
                        && key.epoch == identity.epoch
                        && key.fingerprint == identity.fingerprint
                })
                .ok_or(RepositoryFailure::NotFound)?;
            keys.push(**reference);
        }
        let head = head.ok_or(RepositoryFailure::CorruptState)?;
        if self
            .repository
            .registry_head_at(HeadSlot::registry())
            .await?
            .map(|head| head.version())
            != Some(head)
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        let check = BackupPublicationCheck::start(
            receipt.manifest.checksum(),
            head,
            manifest.objects.len() as u32,
            keys,
        );
        Ok(BackupSnapshotVerification::start(
            owner,
            request,
            manifest,
            registry.ok_or(RepositoryFailure::CorruptState)?,
            check,
        ))
    }
    /// Loads only authenticated control state; ciphertext advances in separate turns.
    pub async fn begin_snapshot_verification(
        &self,
        snapshot: [u8; 16],
        owner: [u8; 16],
        request: [u8; 32],
    ) -> Result<BackupSnapshotVerification, RepositoryFailure> {
        if owner == [0; 16] || request == [0; 32] {
            return Err(RepositoryFailure::InvalidInput);
        }
        self.require_identity().await?;
        let (_, current, registry) = self.current().await?;
        let generation = current.ok_or(RepositoryFailure::NotFound)?;
        let receipt = generation
            .snapshots
            .iter()
            .find(|receipt| receipt.snapshot == snapshot)
            .ok_or(RepositoryFailure::NotFound)?;
        let bytes = self.read_control_object(receipt.manifest).await?;
        let manifest = BackupManifest::verify(&bytes, self.identity, self.signer.identity())?;
        if manifest.snapshot != receipt.snapshot
            || manifest.created != receipt.created
            || manifest.retain_until != receipt.retain_until
        {
            return Err(RepositoryFailure::CorruptState);
        }
        let check = self.prepare_publication(&manifest).await?;
        Ok(BackupSnapshotVerification::start(
            owner,
            request,
            manifest,
            registry.ok_or(RepositoryFailure::CorruptState)?,
            check,
        ))
    }
    pub async fn snapshot_verification_step(
        &self,
        state: &mut BackupSnapshotVerification,
    ) -> Result<bool, RepositoryFailure> {
        if !state.check.complete() {
            return self
                .verify_publication_step(&state.manifest, &mut state.check)
                .await
                .map(|_| state.complete());
        }
        self.manifest_memory(&state.manifest, state.retained_memory_bytes()?)?;
        let Some(file) = state.files.get(state.next_file).copied() else {
            return Ok(true);
        };
        while state
            .manifest
            .objects
            .get(state.file_object)
            .is_some_and(|object| object.file == state.manifest.capture_index)
        {
            state.file_object += 1;
        }
        let object = state
            .manifest
            .objects
            .get(state.file_object)
            .ok_or(RepositoryFailure::CorruptState)?;
        if object.file != file.identity() {
            return Err(RepositoryFailure::CorruptState);
        }
        let length = (object.length - state.file_offset).min(crate::MAX_RANGE_BYTES);
        let bytes = self
            .repository
            .read_range(
                ObjectRange::new(object.object(), state.file_offset, length)?
                    .with_expected_size(object.length)?,
            )
            .await?;
        if bytes.bytes().len() as u64 != length {
            return Err(RepositoryFailure::CorruptState);
        }
        state.file_hash.update(bytes.bytes());
        state.file_offset += length;
        if state.file_offset == object.length {
            state.file_object += 1;
            state.file_offset = 0;
            if object.offset + object.length == file.size() {
                if <[u8; 32]>::from(std::mem::take(&mut state.file_hash).finalize())
                    != file.checksum()
                {
                    return Err(RepositoryFailure::ChecksumMismatch);
                }
                state.next_file += 1;
            }
        }
        Ok(state.complete())
    }
}

impl BackupPublisher<'_> {
    pub fn validate_snapshot_inventory(
        &self,
        state: &mut BackupSnapshotVerification,
        files: &[positron_kernel::BackupCaptureFile],
    ) -> Result<(), RepositoryFailure> {
        let mut objects = state
            .manifest
            .objects
            .iter()
            .filter(|object| object.file != state.manifest.capture_index)
            .peekable();
        for file in files {
            let mut end = 0;
            while let Some(object) = objects
                .peek()
                .filter(|object| object.file == file.identity())
            {
                if object.file_size != file.size() || object.offset != end {
                    return Err(RepositoryFailure::CorruptState);
                }
                end = end
                    .checked_add(object.length)
                    .ok_or(RepositoryFailure::LimitExceeded)?;
                objects.next();
            }
            if end != file.size() {
                return Err(RepositoryFailure::CorruptState);
            }
        }
        if objects.next().is_some() {
            return Err(RepositoryFailure::CorruptState);
        }
        // The authenticated inventory already establishes every native file
        // size. Admit its largest buffered metadata read before accepting it,
        // so later files cannot force repeated replay of earlier verification.
        let metadata_extent = files
            .iter()
            .filter(|file| {
                matches!(
                    file.kind(),
                    positron_kernel::BackupCaptureFileKind::CatalogObject
                        | positron_kernel::BackupCaptureFileKind::GovernanceAudit
                        | positron_kernel::BackupCaptureFileKind::AuditCheckpoint
                )
            })
            .map(|file| file.size())
            .max()
            .unwrap_or(0);
        self.ensure_control_memory(metadata_extent, 0)?;
        self.manifest_memory(
            &state.manifest,
            allocation_bytes::<positron_kernel::BackupCaptureFile>(files.len())?,
        )?;
        let mut inventory = Vec::new();
        inventory
            .try_reserve_exact(files.len())
            .map_err(|_| RepositoryFailure::LimitExceeded)?;
        inventory.extend_from_slice(files);
        state.files = inventory;
        state.next_file = match state.resumed_inventory.take() {
            Some((digest, completed))
                if digest == checkpoint::inventory_digest(files) && completed <= files.len() =>
            {
                completed
            },
            Some(_) => return Err(RepositoryFailure::CorruptState),
            None => 0,
        };
        state.file_object = state
            .manifest
            .objects
            .iter()
            .position(|object| {
                state
                    .files
                    .get(state.next_file)
                    .is_some_and(|file| object.file == file.identity())
            })
            .unwrap_or(state.manifest.objects.len());
        state.file_offset = 0;
        state.file_hash = Sha256::new();
        state.inventory_verified = true;
        Ok(())
    }
    pub fn verification_key_count(&self, state: &BackupSnapshotVerification) -> usize {
        state.check.keys.len()
    }
    pub async fn read_verification_key(
        &self,
        state: &BackupSnapshotVerification,
        index: usize,
    ) -> Result<BackupKeyEnvelope, RepositoryFailure> {
        let reference = state
            .check
            .keys
            .get(index)
            .ok_or(RepositoryFailure::InvalidInput)?;
        let bytes = self.read_control_object(reference.object).await?;
        let envelope = BackupKeyEnvelope::decode_object(&bytes)?;
        if envelope.tenant != reference.tenant
            || envelope.epoch != reference.epoch
            || envelope.fingerprint != reference.fingerprint
        {
            return Err(RepositoryFailure::CorruptState);
        }
        Ok(envelope)
    }
    /// Reads a bounded complete logical file for native metadata authentication.
    /// Data segments use the streaming verification cursor instead.
    pub async fn read_snapshot_file(
        &self,
        manifest: &BackupManifest,
        file: [u8; 32],
        maximum: u64,
    ) -> Result<Vec<u8>, RepositoryFailure> {
        self.manifest_memory(manifest, 0)?;
        let first = manifest
            .objects
            .iter()
            .find(|object| object.file == file)
            .ok_or(RepositoryFailure::NotFound)?;
        if first.file_size > maximum || maximum > MAX_CONTROL_BYTES {
            return Err(RepositoryFailure::LimitExceeded);
        }
        self.ensure_control_memory(first.file_size, 0)?;
        super::super::read::file_bytes(self.repository, manifest, file).await
    }
}
