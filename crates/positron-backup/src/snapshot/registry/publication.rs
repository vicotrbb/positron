//! Bounded verify-before-publication, with authenticated restart progress.
use super::*;
pub struct BackupPublicationCheck {
    pub(super) manifest: [u8; 32],
    pub(super) head: ObjectVersion,
    objects: u32,
    next_object: u32,
    pub(super) keys: Vec<KeyReference>,
    next_key: u32,
    offset: u64,
    digest: Sha256,
}
impl std::fmt::Debug for BackupPublicationCheck {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BackupPublicationCheck")
            .field("next_object", &self.next_object)
            .field("object_count", &self.objects)
            .field("offset", &self.offset)
            .field("next_key", &self.next_key)
            .field("key_count", &self.keys.len())
            .finish()
    }
}

impl BackupPublicationCheck {
    pub(super) fn start(
        manifest: [u8; 32],
        head: ObjectVersion,
        objects: u32,
        keys: Vec<KeyReference>,
    ) -> Self {
        Self {
            manifest,
            head,
            objects,
            next_object: 0,
            keys,
            next_key: 0,
            offset: 0,
            digest: Sha256::new(),
        }
    }
    pub fn retained_memory_bytes(&self) -> Result<u64, RepositoryFailure> {
        allocation_bytes::<KeyReference>(self.keys.capacity())
    }

    pub fn next_step_bytes(&self, manifest: &BackupManifest) -> Result<u64, RepositoryFailure> {
        if let Some(object) = manifest.objects.get(self.next_object as usize) {
            object
                .length
                .checked_sub(self.offset)
                .map(|length| length.min(crate::MAX_RANGE_BYTES))
                .ok_or(RepositoryFailure::CorruptState)
        } else {
            Ok(16_384)
        }
    }
    pub fn complete(&self) -> bool {
        self.next_object == self.objects && self.next_key as usize == self.keys.len()
    }
}
impl BackupPublisher<'_> {
    /// Reconcile a possible prior CAS from the exact durable candidate. This
    /// proves its publication history, rather than repeating a later scrub of
    /// data that may have changed since that successful publication.
    pub async fn reconcile_publication(
        &self,
        manifest: &BackupManifest,
    ) -> Result<Option<BackupPublication>, RepositoryFailure> {
        self.require_identity().await?;
        if manifest.repository != *self.identity {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        let object = self.manifest_object(manifest)?;
        let expected = BackupReceipt {
            snapshot: manifest.snapshot,
            manifest: object.id(),
            created: manifest.created,
            retain_until: manifest.retain_until,
        };
        let (head, generation, registry) = self.current().await?;
        let generation = generation.ok_or(RepositoryFailure::OutcomeUnknown)?;
        let published = if let Some(receipt) = generation
            .snapshots
            .iter()
            .find(|receipt| receipt.snapshot == manifest.snapshot)
        {
            if *receipt != expected {
                return Err(RepositoryFailure::PreconditionFailed);
            }
            let keys = generation
                .keys
                .iter()
                .filter(|key| key.context == manifest.key_context)
                .copied()
                .collect::<Vec<_>>();
            if context_digest(&keys) != manifest.key_context {
                return Err(RepositoryFailure::CorruptState);
            }
            Some(BackupPublication {
                receipt: *receipt,
                registry: registry.ok_or(RepositoryFailure::CorruptState)?,
            })
        } else if generation.reservations.contains(&expected) {
            None
        } else {
            return Err(RepositoryFailure::OutcomeUnknown);
        };
        if self
            .repository
            .registry_head_at(HeadSlot::registry())
            .await?
            .map(|head| head.version())
            != head
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        Ok(published)
    }
    pub async fn prepare_publication(
        &self,
        manifest: &BackupManifest,
    ) -> Result<BackupPublicationCheck, RepositoryFailure> {
        self.require_identity().await?;
        if manifest.repository != *self.identity {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        let object = self.manifest_object(manifest)?;
        let (head, generation, _) = self.current().await?;
        let generation = generation.ok_or(RepositoryFailure::PreconditionFailed)?;
        let expected = BackupReceipt {
            snapshot: manifest.snapshot,
            manifest: object.id(),
            created: manifest.created,
            retain_until: manifest.retain_until,
        };
        if !generation
            .snapshots
            .iter()
            .chain(&generation.reservations)
            .any(|receipt| *receipt == expected)
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        let keys = generation
            .keys
            .into_iter()
            .filter(|key| key.context == manifest.key_context)
            .collect::<Vec<_>>();
        if context_digest(&keys) != manifest.key_context {
            return Err(RepositoryFailure::CorruptState);
        }
        Ok(BackupPublicationCheck::start(
            object.id().checksum(),
            head.ok_or(RepositoryFailure::CorruptState)?,
            manifest.objects.len() as u32,
            keys,
        ))
    }
    /// Completed-object counts are authenticated; partial hashes are never
    /// serialized. Recovery starts the unfinished object at offset zero.
    pub fn publication_checkpoint(
        &self,
        state: &BackupPublicationCheck,
    ) -> Result<Vec<u8>, RepositoryFailure> {
        self.ensure_control_memory(0, allocation_bytes::<KeyReference>(state.keys.capacity())?)?;
        let mut bytes = b"POSBVP01".to_vec();
        bytes.extend_from_slice(&state.manifest);
        bytes.extend_from_slice(&state.head.checksum());
        bytes.extend_from_slice(&state.next_object.to_be_bytes());
        bytes.extend_from_slice(&state.next_key.to_be_bytes());
        super::super::codec::sign(bytes, self.signer)
    }
    pub async fn resume_publication(
        &self,
        manifest: &BackupManifest,
        checkpoint: &[u8],
    ) -> Result<BackupPublicationCheck, RepositoryFailure> {
        let mut state = self.prepare_publication(manifest).await?;
        let mut decoder = super::super::codec::Decoder::new(super::super::codec::verify(
            checkpoint,
            self.signer.identity(),
        )?);
        if decoder.take(8)? != b"POSBVP01" || decoder.array::<32>()? != state.manifest {
            return Err(RepositoryFailure::CorruptState);
        }
        let head = decoder.array::<32>()?;
        let next_object = decoder.u32()?;
        let next_key = decoder.u32()?;
        decoder.finish()?;
        if next_object > state.objects
            || next_key as usize > state.keys.len()
            || (next_key != 0 && next_object != state.objects)
        {
            return Err(RepositoryFailure::CorruptState);
        }
        if head == state.head.checksum() {
            state.next_object = next_object;
            state.next_key = next_key;
        }
        Ok(state)
    }
    pub async fn verify_publication_step(
        &self,
        manifest: &BackupManifest,
        state: &mut BackupPublicationCheck,
    ) -> Result<bool, RepositoryFailure> {
        self.manifest_memory(
            manifest,
            allocation_bytes::<KeyReference>(state.keys.capacity())?,
        )?;
        if self.manifest_object(manifest)?.id().checksum() != state.manifest {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        if self
            .repository
            .registry_head_at(HeadSlot::registry())
            .await?
            .map(|head| head.version())
            != Some(state.head)
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        if let Some(object) = manifest.objects.get(state.next_object as usize) {
            if state.offset == 0 {
                let size = self.repository.object_size_hint(object.object()).await?;
                if size != object.length {
                    return Err(RepositoryFailure::ChecksumMismatch);
                }
            }
            let length = (object.length - state.offset).min(crate::MAX_RANGE_BYTES);
            let part = self
                .repository
                .read_range(
                    ObjectRange::new(object.object(), state.offset, length)?
                        .with_expected_size(object.length)?,
                )
                .await?;
            if part.bytes().len() as u64 != length {
                return Err(RepositoryFailure::CorruptState);
            }
            state.digest.update(part.bytes());
            state.offset += length;
            if state.offset == object.length {
                if <[u8; 32]>::from(state.digest.clone().finalize()) != object.checksum {
                    return Err(RepositoryFailure::ChecksumMismatch);
                }
                state.next_object += 1;
                state.offset = 0;
                state.digest = Sha256::new();
            }
            return Ok(false);
        }
        if let Some(reference) = state.keys.get(state.next_key as usize) {
            let bytes = self.read_control_object(reference.object).await?;
            let envelope = BackupKeyEnvelope::decode_object(&bytes)?;
            if envelope.tenant != reference.tenant
                || envelope.epoch != reference.epoch
                || envelope.fingerprint != reference.fingerprint
            {
                return Err(RepositoryFailure::CorruptState);
            }
            state.next_key += 1;
        }
        Ok(state.complete())
    }
    pub async fn commit_publication(
        &self,
        manifest: &BackupManifest,
        state: &BackupPublicationCheck,
    ) -> Result<BackupPublication, RepositoryFailure> {
        self.manifest_memory(
            manifest,
            allocation_bytes::<KeyReference>(state.keys.capacity())?,
        )?;
        if !state.complete() || self.manifest_object(manifest)?.id().checksum() != state.manifest {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        let (version, generation, current_id) = self.current().await?;
        if version != Some(state.head) {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        let mut generation = generation.ok_or(RepositoryFailure::PreconditionFailed)?;
        let receipt = BackupReceipt {
            snapshot: manifest.snapshot,
            manifest: ObjectId::from_checksum(state.manifest),
            created: manifest.created,
            retain_until: manifest.retain_until,
        };
        if generation.snapshots.contains(&receipt) {
            return Ok(BackupPublication {
                receipt,
                registry: current_id.ok_or(RepositoryFailure::CorruptState)?,
            });
        }
        if !generation.reservations.contains(&receipt) {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        generation.number = generation
            .number
            .checked_add(1)
            .ok_or(RepositoryFailure::LimitExceeded)?;
        generation.previous = current_id.ok_or(RepositoryFailure::CorruptState)?;
        generation
            .reservations
            .retain(|reserved| reserved.snapshot != receipt.snapshot);
        generation.snapshots.push(receipt);
        generation.snapshots.sort_by_key(|receipt| receipt.snapshot);
        self.publish_generation(version, &generation).await?;
        let (_, actual, registry) = self.current().await?;
        if !actual.is_some_and(|generation| generation.snapshots.contains(&receipt)) {
            return Err(RepositoryFailure::OutcomeUnknown);
        }
        Ok(BackupPublication {
            receipt,
            registry: registry.ok_or(RepositoryFailure::CorruptState)?,
        })
    }
}
