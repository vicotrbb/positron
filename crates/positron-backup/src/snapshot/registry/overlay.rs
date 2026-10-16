//! Signed additive recovery routes. Runtime proves provider recovery before publication.
use super::*;
use positron_kernel::key_provider::{KeyEnvelope, KeyScope, ProviderKeyUri};
pub(super) const MAX_OVERLAYS: usize = 4096;
const MAX_OVERLAY_BYTES: usize = 18_400;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OverlayReference {
    pub(super) snapshot: [u8; 16],
    pub(super) target: [u8; 32],
    pub(super) object: ObjectId,
}
/// Additional root recovery route for one exact immutable snapshot.
/// Provider recovery proof belongs to Runtime; this artifact authenticates its bindings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupEnvelopeOverlay {
    snapshot: [u8; 16],
    manifest: ObjectId,
    context: [u8; 32],
    operation: [u8; 16],
    source: KeyEnvelope,
    target: KeyEnvelope,
}
impl BackupEnvelopeOverlay {
    pub fn new(
        snapshot: [u8; 16],
        manifest: ObjectId,
        key_context: [u8; 32],
        operation: [u8; 16],
        source: KeyEnvelope,
        target: KeyEnvelope,
    ) -> Result<Self, RepositoryFailure> {
        if snapshot == [0; 16]
            || manifest.checksum() == [0; 32]
            || key_context == [0; 32]
            || operation == [0; 16]
        {
            return Err(RepositoryFailure::InvalidInput);
        }
        if source.context() != target.context()
            || source.context().scope() != KeyScope::System
            || source.identity() == target.identity()
        {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        Ok(Self {
            snapshot,
            manifest,
            context: key_context,
            operation,
            source,
            target,
        })
    }
    pub const fn snapshot_id(&self) -> [u8; 16] {
        self.snapshot
    }
    pub const fn manifest(&self) -> ObjectId {
        self.manifest
    }
    pub const fn key_context(&self) -> [u8; 32] {
        self.context
    }
    pub const fn operation(&self) -> [u8; 16] {
        self.operation
    }
    pub const fn source(&self) -> &KeyEnvelope {
        &self.source
    }
    pub const fn target(&self) -> &KeyEnvelope {
        &self.target
    }
    pub fn retained_memory_bytes(&self) -> u64 {
        self.source.retained_memory_bytes() + self.target.retained_memory_bytes()
    }
    pub fn signed_bytes(
        &self,
        repository: &RepositoryIdentity,
        signer: &BackupControlSigner,
    ) -> Result<Vec<u8>, RepositoryFailure> {
        if self.source.context().instance() != repository.instance_id()
            || signer.identity().fingerprint() != repository.integrity_fingerprint()
        {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        let mut bytes = b"POSBEO01".to_vec();
        bytes.extend_from_slice(&repository.encode());
        bytes.extend_from_slice(&self.snapshot);
        bytes.extend_from_slice(&self.manifest.checksum());
        bytes.extend_from_slice(&self.context);
        bytes.extend_from_slice(&self.operation);
        for envelope in [&self.source, &self.target] {
            let encoded = envelope.encode();
            bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&encoded);
        }
        super::super::codec::sign(bytes, signer)
    }
    pub fn verify(
        bytes: &[u8],
        repository: &RepositoryIdentity,
        integrity: BootstrapIntegrityIdentity,
    ) -> Result<Self, RepositoryFailure> {
        if bytes.len() > MAX_OVERLAY_BYTES {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let mut decoder =
            super::super::codec::Decoder::new(super::super::codec::verify(bytes, integrity)?);
        if decoder.take(8)? != b"POSBEO01" {
            return Err(RepositoryFailure::CorruptState);
        }
        if RepositoryIdentity::decode(decoder.take(108)?)? != *repository
            || integrity.fingerprint() != repository.integrity_fingerprint()
        {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        let snapshot = decoder.array()?;
        let manifest = ObjectId::from_checksum(decoder.array()?);
        let context = decoder.array()?;
        let operation = decoder.array()?;
        let mut envelope = || {
            let length = decoder.u32()? as usize;
            if length > 9000 {
                return Err(RepositoryFailure::LimitExceeded);
            }
            KeyEnvelope::decode(decoder.take(length)?).map_err(|_| RepositoryFailure::CorruptState)
        };
        let source = envelope()?;
        let target = envelope()?;
        decoder.finish()?;
        let value = Self::new(snapshot, manifest, context, operation, source, target)?;
        if value.source.context().instance() != repository.instance_id() {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        Ok(value)
    }
}
fn target_digest(target: &ProviderKeyUri) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"positron-backup-overlay-target-v1\0");
    hash.update([target.family() as u8]);
    for part in [target.locator(), target.version()] {
        hash.update((part.len() as u32).to_be_bytes());
        hash.update(part.as_bytes());
    }
    hash.finalize().into()
}
impl BackupPublisher<'_> {
    async fn overlay_manifest(
        &self,
        generation: &Generation,
        snapshot: [u8; 16],
    ) -> Result<BackupManifest, RepositoryFailure> {
        let receipt = generation
            .snapshots
            .iter()
            .find(|receipt| receipt.snapshot == snapshot)
            .ok_or(RepositoryFailure::NotFound)?;
        self.read_registered_manifest(*receipt).await
    }
    /// Publishes an immutable signed recovery route through the existing Registry CAS.
    /// Repeating the exact artifact returns the current verified Registry anchor.
    pub async fn publish_envelope_overlay(
        &self,
        overlay: &BackupEnvelopeOverlay,
    ) -> Result<[u8; 32], RepositoryFailure> {
        self.ensure_control_memory(MAX_OVERLAY_BYTES as u64, overlay.retained_memory_bytes())?;
        self.require_identity().await?;
        let (version, generation, registry) = self.current().await?;
        let mut generation = generation.ok_or(RepositoryFailure::NotFound)?;
        let manifest = self.overlay_manifest(&generation, overlay.snapshot).await?;
        let receipt = generation
            .snapshots
            .iter()
            .find(|receipt| receipt.snapshot == overlay.snapshot)
            .ok_or(RepositoryFailure::NotFound)?;
        if receipt.manifest != overlay.manifest || manifest.key_context != overlay.context {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        let object = ImmutableObject::new(overlay.signed_bytes(self.identity, self.signer)?)?;
        let target = target_digest(overlay.target.identity());
        if let Some(existing) = generation
            .overlays
            .iter()
            .find(|reference| reference.snapshot == overlay.snapshot && reference.target == target)
        {
            if existing.object != object.id() {
                return Err(RepositoryFailure::PreconditionFailed);
            }
            let read = self.read_control_object(existing.object).await?;
            if BackupEnvelopeOverlay::verify(&read, self.identity, self.signer.identity())?
                != *overlay
            {
                return Err(RepositoryFailure::CorruptState);
            }
            self.recheck_overlay_head(version).await?;
            return registry.ok_or(RepositoryFailure::CorruptState);
        }
        if generation.overlays.len() >= MAX_OVERLAYS {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let object_id = object.id();
        self.ensure_control_memory(
            generation
                .encoded_length()?
                .checked_add(80)
                .ok_or(RepositoryFailure::LimitExceeded)?,
            overlay.retained_memory_bytes(),
        )?;
        self.repository.put_if_absent(object).await?;
        generation
            .overlays
            .try_reserve_exact(1)
            .map_err(|_| RepositoryFailure::LimitExceeded)?;
        generation.overlays.push(OverlayReference {
            snapshot: overlay.snapshot,
            target,
            object: object_id,
        });
        generation
            .overlays
            .sort_by_key(|reference| (reference.snapshot, reference.target));
        generation.number = generation
            .number
            .checked_add(1)
            .ok_or(RepositoryFailure::LimitExceeded)?;
        generation.previous = registry.ok_or(RepositoryFailure::CorruptState)?;
        self.publish_generation(version, &generation).await?;
        let (_, actual, registry) = self.current().await?;
        if !actual.is_some_and(|state| {
            state
                .overlays
                .iter()
                .any(|reference| reference.object == object_id)
        }) {
            return Err(RepositoryFailure::OutcomeUnknown);
        }
        registry.ok_or(RepositoryFailure::CorruptState)
    }
    pub async fn read_envelope_overlay(
        &self,
        snapshot: [u8; 16],
        target: &ProviderKeyUri,
    ) -> Result<Option<BackupEnvelopeOverlay>, RepositoryFailure> {
        self.ensure_control_memory(MAX_OVERLAY_BYTES as u64, 0)?;
        self.require_identity().await?;
        let (version, generation, _) = self.current().await?;
        let generation = generation.ok_or(RepositoryFailure::NotFound)?;
        let manifest = self.overlay_manifest(&generation, snapshot).await?;
        let target_identity = target_digest(target);
        let reference = generation.overlays.iter().find(|reference| {
            reference.snapshot == snapshot && reference.target == target_identity
        });
        let result = if let Some(reference) = reference {
            let bytes = self.read_control_object(reference.object).await?;
            let overlay =
                BackupEnvelopeOverlay::verify(&bytes, self.identity, self.signer.identity())?;
            let receipt = generation
                .snapshots
                .iter()
                .find(|receipt| receipt.snapshot == snapshot)
                .ok_or(RepositoryFailure::CorruptState)?;
            if overlay.snapshot != snapshot
                || overlay.manifest != receipt.manifest
                || overlay.context != manifest.key_context
                || overlay.target.identity() != target
            {
                return Err(RepositoryFailure::CorruptState);
            }
            Some(overlay)
        } else {
            None
        };
        self.recheck_overlay_head(version).await?;
        Ok(result)
    }
    async fn recheck_overlay_head(
        &self,
        expected: Option<ObjectVersion>,
    ) -> Result<(), RepositoryFailure> {
        if self
            .repository
            .registry_head_at(HeadSlot::registry())
            .await?
            .map(|head| head.version())
            != expected
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        Ok(())
    }
}
