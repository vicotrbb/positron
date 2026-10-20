#[cfg(all(fuzzing, feature = "test-support"))]
mod fuzzing;
#[cfg(all(fuzzing, feature = "test-support"))]
pub(crate) use fuzzing::fuzz_control_frames;
mod codec;
mod expiry;
use expiry::DeletionClaim;
pub use expiry::{BackupCleanupPlan, BackupCleanupProgress, BackupCleanupReason};
mod barrier;
mod purge;
mod purge_fence;
pub use purge::BackupTenantPurge;
pub use purge_fence::TenantKeyPurgeFence;
mod tombstone;
pub use tombstone::BackupPurgeTombstone;
mod overlay;
pub use overlay::BackupEnvelopeOverlay;
use overlay::OverlayReference;
pub(super) use overlay::recovery_overlay;
mod listing;
mod publication;
mod snapshot_verification;
pub use snapshot_verification::{
    BackupRestoreReport, BackupSnapshotVerification, BackupVerificationReport,
};
mod verification;
pub use verification::BackupRegistryVerification;
use verification::{CachedGeneration, VerifiedHead};
mod reservation;
use super::*;
use crate::{
    CasOutcome, HeadSlot, ImmutableObject, ObjectId, ObjectRange, ObjectVersion,
    RegistryHeadChange, Repository,
};
pub use listing::{BackupListCursor, BackupSnapshotPage};
pub use publication::BackupPublicationCheck;
use sha2::{Digest, Sha256};
const MAX_CONTROL_BYTES: u64 = 8 * 1024 * 1024;
const MAX_REGISTRY_GENERATIONS: usize = 65_536;
const MAX_REGISTERED_SNAPSHOTS: usize = 1024;
const MAX_KEY_ENVELOPES: usize = 4096;
/// Authenticated source key identity, without requiring a destroyed envelope.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BackupKeyIdentity {
    tenant: [u8; 16],
    epoch: u64,
    fingerprint: [u8; 32],
}
impl BackupKeyIdentity {
    pub fn new(
        tenant: [u8; 16],
        epoch: u64,
        fingerprint: [u8; 32],
    ) -> Result<Self, RepositoryFailure> {
        if tenant == [0; 16] || epoch == 0 || fingerprint == [0; 32] {
            return Err(RepositoryFailure::InvalidInput);
        }
        Ok(Self {
            tenant,
            epoch,
            fingerprint,
        })
    }
}
/// A tenant KEK envelope already authenticated by Data Protection. The root
/// key itself, credentials and Recovery Bundles never enter this boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct BackupKeyEnvelope {
    tenant: [u8; 16],
    epoch: u64,
    fingerprint: [u8; 32],
    protected: Vec<u8>,
}
impl std::fmt::Debug for BackupKeyEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BackupKeyEnvelope { <protected> }")
    }
}
const MAX_KEY_PROTECTED_BYTES: usize = 16_384;
const MAX_KEY_OBJECT_BYTES: u64 = 8 + 16 + 8 + 32 + 4 + MAX_KEY_PROTECTED_BYTES as u64;

impl BackupKeyEnvelope {
    pub fn new(
        tenant: [u8; 16],
        epoch: u64,
        fingerprint: [u8; 32],
        protected: Vec<u8>,
    ) -> Result<Self, RepositoryFailure> {
        if tenant == [0; 16]
            || epoch == 0
            || fingerprint == [0; 32]
            || protected.is_empty()
            || protected.len() > MAX_KEY_PROTECTED_BYTES
        {
            return Err(RepositoryFailure::InvalidInput);
        }
        Ok(Self {
            tenant,
            epoch,
            fingerprint,
            protected,
        })
    }
    pub const fn tenant(&self) -> [u8; 16] {
        self.tenant
    }
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    pub const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
    pub fn protected(&self) -> &[u8] {
        &self.protected
    }
    pub fn retained_memory_bytes(&self) -> u64 {
        self.protected.capacity() as u64
    }
    pub(super) fn object(&self) -> Result<ImmutableObject, RepositoryFailure> {
        let mut bytes = b"POSBKE01".to_vec();
        bytes.extend_from_slice(&self.tenant);
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.fingerprint);
        bytes.extend_from_slice(&(self.protected.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.protected);
        ImmutableObject::new(bytes)
    }
    pub(super) fn decode_object(bytes: &[u8]) -> Result<Self, RepositoryFailure> {
        let mut decoder = super::codec::Decoder::new(bytes);
        if decoder.take(8)? != b"POSBKE01" {
            return Err(RepositoryFailure::CorruptState);
        }
        let tenant = decoder.array()?;
        let epoch = decoder.u64()?;
        let fingerprint = decoder.array()?;
        let length = decoder.u32()? as usize;
        if length == 0 || length > MAX_KEY_PROTECTED_BYTES {
            return Err(RepositoryFailure::CorruptState);
        }
        let protected = decoder.take(length)?.to_vec();
        decoder.finish()?;
        Self::new(tenant, epoch, fingerprint, protected)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct KeyReference {
    context: [u8; 32],
    tenant: [u8; 16],
    epoch: u64,
    fingerprint: [u8; 32],
    object: ObjectId,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupReceipt {
    snapshot: [u8; 16],
    manifest: ObjectId,
    created: u64,
    retain_until: u64,
}
/// Exact verified Registry Generation accompanying a publication receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupPublication {
    receipt: BackupReceipt,
    registry: [u8; 32],
}
impl BackupPublication {
    pub const fn snapshot_id(self) -> [u8; 16] {
        self.receipt.snapshot_id()
    }
    pub const fn manifest(self) -> ObjectId {
        self.receipt.manifest()
    }
    pub const fn retain_until(self) -> u64 {
        self.receipt.retain_until()
    }
    pub const fn registry_generation(self) -> [u8; 32] {
        self.registry
    }
}
impl BackupReceipt {
    pub const fn created_at(self) -> u64 {
        self.created
    }
    pub const fn snapshot_id(self) -> [u8; 16] {
        self.snapshot
    }
    pub const fn manifest(self) -> ObjectId {
        self.manifest
    }
    pub const fn retain_until(self) -> u64 {
        self.retain_until
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Generation {
    number: u64,
    previous: [u8; 32],
    repository: RepositoryIdentity,
    snapshots: Vec<BackupReceipt>,
    reservations: Vec<BackupReceipt>,
    claims: Vec<DeletionClaim>,
    keys: Vec<KeyReference>,
    overlays: Vec<OverlayReference>,
    tombstones: Vec<BackupPurgeTombstone>,
}
/// Deep Backup workflow boundary; Repository provider calls stay internal.
pub struct BackupPublisher<'a> {
    pub(super) repository: &'a dyn Repository,
    identity: &'a RepositoryIdentity,
    signer: &'a BackupControlSigner,
    trusted: Option<[u8; 32]>,
    resources: Option<&'a positron_kernel::NativeAwsResources>,
    external_retained: u64,
    control_extent: std::sync::atomic::AtomicU64,
    retained_inputs: std::sync::atomic::AtomicU64,
    cache_memory: std::sync::atomic::AtomicU64,
    verification: Option<&'a BackupRegistryVerification>,
    known_head: std::sync::Mutex<Option<VerifiedHead>>,
    successor: std::sync::Mutex<Option<CachedGeneration>>,
}
impl<'a> BackupPublisher<'a> {
    /// Initial control admission, excluding native transport and retained capture.
    /// Larger controls report their complete required claim before body allocation.
    pub const fn control_read_memory_bytes() -> u64 {
        MAX_CONTROL_BYTES
    }

    /// Maximum canonical signed Registry read, excluding provider transport.
    /// The fixed base and eightfold wire overlap are the same control guard
    /// used before decoding; callers add their provider and unrelated heap.
    pub const fn registry_read_memory_bytes() -> u64 {
        MAX_CONTROL_BYTES + 8 * verification::MAX_GENERATION_BYTES
    }

    /// Uses a live system Maintenance repository grant. The trusted Runtime owner
    /// supplies only unrelated retained capture/context/checkpoint heap bytes;
    /// manifest, publication and cleanup inputs are measured here, not twice.
    pub fn with_control_resources(
        mut self,
        resources: &'a positron_kernel::NativeAwsResources,
        external_retained_capture_bytes: u64,
    ) -> Result<Self, RepositoryFailure> {
        if !resources.authorizes_repository_transport() {
            return Err(RepositoryFailure::PermissionDenied);
        }
        self.resources = Some(resources);
        self.external_retained = external_retained_capture_bytes;
        self.ensure_control_memory(0, 0)?;
        Ok(self)
    }
    fn ensure_control_memory(&self, extent: u64, retained: u64) -> Result<(), RepositoryFailure> {
        use std::sync::atomic::Ordering;
        if extent > MAX_CONTROL_BYTES {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let extent = self
            .control_extent
            .fetch_max(extent, Ordering::Relaxed)
            .max(extent);
        let retained = self
            .retained_inputs
            .fetch_max(retained, Ordering::Relaxed)
            .max(retained);
        // Wire records are receipt=64, key=120, claim=97+32N bytes. Bounded
        // decoded generations (including Vec headers) use less than 1.4x wire.
        // Current+historical decoded generations+body use <=3.8L; a nested
        // retained successor adds <=1.4L, and a signed candidate capacity <=2L:
        // <=7.2L altogether. Eight units cover that conservative overlap.
        // Caller-held input Vec capacities are added separately. The fixed
        // 8MiB also covers malformed bounded counts before decoding fails (the
        // largest table is 65536*88 bytes), a bounded range and small headers.
        // For large ranges the 8L term covers that range independently.
        let native = super::read::native_memory(self.identity)?;
        let memory_bytes = native
            .checked_add(MAX_CONTROL_BYTES)
            .and_then(|n| extent.checked_mul(8).and_then(|e| n.checked_add(e)))
            .and_then(|n| n.checked_add(retained))
            .and_then(|n| n.checked_add(self.external_retained))
            .and_then(|n| n.checked_add(self.cache_memory.load(Ordering::Relaxed)))
            .ok_or(RepositoryFailure::LimitExceeded)?;
        match self.resources {
            Some(resources)
                if resources.authorizes_repository_transport()
                    && resources
                        .granted()
                        .get(positron_kernel::ResourceDimension::MemoryBytes)
                        >= memory_bytes =>
            {
                Ok(())
            },
            _ => Err(RepositoryFailure::ControlMemoryRequired { memory_bytes }),
        }
    }
    fn manifest_memory(
        &self,
        manifest: &BackupManifest,
        additional: u64,
    ) -> Result<(), RepositoryFailure> {
        let extent = 380u64
            .checked_add(
                (manifest.objects.len() as u64)
                    .checked_mul(88)
                    .ok_or(RepositoryFailure::LimitExceeded)?,
            )
            .ok_or(RepositoryFailure::LimitExceeded)?;
        let retained = allocation_bytes::<BackupObject>(manifest.objects.capacity())?
            .checked_add(additional)
            .ok_or(RepositoryFailure::LimitExceeded)?;
        self.ensure_control_memory(extent, retained)
    }
    pub(super) fn capture_memory(
        &self,
        manifest: &BackupManifest,
        keys: &[BackupKeyEnvelope],
        file_map: u64,
    ) -> Result<(), RepositoryFailure> {
        self.key_memory(keys, manifest)?;
        // Candidate metadata remains alive when step returns its verified clone.
        // Raw envelope capacity is owned by the caller's external amount.
        let retained = file_map
            .checked_add(allocation_bytes::<KeyReference>(keys.len())?)
            .and_then(|bytes| {
                allocation_bytes::<BackupObject>(manifest.objects.capacity())
                    .ok()
                    .and_then(|candidate| bytes.checked_add(candidate))
            })
            .ok_or(RepositoryFailure::LimitExceeded)?;
        self.manifest_memory(manifest, retained)
    }
    fn manifest_object(
        &self,
        manifest: &BackupManifest,
    ) -> Result<ImmutableObject, RepositoryFailure> {
        self.manifest_memory(manifest, 0)?;
        ImmutableObject::new(manifest.signed_bytes(self.signer)?)
    }
    fn key_memory(
        &self,
        keys: &[BackupKeyEnvelope],
        manifest: &BackupManifest,
    ) -> Result<(), RepositoryFailure> {
        if keys.len() > MAX_KEY_ENVELOPES {
            return Err(RepositoryFailure::LimitExceeded);
        }
        // Raw envelope storage belongs to the external capture/context amount.
        // Generated references are an internal control inventory, not another
        // copy of that protected input.
        self.ensure_control_memory(allocation_bytes::<KeyReference>(keys.len())?, 0)?;
        self.manifest_memory(manifest, 0)
    }

    pub fn new(
        repository: &'a dyn Repository,
        identity: &'a RepositoryIdentity,
        signer: &'a BackupControlSigner,
    ) -> Self {
        Self {
            repository,
            identity,
            signer,
            trusted: None,
            resources: None,
            external_retained: 0,
            control_extent: std::sync::atomic::AtomicU64::new(0),
            retained_inputs: std::sync::atomic::AtomicU64::new(0),
            cache_memory: std::sync::atomic::AtomicU64::new(0),
            verification: None,
            known_head: std::sync::Mutex::new(None),
            successor: std::sync::Mutex::new(None),
        }
    }
    pub fn with_trusted_generation(
        mut self,
        generation: [u8; 32],
    ) -> Result<Self, RepositoryFailure> {
        if generation == [0; 32] {
            return Err(RepositoryFailure::InvalidInput);
        }
        self.trusted = Some(generation);
        Ok(self)
    }
    pub(super) async fn require_identity(&self) -> Result<(), RepositoryFailure> {
        self.ensure_control_memory(0, 0)?;
        if self.repository.identify().await? != *self.identity
            || self.signer.identity().fingerprint() != self.identity.integrity_fingerprint()
        {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        Ok(())
    }
    pub fn key_context(keys: &[BackupKeyEnvelope]) -> Result<[u8; 32], RepositoryFailure> {
        // The independently authenticated source Catalog may contain no
        // recoverable tenant keys after purge. Its signed empty identity digest
        // remains distinct from every nonempty manifest context.
        Ok(context_digest(&key_references(keys)?))
    }
    /// Publishes only after every encrypted object and independent key binding
    /// has been verified. The immutable generation is durable before head CAS.
    pub async fn publish(
        &self,
        manifest: &BackupManifest,
        keys: &[BackupKeyEnvelope],
    ) -> Result<BackupPublication, RepositoryFailure> {
        self.key_memory(keys, manifest)?;
        if Self::key_context(keys)? != manifest.key_context {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        let mut next_key = 0;
        while usize::try_from(next_key).map_err(|_| RepositoryFailure::LimitExceeded)? < keys.len()
        {
            next_key = self.prepare_key_step(manifest, keys, next_key).await?;
        }
        let mut state = self.prepare_publication(manifest).await?;
        while !self.verify_publication_step(manifest, &mut state).await? {}
        self.commit_publication(manifest, &state).await
    }
    pub async fn verify(&self, snapshot: [u8; 16]) -> Result<BackupManifest, RepositoryFailure> {
        self.verify_current(snapshot)
            .await
            .map(|(manifest, _)| manifest)
    }
    async fn verify_current(
        &self,
        snapshot: [u8; 16],
    ) -> Result<(BackupManifest, [u8; 32]), RepositoryFailure> {
        self.require_identity().await?;
        let (verified_head, current, registry) = self.current().await?;
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
        let matching = generation
            .keys
            .iter()
            .filter(|key| key.context == manifest.key_context)
            .copied()
            .collect::<Vec<_>>();
        if context_digest(&matching) != manifest.key_context {
            return Err(RepositoryFailure::CorruptState);
        }
        // Key references are verified independently of the immutable ciphertext.
        for reference in &matching {
            let bytes = self.read_control_object(reference.object).await?;
            let mut decoder = super::codec::Decoder::new(&bytes);
            if decoder.take(8)? != b"POSBKE01"
                || decoder.array::<16>()? != reference.tenant
                || decoder.u64()? != reference.epoch
                || decoder.array::<32>()? != reference.fingerprint
            {
                return Err(RepositoryFailure::CorruptState);
            }
            let length = decoder.u32()? as usize;
            if length == 0 || length > MAX_KEY_PROTECTED_BYTES {
                return Err(RepositoryFailure::CorruptState);
            }
            decoder.take(length)?;
            decoder.finish()?;
        }
        for object in &manifest.objects {
            super::transfer::verify_object(self.repository, object.object(), object.length).await?;
        }
        if self
            .repository
            .registry_head_at(HeadSlot::registry())
            .await?
            .map(|head| head.version())
            != verified_head
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        Ok((manifest, registry.ok_or(RepositoryFailure::CorruptState)?))
    }
    async fn publish_generation(
        &self,
        version: Option<ObjectVersion>,
        generation: &Generation,
    ) -> Result<(), RepositoryFailure> {
        self.cache_memory.fetch_max(
            generation.retained_memory_bytes()?,
            std::sync::atomic::Ordering::Relaxed,
        );
        self.ensure_control_memory(generation.encoded_length()?, 0)?;
        // Admission includes the retained candidate before cloning. Replace the
        // prior cache before allocating, so repeated CAS never stacks caches.
        drop(
            self.successor
                .lock()
                .map_err(|_| RepositoryFailure::CorruptState)?
                .take(),
        );
        let candidate = generation.clone();
        let object = ImmutableObject::new(generation.signed_bytes(self.signer)?)?;
        let id = object.id();
        self.repository.put_if_absent(object).await?;
        let mut head = b"POSBKH01".to_vec();
        head.extend_from_slice(&id.checksum());
        let head = super::codec::sign(head, self.signer)?;
        let head_version = ObjectVersion::from_checksum(Sha256::digest(&head).into());
        let outcome = match self
            .repository
            .compare_and_swap_head_at(
                HeadSlot::registry(),
                RegistryHeadChange::new(version, head.clone())?,
            )
            .await
        {
            Ok(CasOutcome::Published(version)) if version == head_version => Ok(()),
            Ok(CasOutcome::Published(_)) => Err(RepositoryFailure::CorruptState),
            Ok(CasOutcome::Conflict(_)) => {
                if self
                    .repository
                    .registry_head_at(HeadSlot::registry())
                    .await?
                    .is_some_and(|actual| actual.bytes() == head)
                {
                    Ok(())
                } else {
                    Err(RepositoryFailure::PreconditionFailed)
                }
            },
            Err(RepositoryFailure::OutcomeUnknown) => {
                if self
                    .repository
                    .registry_head_at(HeadSlot::registry())
                    .await?
                    .is_some_and(|actual| actual.bytes() == head)
                {
                    Ok(())
                } else {
                    Err(RepositoryFailure::OutcomeUnknown)
                }
            },
            Err(failure) => Err(failure),
        };
        outcome?;
        self.retain_successor(
            VerifiedHead {
                version: head_version,
                generation: id.checksum(),
            },
            candidate,
        )
    }

    async fn current(
        &self,
    ) -> Result<(Option<ObjectVersion>, Option<Generation>, Option<[u8; 32]>), RepositoryFailure>
    {
        let verified = self.verification_head()?;
        let Some((head, id)) = self.read_registry_head().await? else {
            if self.trusted.is_some() || verified.is_some_and(|proof| proof.generation != [0; 32]) {
                return Err(RepositoryFailure::PreconditionFailed);
            }
            return Ok((None, None, None));
        };
        if let Some(proof) = verified {
            if proof.version != head.version() || proof.generation != id {
                return Err(RepositoryFailure::PreconditionFailed);
            }
        } else if self.trusted.is_some_and(|trusted| trusted != id) {
            // Administration advances ancestry through its bounded signed
            // Maintenance cursor. Read-only callers receive a bounded refusal.
            return Err(RepositoryFailure::LimitExceeded);
        }
        let cached = self
            .successor
            .lock()
            .map_err(|_| RepositoryFailure::CorruptState)?
            .take();
        let generation = match cached {
            Some(cached)
                if cached.head.version == head.version() && cached.head.generation == id =>
            {
                cached.generation
            },
            _ => self.read_generation(ObjectId::from_checksum(id)).await?,
        };
        if verified.is_none()
            && self.trusted.is_none()
            && (generation.number != 1 || generation.previous != [0; 32])
        {
            return Err(RepositoryFailure::LimitExceeded);
        }
        if self
            .repository
            .registry_head_at(HeadSlot::registry())
            .await?
            .as_ref()
            != Some(&head)
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        *self
            .known_head
            .lock()
            .map_err(|_| RepositoryFailure::CorruptState)? = Some(VerifiedHead {
            version: head.version(),
            generation: id,
        });
        Ok((Some(head.version()), Some(generation), Some(id)))
    }
}
fn key_references(keys: &[BackupKeyEnvelope]) -> Result<Vec<KeyReference>, RepositoryFailure> {
    if keys.len() > MAX_KEY_ENVELOPES {
        return Err(RepositoryFailure::InvalidInput);
    }
    let mut references = Vec::new();
    references
        .try_reserve_exact(keys.len())
        .map_err(|_| RepositoryFailure::LimitExceeded)?;
    for key in keys {
        references.push(KeyReference {
            context: [0; 32],
            tenant: key.tenant,
            epoch: key.epoch,
            fingerprint: key.fingerprint,
            object: key.object()?.id(),
        });
    }
    references.sort_by_key(|key| (key.tenant, key.epoch, key.object));
    if references.windows(2).any(|pair| {
        pair.first()
            .zip(pair.get(1))
            .is_some_and(|(left, right)| left.tenant == right.tenant && left.epoch == right.epoch)
    }) {
        return Err(RepositoryFailure::InvalidInput);
    }
    let context = context_digest(&references);
    for reference in &mut references {
        reference.context = context;
    }
    Ok(references)
}
fn context_digest(references: &[KeyReference]) -> [u8; 32] {
    key_identity_context(references.iter().map(|key| BackupKeyIdentity {
        tenant: key.tenant,
        epoch: key.epoch,
        fingerprint: key.fingerprint,
    }))
}
fn key_identity_context(keys: impl Iterator<Item = BackupKeyIdentity>) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"positron-backup-key-context-v1\0");
    for key in keys {
        hash.update(key.tenant);
        hash.update(key.epoch.to_be_bytes());
        hash.update(key.fingerprint);
    }
    hash.finalize().into()
}
impl BackupPublisher<'_> {
    async fn read_control_object(&self, id: ObjectId) -> Result<Vec<u8>, RepositoryFailure> {
        super::read::object_bytes(self.repository, id, |size| {
            self.ensure_control_memory(size, 0)
        })
        .await
    }
}
fn allocation_bytes<T>(capacity: usize) -> Result<u64, RepositoryFailure> {
    u64::try_from(capacity)
        .ok()
        .and_then(|n| n.checked_mul(std::mem::size_of::<T>() as u64))
        .ok_or(RepositoryFailure::LimitExceeded)
}
