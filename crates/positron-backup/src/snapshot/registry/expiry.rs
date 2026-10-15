//! Retention shares the signed Registry CAS with publishers and reservations.
mod cancellation;
pub(super) mod codec;
mod completion;
use super::*;
use std::collections::BTreeSet;
pub(super) const MAX_CLAIMED_OBJECTS: usize =
    super::super::MAX_BACKUP_OBJECTS + MAX_KEY_ENVELOPES + MAX_REGISTERED_SNAPSHOTS;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupCleanupReason {
    Retention,
    Cancellation,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DeletionClaim {
    pub(super) owner: [u8; 16],
    pub(super) reason: BackupCleanupReason,
    pub(super) receipt: BackupReceipt,
    pub(super) remaining: Vec<ObjectId>,
    pub(super) deleted: u32,
    pub(super) absent: u32,
    pub(super) shared: u32,
}
/// Volatile reference scan; a crash before the claim CAS simply rescans.
pub struct BackupCleanupPlan {
    head: ObjectVersion,
    owner: [u8; 16],
    receipt: BackupReceipt,
    others: Vec<BackupReceipt>,
    keys: Vec<KeyReference>,
    candidates: Vec<ObjectId>,
    reason: BackupCleanupReason,
    uploads: Vec<BackupObject>,
    next_upload: usize,
    initial: usize,
    next: usize,
    contexts: BTreeSet<[u8; 32]>,
}
impl BackupCleanupPlan {
    pub fn retained_memory_bytes(&self) -> Result<u64, RepositoryFailure> {
        [
            allocation_bytes::<BackupReceipt>(self.others.capacity())?,
            allocation_bytes::<KeyReference>(self.keys.capacity())?,
            allocation_bytes::<ObjectId>(self.candidates.capacity())?,
            allocation_bytes::<BackupObject>(self.uploads.capacity())?,
            allocation_bytes::<[u8; 128]>(self.contexts.len())?,
        ]
        .into_iter()
        .try_fold(0u64, |n, v| {
            n.checked_add(v).ok_or(RepositoryFailure::LimitExceeded)
        })
    }
    pub const fn retain_until(&self) -> u64 {
        self.receipt.retain_until
    }
    pub fn next_upload_reconciliation_bytes(&self) -> Option<u64> {
        self.uploads
            .get(self.next_upload)
            .map(|object| object.length)
    }
    pub fn pending_upload_reconciliations(&self) -> usize {
        self.uploads.len().saturating_sub(self.next_upload)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupCleanupProgress {
    owner: [u8; 16],
    reason: BackupCleanupReason,
    snapshot: [u8; 16],
    manifest: ObjectId,
    registry: [u8; 32],
    remaining: u32,
    deleted: u32,
    absent: u32,
    shared: u32,
}
impl BackupCleanupProgress {
    pub const fn owner(self) -> [u8; 16] {
        self.owner
    }
    pub const fn reason(self) -> BackupCleanupReason {
        self.reason
    }
    pub const fn snapshot_id(self) -> [u8; 16] {
        self.snapshot
    }
    pub const fn manifest(self) -> ObjectId {
        self.manifest
    }
    pub const fn registry_generation(self) -> [u8; 32] {
        self.registry
    }
    pub const fn complete(self) -> bool {
        self.remaining == 0
    }
    pub const fn pending_objects(self) -> u32 {
        self.remaining
    }
    pub const fn deleted_objects(self) -> u32 {
        self.deleted
    }
    pub const fn already_absent_objects(self) -> u32 {
        self.absent
    }
    pub const fn retained_shared_objects(self) -> u32 {
        self.shared
    }
}
impl DeletionClaim {
    fn progress(&self, registry: [u8; 32]) -> BackupCleanupProgress {
        BackupCleanupProgress {
            owner: self.owner,
            reason: self.reason,
            snapshot: self.receipt.snapshot,
            manifest: self.receipt.manifest,
            registry,
            remaining: self.remaining.len() as u32,
            deleted: self.deleted,
            absent: self.absent,
            shared: self.shared,
        }
    }
}
impl BackupPublisher<'_> {
    /// Recover this exact operation's signed cleanup claim without relying on
    /// a local capture sidecar that may already have been removed.
    pub async fn cleanup_for_owner(
        &self,
        owner: [u8; 16],
    ) -> Result<Option<BackupCleanupProgress>, RepositoryFailure> {
        self.require_identity().await?;
        let (head, generation, registry) = self.current().await?;
        let progress = match generation {
            Some(generation) => {
                let registry = registry.ok_or(RepositoryFailure::CorruptState)?;
                generation
                    .claims
                    .iter()
                    .find(|claim| claim.owner == owner)
                    .map(|claim| claim.progress(registry))
            },
            None => None,
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
        Ok(progress)
    }
    pub async fn prepare_expiry(
        &self,
        owner: [u8; 16],
        snapshot: [u8; 16],
        expected_manifest: [u8; 32],
    ) -> Result<BackupCleanupPlan, RepositoryFailure> {
        self.prepare_cleanup(
            owner,
            snapshot,
            expected_manifest,
            BackupCleanupReason::Retention,
        )
        .await
    }
    async fn prepare_cleanup(
        &self,
        owner: [u8; 16],
        snapshot: [u8; 16],
        expected_manifest: [u8; 32],
        reason: BackupCleanupReason,
    ) -> Result<BackupCleanupPlan, RepositoryFailure> {
        self.require_identity().await?;
        if owner == [0; 16] || snapshot == [0; 16] || expected_manifest == [0; 32] {
            return Err(RepositoryFailure::InvalidInput);
        }
        let (head, generation, _) = self.current().await?;
        let generation = generation.ok_or(RepositoryFailure::NotFound)?;
        let entries = match reason {
            BackupCleanupReason::Retention => &generation.snapshots,
            BackupCleanupReason::Cancellation => &generation.reservations,
        };
        let receipt = entries
            .iter()
            .find(|receipt| receipt.snapshot == snapshot)
            .copied()
            .ok_or(if reason == BackupCleanupReason::Cancellation {
                RepositoryFailure::PreconditionFailed
            } else {
                RepositoryFailure::NotFound
            })?;
        if receipt.manifest.checksum() != expected_manifest {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        let manifest = self.read_registered_manifest(receipt).await?;
        let mut candidates = Vec::new();
        candidates
            .try_reserve_exact(
                manifest
                    .objects
                    .len()
                    .checked_add(generation.keys.len() + 1)
                    .ok_or(RepositoryFailure::LimitExceeded)?,
            )
            .map_err(|_| RepositoryFailure::LimitExceeded)?;
        candidates.extend(manifest.objects.iter().map(|object| object.object()));
        candidates.push(receipt.manifest);
        for key in &generation.keys {
            if key.context == manifest.key_context {
                candidates.push(key.object);
            }
        }
        candidates.sort_unstable();
        candidates.dedup();
        if candidates.len() > MAX_CLAIMED_OBJECTS {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let initial = candidates.len();
        let others = generation
            .snapshots
            .into_iter()
            .chain(generation.reservations)
            .filter(|item| item.snapshot != snapshot)
            .collect();
        let uploads = if reason == BackupCleanupReason::Cancellation {
            manifest.objects
        } else {
            Vec::new()
        };
        Ok(BackupCleanupPlan {
            reason,
            uploads,
            next_upload: 0,
            head: head.ok_or(RepositoryFailure::CorruptState)?,
            owner,
            receipt,
            others,
            keys: generation.keys,
            candidates,
            initial,
            next: 0,
            contexts: BTreeSet::new(),
        })
    }
    /// Scans one signed manifest under the same exact authoritative head.
    pub async fn scan_expiry_step(
        &self,
        plan: &mut BackupCleanupPlan,
    ) -> Result<bool, RepositoryFailure> {
        self.ensure_control_memory(0, plan.retained_memory_bytes()?)?;
        self.require_head(plan.head).await?;
        if let Some(receipt) = plan.others.get(plan.next).copied() {
            let manifest = self.read_registered_manifest(receipt).await?;
            let mut referenced = Vec::new();
            referenced
                .try_reserve_exact(
                    manifest
                        .objects
                        .len()
                        .checked_add(plan.keys.len() + 1)
                        .ok_or(RepositoryFailure::LimitExceeded)?,
                )
                .map_err(|_| RepositoryFailure::LimitExceeded)?;
            referenced.push(receipt.manifest);
            referenced.extend(manifest.objects.iter().map(|object| object.object()));
            for key in &plan.keys {
                if key.context == manifest.key_context {
                    referenced.push(key.object);
                }
            }
            referenced.sort_unstable();
            referenced.dedup();
            plan.candidates
                .retain(|object| referenced.binary_search(object).is_err());
            plan.contexts.insert(manifest.key_context);
            plan.next += 1;
        }
        self.require_head(plan.head).await?;
        Ok(plan.next == plan.others.len())
    }
    /// The destructive deadline comes exclusively from Kernel's existing
    /// trusted lifecycle clock, immediately before the signed unpublish CAS.
    pub async fn claim_expiry(
        &self,
        plan: &BackupCleanupPlan,
        clock: &positron_kernel::RetentionTimeAuthority,
    ) -> Result<BackupCleanupProgress, RepositoryFailure> {
        if plan.reason != BackupCleanupReason::Retention {
            return Err(RepositoryFailure::InvalidInput);
        }
        let now = clock
            .destructive_governance_now_seconds()
            .map_err(|_| RepositoryFailure::PreconditionFailed)?;
        if now < plan.receipt.retain_until {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        self.claim_cleanup(plan).await
    }
    async fn claim_cleanup(
        &self,
        plan: &BackupCleanupPlan,
    ) -> Result<BackupCleanupProgress, RepositoryFailure> {
        self.ensure_control_memory(0, plan.retained_memory_bytes()?)?;
        if plan.next != plan.others.len() || plan.next_upload != plan.uploads.len() {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        let (version, generation, previous) = self.current().await?;
        if version != Some(plan.head) {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        let mut generation = generation.ok_or(RepositoryFailure::NotFound)?;
        let entries = match plan.reason {
            BackupCleanupReason::Retention => &generation.snapshots,
            BackupCleanupReason::Cancellation => &generation.reservations,
        };
        if !entries.contains(&plan.receipt)
            || generation.claims.iter().any(|claim| {
                claim.owner == plan.owner || claim.receipt.snapshot == plan.receipt.snapshot
            })
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        let claimed =
            generation
                .claims
                .iter()
                .try_fold(plan.candidates.len(), |count, claim| {
                    count
                        .checked_add(claim.remaining.len())
                        .ok_or(RepositoryFailure::LimitExceeded)
                })?;
        if claimed > MAX_CLAIMED_OBJECTS {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let shared = u32::try_from(
            plan.initial
                .checked_sub(plan.candidates.len())
                .ok_or(RepositoryFailure::CorruptState)?,
        )
        .map_err(|_| RepositoryFailure::LimitExceeded)?;
        let claim = DeletionClaim {
            owner: plan.owner,
            reason: plan.reason,
            receipt: plan.receipt,
            remaining: plan.candidates.clone(),
            deleted: 0,
            absent: 0,
            shared,
        };
        match plan.reason {
            BackupCleanupReason::Retention => generation
                .snapshots
                .retain(|receipt| *receipt != plan.receipt),
            BackupCleanupReason::Cancellation => generation
                .reservations
                .retain(|receipt| *receipt != plan.receipt),
        }
        generation
            .keys
            .retain(|key| plan.contexts.contains(&key.context));
        generation.claims.push(claim);
        generation.claims.sort_by_key(|claim| claim.owner);
        generation.number = generation
            .number
            .checked_add(1)
            .ok_or(RepositoryFailure::LimitExceeded)?;
        generation.previous = previous.ok_or(RepositoryFailure::CorruptState)?;
        self.publish_generation(version, &generation).await?;
        self.expiry_progress(plan.owner, plan.receipt.manifest.checksum())
            .await
    }
    pub async fn expiry_progress(
        &self,
        owner: [u8; 16],
        manifest: [u8; 32],
    ) -> Result<BackupCleanupProgress, RepositoryFailure> {
        self.require_identity().await?;
        let (_, generation, registry) = self.current().await?;
        let generation = generation.ok_or(RepositoryFailure::NotFound)?;
        let claim = generation
            .claims
            .iter()
            .find(|claim| claim.owner == owner && claim.receipt.manifest.checksum() == manifest)
            .ok_or(RepositoryFailure::NotFound)?;
        Ok(claim.progress(registry.ok_or(RepositoryFailure::CorruptState)?))
    }
    /// One provider delete and one exact Registry CAS. Ambiguous or denied
    /// deletion retains the signed claim and never reports the object deleted.
    pub async fn delete_expired_step(
        &self,
        owner: [u8; 16],
        manifest: [u8; 32],
    ) -> Result<BackupCleanupProgress, RepositoryFailure> {
        self.require_identity().await?;
        let (version, generation, previous) = self.current().await?;
        let mut generation = generation.ok_or(RepositoryFailure::NotFound)?;
        let claim = generation
            .claims
            .iter_mut()
            .find(|claim| claim.owner == owner && claim.receipt.manifest.checksum() == manifest)
            .ok_or(RepositoryFailure::NotFound)?;
        let Some(object) = claim.remaining.first().copied() else {
            return Ok(claim.progress(previous.ok_or(RepositoryFailure::CorruptState)?));
        };
        match self.repository.delete(object).await? {
            crate::DeleteOutcome::Deleted => {
                claim.deleted = claim
                    .deleted
                    .checked_add(1)
                    .ok_or(RepositoryFailure::LimitExceeded)?
            },
            crate::DeleteOutcome::AlreadyAbsent => {
                claim.absent = claim
                    .absent
                    .checked_add(1)
                    .ok_or(RepositoryFailure::LimitExceeded)?
            },
        }
        claim.remaining.remove(0);
        generation.number = generation
            .number
            .checked_add(1)
            .ok_or(RepositoryFailure::LimitExceeded)?;
        generation.previous = previous.ok_or(RepositoryFailure::CorruptState)?;
        self.publish_generation(version, &generation).await?;
        self.expiry_progress(owner, manifest).await
    }
    /// Called only after the durable terminal receipt/audit/anchor transaction.
    /// Empty claims contain no blocked IDs; acknowledgement removes metadata.
    pub async fn acknowledge_expiry(
        &self,
        owner: [u8; 16],
        manifest: [u8; 32],
    ) -> Result<(), RepositoryFailure> {
        self.require_identity().await?;
        let (version, generation, previous) = self.current().await?;
        let mut generation = generation.ok_or(RepositoryFailure::NotFound)?;
        let Some(claim) = generation.claims.iter().find(|claim| claim.owner == owner) else {
            return Ok(());
        };
        if claim.receipt.manifest.checksum() != manifest || !claim.remaining.is_empty() {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        generation.claims.retain(|claim| claim.owner != owner);
        generation.number = generation
            .number
            .checked_add(1)
            .ok_or(RepositoryFailure::LimitExceeded)?;
        generation.previous = previous.ok_or(RepositoryFailure::CorruptState)?;
        self.publish_generation(version, &generation).await
    }
    async fn read_registered_manifest(
        &self,
        receipt: BackupReceipt,
    ) -> Result<BackupManifest, RepositoryFailure> {
        let bytes = self.read_control_object(receipt.manifest).await?;
        let manifest = BackupManifest::verify(&bytes, self.identity, self.signer.identity())?;
        if manifest.snapshot != receipt.snapshot
            || manifest.created != receipt.created
            || manifest.retain_until != receipt.retain_until
        {
            return Err(RepositoryFailure::CorruptState);
        }
        Ok(manifest)
    }
    async fn require_head(&self, version: ObjectVersion) -> Result<(), RepositoryFailure> {
        self.ensure_control_memory(0, 0)?;
        if self
            .repository
            .registry_head_at(HeadSlot::registry())
            .await?
            .map(|head| head.version())
            != Some(version)
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        Ok(())
    }
}
