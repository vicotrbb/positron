//! Signed ancestry progress fits the existing authenticated Maintenance checkpoint.
use super::*;
use std::sync::Mutex;
// Signed fixed header + largest retained record kind + all bounded key and
// remaining-object records. Even this conservative combination fits one range.
pub(super) const MAX_GENERATION_BYTES: u64 = 236
    + MAX_REGISTERED_SNAPSHOTS as u64 * 97
    + MAX_KEY_ENVELOPES as u64 * 120
    + expiry::MAX_CLAIMED_OBJECTS as u64 * 32;
const MAX_CURSOR_BYTES: usize = 512;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Walk,
    Recheck,
    Complete,
}
#[derive(Clone, Copy, Debug)]
struct Cursor {
    repository: [u8; 32],
    owner: [u8; 16],
    request: [u8; 32],
    authority: [u8; 32],
    anchor: [u8; 32],
    head: [u8; 32],
    target: [u8; 32],
    next: [u8; 32],
    expected: u64,
    number: u64,
    count: u32,
    stage: Stage,
}
/// Opaque fixed-size proof. No provider capability or control body is serialized.
/// Successful exact CAS updates this same proof before its next checkpoint.
#[derive(Debug)]
pub struct BackupRegistryVerification {
    cursor: Mutex<Cursor>,
}
impl BackupRegistryVerification {
    pub fn complete(&self) -> Result<bool, RepositoryFailure> {
        Ok(self.get()?.stage == Stage::Complete)
    }
    pub const fn retained_memory_bytes(&self) -> u64 {
        0
    }
    fn get(&self) -> Result<Cursor, RepositoryFailure> {
        self.cursor
            .lock()
            .map(|value| *value)
            .map_err(|_| RepositoryFailure::CorruptState)
    }
    fn set(&self, value: Cursor) -> Result<(), RepositoryFailure> {
        *self
            .cursor
            .lock()
            .map_err(|_| RepositoryFailure::CorruptState)? = value;
        Ok(())
    }
}
#[derive(Clone, Copy)]
pub(super) struct VerifiedHead {
    pub(super) version: ObjectVersion,
    pub(super) generation: [u8; 32],
}
pub(super) struct CachedGeneration {
    pub(super) head: VerifiedHead,
    pub(super) generation: Generation,
}
impl<'a> BackupPublisher<'a> {
    fn cursor_binding(&self, cursor: Cursor) -> Result<(), RepositoryFailure> {
        self.ensure_control_memory(0, 0)?;
        let repository: [u8; 32] = Sha256::digest(self.identity.encode()).into();
        if cursor.repository != repository
            || self.signer.identity().fingerprint() != self.identity.integrity_fingerprint()
        {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        if cursor.authority != self.trusted.unwrap_or([0; 32]) {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        Ok(())
    }
    pub async fn begin_registry_verification(
        &self,
        owner: [u8; 16],
        request: [u8; 32],
    ) -> Result<BackupRegistryVerification, RepositoryFailure> {
        if owner == [0; 16] || request == [0; 32] {
            return Err(RepositoryFailure::InvalidInput);
        }
        self.require_identity().await?;
        let head = self.read_registry_head().await?;
        if head.is_none() && self.trusted.is_some() {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        let (version, target) = head
            .map(|(head, id)| (head.version().checksum(), id))
            .unwrap_or(([0; 32], [0; 32]));
        Ok(BackupRegistryVerification {
            cursor: Mutex::new(Cursor {
                repository: Sha256::digest(self.identity.encode()).into(),
                owner,
                request,
                authority: self.trusted.unwrap_or([0; 32]),
                anchor: self.trusted.unwrap_or([0; 32]),
                head: version,
                target,
                next: target,
                expected: 0,
                number: 0,
                count: 0,
                stage: if target == [0; 32] {
                    Stage::Complete
                } else {
                    Stage::Walk
                },
            }),
        })
    }
    /// One generation body at most. Rechecking the small head is a separate
    /// turn, so native metadata/identity replies plus the frame stay bounded.
    pub async fn registry_verification_step(
        &self,
        state: &mut BackupRegistryVerification,
    ) -> Result<bool, RepositoryFailure> {
        let mut cursor = state.get()?;
        self.cursor_binding(cursor)?;
        if cursor.stage == Stage::Walk {
            let generation = self
                .read_generation(ObjectId::from_checksum(cursor.next))
                .await?;
            if cursor.expected != 0 && generation.number != cursor.expected {
                return Err(RepositoryFailure::CorruptState);
            }
            cursor.count = cursor
                .count
                .checked_add(1)
                .filter(|count| *count <= MAX_REGISTRY_GENERATIONS as u32)
                .ok_or(RepositoryFailure::LimitExceeded)?;
            if cursor.number == 0 {
                cursor.number = generation.number;
            }
            let reached = cursor.anchor != [0; 32] && cursor.next == cursor.anchor;
            if reached || generation.number == 1 {
                if generation.number == 1 && generation.previous != [0; 32] {
                    return Err(RepositoryFailure::CorruptState);
                }
                if !reached && cursor.anchor != [0; 32] {
                    return Err(RepositoryFailure::PreconditionFailed);
                }
                cursor.anchor = cursor.target;
                cursor.next = [0; 32];
                cursor.expected = 0;
                cursor.stage = Stage::Recheck;
            } else {
                if generation.previous == [0; 32] {
                    return Err(RepositoryFailure::CorruptState);
                }
                cursor.next = generation.previous;
                cursor.expected = generation
                    .number
                    .checked_sub(1)
                    .filter(|number| *number != 0)
                    .ok_or(RepositoryFailure::CorruptState)?;
            }
            state.set(cursor)?;
            return Ok(false);
        }
        let current = self.read_registry_head().await?;
        let (head, target) = current
            .map(|(head, id)| (head.version().checksum(), id))
            .unwrap_or(([0; 32], [0; 32]));
        if head == cursor.head && target == cursor.target {
            cursor.stage = Stage::Complete;
            state.set(cursor)?;
            return Ok(true);
        }
        if target == [0; 32] {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        // The fully proven prior target remains a transitive local anchor even
        // when another writer advances the head during our final recheck.
        cursor.head = head;
        cursor.target = target;
        cursor.next = target;
        cursor.expected = 0;
        cursor.number = 0;
        cursor.count = 0;
        cursor.stage = Stage::Walk;
        state.set(cursor)?;
        Ok(false)
    }
    pub fn registry_verification_checkpoint(
        &self,
        state: &BackupRegistryVerification,
    ) -> Result<Vec<u8>, RepositoryFailure> {
        let cursor = state.get()?;
        self.cursor_binding(cursor)?;
        let mut bytes = b"POSBVR01".to_vec();
        bytes.extend_from_slice(&cursor.repository);
        bytes.extend_from_slice(&cursor.owner);
        bytes.extend_from_slice(&cursor.request);
        for value in [
            cursor.authority,
            cursor.anchor,
            cursor.head,
            cursor.target,
            cursor.next,
        ] {
            bytes.extend_from_slice(&value);
        }
        bytes.extend_from_slice(&cursor.expected.to_be_bytes());
        bytes.extend_from_slice(&cursor.number.to_be_bytes());
        bytes.extend_from_slice(&cursor.count.to_be_bytes());
        bytes.push(match cursor.stage {
            Stage::Walk => 1,
            Stage::Recheck => 2,
            Stage::Complete => 3,
        });
        super::super::codec::sign(bytes, self.signer)
    }
    pub fn resume_registry_verification(
        &self,
        bytes: &[u8],
        owner: [u8; 16],
        request: [u8; 32],
    ) -> Result<BackupRegistryVerification, RepositoryFailure> {
        self.ensure_control_memory(0, 0)?;
        if bytes.len() > MAX_CURSOR_BYTES || owner == [0; 16] || request == [0; 32] {
            return Err(RepositoryFailure::InvalidInput);
        }
        let mut decoder = super::super::codec::Decoder::new(super::super::codec::verify(
            bytes,
            self.signer.identity(),
        )?);
        if decoder.take(8)? != b"POSBVR01" {
            return Err(RepositoryFailure::CorruptState);
        }
        let cursor = Cursor {
            repository: decoder.array()?,
            owner: decoder.array()?,
            request: decoder.array()?,
            authority: decoder.array()?,
            anchor: decoder.array()?,
            head: decoder.array()?,
            target: decoder.array()?,
            next: decoder.array()?,
            expected: decoder.u64()?,
            number: decoder.u64()?,
            count: decoder.u32()?,
            stage: match decoder.take(1)? {
                [1] => Stage::Walk,
                [2] => Stage::Recheck,
                [3] => Stage::Complete,
                _ => return Err(RepositoryFailure::CorruptState),
            },
        };
        decoder.finish()?;
        if cursor.owner != owner || cursor.request != request {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        self.cursor_binding(cursor)?;
        let empty = cursor.target == [0; 32];
        let shape = if empty {
            cursor.head == [0; 32]
                && cursor.authority == [0; 32]
                && cursor.anchor == [0; 32]
                && cursor.next == [0; 32]
                && cursor.expected == 0
                && cursor.number == 0
                && cursor.count == 0
                && cursor.stage == Stage::Complete
        } else if cursor.head == [0; 32] {
            false
        } else if cursor.stage == Stage::Walk {
            cursor.next != [0; 32]
                && if cursor.count == 0 {
                    cursor.next == cursor.target && cursor.expected == 0 && cursor.number == 0
                } else {
                    cursor.expected != 0
                        && cursor.number.checked_sub(u64::from(cursor.count))
                            == Some(cursor.expected)
                }
        } else {
            cursor.anchor == cursor.target
                && cursor.next == [0; 32]
                && cursor.expected == 0
                && cursor.number != 0
        };
        if !shape || cursor.count > MAX_REGISTRY_GENERATIONS as u32 {
            return Err(RepositoryFailure::CorruptState);
        }
        Ok(BackupRegistryVerification {
            cursor: Mutex::new(cursor),
        })
    }
    pub fn with_registry_verification(
        mut self,
        state: &'a BackupRegistryVerification,
    ) -> Result<Self, RepositoryFailure> {
        let cursor = state.get()?;
        self.cursor_binding(cursor)?;
        if cursor.stage != Stage::Complete {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        self.verification = Some(state);
        Ok(self)
    }
    pub(super) fn verification_head(&self) -> Result<Option<VerifiedHead>, RepositoryFailure> {
        if let Some(state) = self.verification {
            let cursor = state.get()?;
            self.cursor_binding(cursor)?;
            if cursor.stage != Stage::Complete {
                return Err(RepositoryFailure::PreconditionFailed);
            }
            return Ok(Some(VerifiedHead {
                version: ObjectVersion::from_checksum(cursor.head),
                generation: cursor.target,
            }));
        }
        self.known_head
            .lock()
            .map(|head| *head)
            .map_err(|_| RepositoryFailure::CorruptState)
    }
    pub(super) async fn read_registry_head(
        &self,
    ) -> Result<Option<(crate::RegistryHead, [u8; 32])>, RepositoryFailure> {
        self.ensure_control_memory(0, 0)?;
        let Some(head) = self
            .repository
            .registry_head_at(HeadSlot::registry())
            .await?
        else {
            return Ok(None);
        };
        let mut decoder = super::super::codec::Decoder::new(super::super::codec::verify(
            head.bytes(),
            self.signer.identity(),
        )?);
        if decoder.take(8)? != b"POSBKH01" {
            return Err(RepositoryFailure::CorruptState);
        }
        let id = decoder.array()?;
        decoder.finish()?;
        if id == [0; 32] {
            return Err(RepositoryFailure::CorruptState);
        }
        Ok(Some((head, id)))
    }
    pub(super) async fn read_generation(
        &self,
        id: ObjectId,
    ) -> Result<Generation, RepositoryFailure> {
        self.ensure_control_memory(0, 0)?;
        let size = self.repository.object_size_hint(id).await?;
        if !(236..=MAX_GENERATION_BYTES).contains(&size) {
            return Err(RepositoryFailure::LimitExceeded);
        }
        self.ensure_control_memory(size, 0)?;
        let part = self
            .repository
            .read_range(ObjectRange::new(id, 0, size)?.with_expected_size(size)?)
            .await?;
        if part.bytes().len() as u64 != size {
            return Err(RepositoryFailure::CorruptState);
        }
        if <[u8; 32]>::from(Sha256::digest(part.bytes())) != id.checksum() {
            return Err(RepositoryFailure::ChecksumMismatch);
        }
        let generation = Generation::verify(part.bytes(), self.identity, self.signer.identity())?;
        if (generation.number == 1) != (generation.previous == [0; 32]) {
            return Err(RepositoryFailure::CorruptState);
        }
        Ok(generation)
    }
    pub(super) fn retain_successor(
        &self,
        head: VerifiedHead,
        generation: Generation,
    ) -> Result<(), RepositoryFailure> {
        if let Some(state) = self.verification {
            let mut cursor = state.get()?;
            self.cursor_binding(cursor)?;
            if cursor.stage != Stage::Complete || generation.previous != cursor.target {
                return Err(RepositoryFailure::PreconditionFailed);
            }
            cursor.anchor = head.generation;
            cursor.target = head.generation;
            cursor.head = head.version.checksum();
            cursor.next = [0; 32];
            cursor.expected = 0;
            cursor.number = generation.number;
            cursor.count = 0;
            state.set(cursor)?;
        }
        *self
            .known_head
            .lock()
            .map_err(|_| RepositoryFailure::CorruptState)? = Some(head);
        *self
            .successor
            .lock()
            .map_err(|_| RepositoryFailure::CorruptState)? =
            Some(CachedGeneration { head, generation });
        Ok(())
    }
}
impl Generation {
    pub(super) fn retained_memory_bytes(&self) -> Result<u64, RepositoryFailure> {
        let fixed = [
            allocation_bytes::<BackupReceipt>(self.snapshots.capacity())?,
            allocation_bytes::<BackupReceipt>(self.reservations.capacity())?,
            allocation_bytes::<KeyReference>(self.keys.capacity())?,
            allocation_bytes::<DeletionClaim>(self.claims.capacity())?,
        ]
        .into_iter()
        .try_fold(0u64, |n, v| {
            n.checked_add(v).ok_or(RepositoryFailure::LimitExceeded)
        })?;
        self.claims.iter().try_fold(fixed, |n, claim| {
            n.checked_add(allocation_bytes::<ObjectId>(claim.remaining.capacity())?)
                .ok_or(RepositoryFailure::LimitExceeded)
        })
    }
}
