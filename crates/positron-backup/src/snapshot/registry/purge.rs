//! Bounded, signed tenant-envelope deletion progress in the existing checkpoint.
use super::*;
const MAX_CHECKPOINT: usize = 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Tombstone,
    PublishTombstone,
    Remove,
    PublishRemoval,
    Walk,
    Recheck,
    Complete,
}
/// Opaque continuation. Only `complete` proves the entire reachable ancestry was
/// processed; a published tombstone or advanced head alone is not completion.
#[derive(Clone, Debug)]
pub struct BackupTenantPurge {
    repository: [u8; 32],
    authority: [u8; 32],
    owner: [u8; 16],
    request: [u8; 32],
    tombstone: BackupPurgeTombstone,
    initial: [u8; 32],
    head: [u8; 32],
    version: [u8; 32],
    number: u64,
    intent: [u8; 32],
    intent_number: u64,
    next: [u8; 32],
    expected: u64,
    key: u32,
    phase: Phase,
}
impl BackupTenantPurge {
    pub const MAX_CHECKPOINT_BYTES: usize = MAX_CHECKPOINT;
    pub fn complete(&self) -> bool {
        self.phase == Phase::Complete
    }
    /// Current authenticated head, including while deletion remains pending.
    pub fn registry_generation(&self) -> Option<[u8; 32]> {
        (self.head != [0; 32]).then_some(self.head)
    }
}
impl BackupPublisher<'_> {
    fn bind_purge(&self, state: &BackupTenantPurge) -> Result<(), RepositoryFailure> {
        if self.signer.identity().fingerprint() != self.identity.integrity_fingerprint() {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        if state.repository != <[u8; 32]>::from(Sha256::digest(self.identity.encode()))
            || state.authority != self.trusted.unwrap_or([0; 32])
            || state.owner == [0; 16]
            || state.request == [0; 32]
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        self.require_purge_shape(state)
    }
    fn require_purge_shape(&self, state: &BackupTenantPurge) -> Result<(), RepositoryFailure> {
        let publishing = matches!(state.phase, Phase::PublishTombstone | Phase::PublishRemoval);
        if (state.head == [0; 32]) != (state.version == [0; 32])
            || (state.head == [0; 32]) != (state.number == 0)
            || publishing != (state.intent != [0; 32] && state.intent_number > 0)
            || !publishing && (state.intent != [0; 32] || state.intent_number != 0)
            || !matches!(state.phase, Phase::Tombstone | Phase::PublishTombstone)
                && state.head == [0; 32]
            || publishing && state.number.checked_add(1) != Some(state.intent_number)
            || state.phase == Phase::Walk && state.expected > state.number
            || state.key as usize > MAX_KEY_ENVELOPES
            || state.phase == Phase::Walk && (state.next == [0; 32] || state.expected == 0)
            || state.phase != Phase::Walk
                && (state.next != [0; 32] || state.expected != 0 || state.key != 0)
        {
            return Err(RepositoryFailure::CorruptState);
        }
        Ok(())
    }
    pub async fn begin_tenant_purge(
        &self,
        tombstone: &BackupPurgeTombstone,
        owner: [u8; 16],
        request: [u8; 32],
    ) -> Result<BackupTenantPurge, RepositoryFailure> {
        self.require_identity().await?;
        let (version, generation, head) = self.current().await?;
        let state = BackupTenantPurge {
            repository: Sha256::digest(self.identity.encode()).into(),
            authority: self.trusted.unwrap_or([0; 32]),
            owner,
            request,
            tombstone: tombstone.clone(),
            initial: head.unwrap_or([0; 32]),
            head: head.unwrap_or([0; 32]),
            version: version.map_or([0; 32], ObjectVersion::checksum),
            number: generation.map_or(0, |g| g.number),
            intent: [0; 32],
            intent_number: 0,
            next: [0; 32],
            expected: 0,
            key: 0,
            phase: Phase::Tombstone,
        };
        self.bind_purge(&state)?;
        Ok(state)
    }
    pub fn tenant_purge_checkpoint(
        &self,
        state: &BackupTenantPurge,
    ) -> Result<Vec<u8>, RepositoryFailure> {
        self.bind_purge(state)?;
        let mut bytes = b"POSBPG01".to_vec();
        for value in [state.repository, state.authority] {
            bytes.extend_from_slice(&value);
        }
        bytes.extend_from_slice(&state.owner);
        bytes.extend_from_slice(&state.request);
        bytes.extend_from_slice(&state.tombstone.tenant());
        bytes.extend_from_slice(&state.tombstone.operation());
        bytes.extend_from_slice(&state.tombstone.created_at().to_be_bytes());
        bytes.push(state.tombstone.slug().len() as u8);
        bytes.extend_from_slice(state.tombstone.slug().as_bytes());
        for value in [
            state.initial,
            state.head,
            state.version,
            state.intent,
            state.next,
        ] {
            bytes.extend_from_slice(&value);
        }
        for value in [state.number, state.intent_number, state.expected] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.extend_from_slice(&state.key.to_be_bytes());
        bytes.push(match state.phase {
            Phase::Tombstone => 0,
            Phase::PublishTombstone => 1,
            Phase::Remove => 2,
            Phase::PublishRemoval => 3,
            Phase::Walk => 4,
            Phase::Recheck => 5,
            Phase::Complete => 6,
        });
        super::super::codec::sign(bytes, self.signer)
    }
    pub fn resume_tenant_purge_checkpoint(
        &self,
        bytes: &[u8],
        owner: [u8; 16],
        request: [u8; 32],
    ) -> Result<BackupTenantPurge, RepositoryFailure> {
        if bytes.len() > MAX_CHECKPOINT {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let mut decoder = super::super::codec::Decoder::new(super::super::codec::verify(
            bytes,
            self.signer.identity(),
        )?);
        if decoder.take(8)? != b"POSBPG01" {
            return Err(RepositoryFailure::CorruptState);
        }
        let repository = decoder.array()?;
        let authority = decoder.array()?;
        let found_owner = decoder.array()?;
        let found_request = decoder.array()?;
        let tenant = decoder.array()?;
        let operation = decoder.array()?;
        let created = decoder.u64()?;
        let length = usize::from(
            *decoder
                .take(1)?
                .first()
                .ok_or(RepositoryFailure::CorruptState)?,
        );
        let slug = std::str::from_utf8(decoder.take(length)?)
            .map_err(|_| RepositoryFailure::CorruptState)?;
        let tombstone = BackupPurgeTombstone::new(tenant, slug, operation, created)?;
        let initial = decoder.array()?;
        let head = decoder.array()?;
        let version = decoder.array()?;
        let intent = decoder.array()?;
        let next = decoder.array()?;
        let number = decoder.u64()?;
        let intent_number = decoder.u64()?;
        let expected = decoder.u64()?;
        let key = decoder.u32()?;
        let phase = match decoder.take(1)? {
            [0] => Phase::Tombstone,
            [1] => Phase::PublishTombstone,
            [2] => Phase::Remove,
            [3] => Phase::PublishRemoval,
            [4] => Phase::Walk,
            [5] => Phase::Recheck,
            [6] => Phase::Complete,
            _ => return Err(RepositoryFailure::CorruptState),
        };
        decoder.finish()?;
        if found_owner != owner || found_request != request {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        let state = BackupTenantPurge {
            repository,
            authority,
            owner,
            request,
            tombstone,
            initial,
            head,
            version,
            number,
            intent,
            intent_number,
            next,
            expected,
            key,
            phase,
        };
        self.bind_purge(&state)?;
        Ok(state)
    }
    fn purge_successor(
        &self,
        state: &BackupTenantPurge,
        current: Option<Generation>,
        tombstone: bool,
    ) -> Result<Option<Generation>, RepositoryFailure> {
        let mut generation = current.unwrap_or(Generation {
            number: 0,
            previous: [0; 32],
            repository: self.identity.clone(),
            snapshots: vec![],
            reservations: vec![],
            claims: vec![],
            keys: vec![],
            overlays: vec![],
            tombstones: vec![],
        });
        if generation.number != state.number {
            return Err(RepositoryFailure::CorruptState);
        }
        if tombstone {
            if let Some(existing) = generation.tombstones.iter().find(|t| {
                t.tenant() == state.tombstone.tenant() || t.slug() == state.tombstone.slug()
            }) {
                return if existing == &state.tombstone {
                    Ok(None)
                } else {
                    Err(RepositoryFailure::PreconditionFailed)
                };
            }
            if generation.tombstones.len() >= tombstone::MAX_TOMBSTONES {
                return Err(RepositoryFailure::LimitExceeded);
            }
            generation.tombstones.push(state.tombstone.clone());
            generation
                .tombstones
                .sort_by_key(BackupPurgeTombstone::tenant);
        } else {
            if !generation.tombstones.contains(&state.tombstone) {
                return Err(RepositoryFailure::PreconditionFailed);
            }
            if !generation
                .keys
                .iter()
                .any(|k| k.tenant == state.tombstone.tenant())
            {
                return Ok(None);
            }
            generation
                .keys
                .retain(|k| k.tenant != state.tombstone.tenant());
        }
        generation.previous = state.head;
        generation.number = generation
            .number
            .checked_add(1)
            .ok_or(RepositoryFailure::LimitExceeded)?;
        Ok(Some(generation))
    }
    fn start_purge_walk(state: &mut BackupTenantPurge) {
        state.phase = Phase::Walk;
        state.next = state.head;
        state.expected = state.number;
        state.key = 0;
    }
    /// One phase, at most one signed generation read and one tenant-key deletion.
    /// Persist its signed checkpoint before the next turn. Publication intent is
    /// checkpointed in a separate phase so an interrupted CAS can be reconciled.
    pub async fn tenant_purge_step(
        &self,
        state: &mut BackupTenantPurge,
    ) -> Result<bool, RepositoryFailure> {
        self.require_identity().await?;
        self.bind_purge(state)?;
        let actual = self.read_registry_head().await?;
        let actual_id = actual.as_ref().map_or([0; 32], |(_, id)| *id);
        let actual_version = actual
            .as_ref()
            .map_or([0; 32], |(head, _)| head.version().checksum());
        let publishing = matches!(state.phase, Phase::PublishTombstone | Phase::PublishRemoval);
        let previous = state.head;
        let reconciled = publishing && actual_id == state.intent;
        if reconciled {
            state.head = actual_id;
            state.version = actual_version;
            state.number = state.intent_number;
            state.intent = [0; 32];
            state.intent_number = 0;
            if state.phase == Phase::PublishTombstone {
                state.phase = Phase::Remove;
            } else {
                Self::start_purge_walk(state);
            }
        } else if actual_id != state.head || actual_version != state.version {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        self.adopt_purge_head(
            state.initial,
            previous,
            state.head,
            state.version,
            state.number,
        )?;
        if reconciled {
            return Ok(false);
        }
        match state.phase {
            Phase::Complete => return Ok(true),
            Phase::Recheck => {
                state.phase = Phase::Complete;
                return Ok(true);
            },
            Phase::Walk => {
                let generation = self
                    .read_generation(ObjectId::from_checksum(state.next))
                    .await?;
                if generation.number != state.expected {
                    return Err(RepositoryFailure::CorruptState);
                }
                let next_key = generation
                    .keys
                    .iter()
                    .enumerate()
                    .skip(state.key as usize)
                    .find(|(_, key)| key.tenant == state.tombstone.tenant());
                if let Some((index, key)) = next_key {
                    let fence = TenantKeyPurgeFence::new(
                        key.object,
                        &state.tombstone,
                        self.identity,
                        self.signer,
                    )?;
                    self.repository
                        .delete_tenant_key(key.object, &fence)
                        .await?;
                    state.key =
                        u32::try_from(index + 1).map_err(|_| RepositoryFailure::LimitExceeded)?;
                }
                if !generation
                    .keys
                    .iter()
                    .skip(state.key as usize)
                    .any(|key| key.tenant == state.tombstone.tenant())
                {
                    state.next = generation.previous;
                    state.key = 0;
                    state.expected = state
                        .expected
                        .checked_sub(1)
                        .ok_or(RepositoryFailure::CorruptState)?;
                    if state.next == [0; 32] {
                        state.expected = 0;
                        state.phase = Phase::Recheck;
                    }
                }
            },
            phase => {
                let current = if state.head == [0; 32] {
                    None
                } else {
                    Some(
                        self.read_generation(ObjectId::from_checksum(state.head))
                            .await?,
                    )
                };
                let tombstone = matches!(phase, Phase::Tombstone | Phase::PublishTombstone);
                let successor = self.purge_successor(state, current, tombstone)?;
                if let Some(generation) = successor {
                    self.ensure_control_memory(generation.encoded_length()?, 0)?;
                    let id: [u8; 32] = Sha256::digest(generation.signed_bytes(self.signer)?).into();
                    if publishing {
                        if id != state.intent || generation.number != state.intent_number {
                            return Err(RepositoryFailure::CorruptState);
                        }
                        self.publish_generation(
                            (state.head != [0; 32])
                                .then_some(ObjectVersion::from_checksum(state.version)),
                            &generation,
                        )
                        .await?;
                        let (head, actual) = self
                            .read_registry_head()
                            .await?
                            .ok_or(RepositoryFailure::PreconditionFailed)?;
                        if actual != id {
                            return Err(RepositoryFailure::PreconditionFailed);
                        }
                        state.head = id;
                        state.version = head.version().checksum();
                        state.number = generation.number;
                        state.intent = [0; 32];
                        state.intent_number = 0;
                        if tombstone {
                            state.phase = Phase::Remove;
                        } else {
                            Self::start_purge_walk(state);
                        }
                    } else {
                        state.intent = id;
                        state.intent_number = generation.number;
                        state.phase = if tombstone {
                            Phase::PublishTombstone
                        } else {
                            Phase::PublishRemoval
                        };
                    }
                } else if tombstone {
                    state.phase = Phase::Remove;
                } else {
                    Self::start_purge_walk(state);
                }
            },
        }
        let found = self.read_registry_head().await?;
        if found.as_ref().map_or([0; 32], |(_, id)| *id) != state.head
            || found
                .as_ref()
                .map_or([0; 32], |(head, _)| head.version().checksum())
                != state.version
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        Ok(false)
    }
}
