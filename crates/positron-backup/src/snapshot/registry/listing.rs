use super::*;
/// Pagination is bound to one exact authenticated Registry Generation. A
/// concurrent change requires starting over rather than silently omitting data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupListCursor {
    repository: [u8; 32],
    generation: [u8; 32],
    after: [u8; 16],
}
impl BackupListCursor {
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = b"POSBLS01".to_vec();
        bytes.extend_from_slice(&self.repository);
        bytes.extend_from_slice(&self.generation);
        bytes.extend_from_slice(&self.after);
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, RepositoryFailure> {
        let mut decoder = super::super::codec::Decoder::new(bytes);
        if decoder.take(8)? != b"POSBLS01" {
            return Err(RepositoryFailure::InvalidInput);
        }
        let value = Self {
            repository: decoder.array()?,
            generation: decoder.array()?,
            after: decoder.array()?,
        };
        decoder.finish()?;
        if value.repository == [0; 32] || value.generation == [0; 32] || value.after == [0; 16] {
            return Err(RepositoryFailure::InvalidInput);
        }
        Ok(value)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupSnapshotPage {
    generation: Option<[u8; 32]>,
    snapshots: Vec<BackupReceipt>,
    next: Option<BackupListCursor>,
}
impl BackupSnapshotPage {
    pub const fn registry_generation(&self) -> Option<[u8; 32]> {
        self.generation
    }
    pub fn snapshots(&self) -> &[BackupReceipt] {
        &self.snapshots
    }
    pub const fn next_cursor(&self) -> Option<BackupListCursor> {
        self.next
    }
}
impl BackupPublisher<'_> {
    /// Reads published entries exclusively from the signed Registry, never an
    /// advisory provider object listing or in-flight candidate reservations.
    pub async fn list(
        &self,
        cursor: Option<BackupListCursor>,
        limit: usize,
    ) -> Result<BackupSnapshotPage, RepositoryFailure> {
        if !(1..=128).contains(&limit) {
            return Err(RepositoryFailure::InvalidInput);
        }
        self.require_identity().await?;
        let (head, generation, id) = self.current().await?;
        let repository: [u8; 32] = Sha256::digest(self.identity.encode()).into();
        if cursor
            .is_some_and(|cursor| cursor.repository != repository || Some(cursor.generation) != id)
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        let Some(generation) = generation else {
            return Ok(BackupSnapshotPage {
                generation: None,
                snapshots: Vec::new(),
                next: None,
            });
        };
        if cursor.is_some_and(|cursor| {
            !generation
                .snapshots
                .iter()
                .any(|entry| entry.snapshot == cursor.after)
        }) {
            return Err(RepositoryFailure::InvalidInput);
        }
        let mut entries = generation
            .snapshots
            .into_iter()
            .filter(|entry| cursor.is_none_or(|cursor| entry.snapshot > cursor.after));
        let snapshots = entries.by_ref().take(limit).collect::<Vec<_>>();
        let next = if entries.next().is_some() {
            Some(BackupListCursor {
                repository,
                generation: id.ok_or(RepositoryFailure::CorruptState)?,
                after: snapshots
                    .last()
                    .ok_or(RepositoryFailure::CorruptState)?
                    .snapshot,
            })
        } else {
            None
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
        Ok(BackupSnapshotPage {
            generation: id,
            snapshots,
            next,
        })
    }
}
