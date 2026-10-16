//! Initial registration cannot import excluded tenant key material.
use super::*;
impl BackupPublisher<'_> {
    /// Installs all permanent exclusions before an unregistered candidate enters
    /// managed scope. Dirty candidates are refused without deleting their data.
    pub async fn prepare_purge_barrier(
        &self,
        tombstones: &[BackupPurgeTombstone],
    ) -> Result<Option<[u8; 32]>, RepositoryFailure> {
        self.require_identity().await?;
        if tombstones.len() > tombstone::MAX_TOMBSTONES {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let control_bytes = (tombstones.len() as u64)
            .checked_mul(tombstone::MAX_SIGNED_BYTES as u64 + 4)
            .and_then(|bytes| bytes.checked_add(244))
            .ok_or(RepositoryFailure::LimitExceeded)?;
        self.ensure_control_memory(
            control_bytes,
            allocation_bytes::<BackupPurgeTombstone>(tombstones.len())?,
        )?;
        let mut tombstones = tombstones.to_vec();
        tombstones.sort_by_key(BackupPurgeTombstone::tenant);
        if tombstones.windows(2).any(|p| {
            p.first()
                .zip(p.get(1))
                .is_some_and(|(a, b)| a.tenant() == b.tenant() || a.slug() == b.slug())
        }) || tombstones
            .iter()
            .enumerate()
            .any(|(i, a)| tombstones.iter().skip(i + 1).any(|b| a.slug() == b.slug()))
        {
            return Err(RepositoryFailure::InvalidInput);
        }
        let initial = Generation {
            number: 1,
            previous: [0; 32],
            repository: self.identity.clone(),
            snapshots: vec![],
            reservations: vec![],
            claims: vec![],
            keys: vec![],
            overlays: vec![],
            tombstones: tombstones.clone(),
        };
        let candidate = ImmutableObject::new(initial.signed_bytes(self.signer)?)?;
        let current = self.read_registry_head().await?;
        let allowed = vec![candidate.id()];
        let (anchor, head_bytes) = if let Some((head, id)) = &current {
            let verified = self.verification_head()?;
            if verified
                .is_some_and(|proof| proof.version != head.version() || proof.generation != *id)
                || verified.is_none() && self.trusted.is_some_and(|trusted| trusted != *id)
            {
                return Err(RepositoryFailure::PreconditionFailed);
            }
            if *id != candidate.id().checksum() {
                return Err(RepositoryFailure::PreconditionFailed);
            }
            // An unregistered candidate may only retry this exact initial
            // installation. Older control ancestry requires operator remediation.
            let generation = self.read_generation(candidate.id()).await?;
            if generation != initial {
                return Err(RepositoryFailure::PreconditionFailed);
            }
            (Some(*id), head.bytes().to_vec())
        } else {
            let mut bytes = b"POSBKH01".to_vec();
            bytes.extend_from_slice(&candidate.id().checksum());
            (None, super::super::codec::sign(bytes, self.signer)?)
        };
        self.ensure_control_memory(
            initial.encoded_length()?,
            allocation_bytes::<ObjectId>(allowed.capacity())?,
        )?;
        self.repository
            .verify_control_inventory(&allowed, &head_bytes, Some(&candidate))
            .await?;
        if self
            .repository
            .registry_head_at(HeadSlot::registry())
            .await?
            .as_ref()
            != current.as_ref().map(|(head, _)| head)
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        if anchor.is_some() {
            return Ok(anchor);
        }
        if tombstones.is_empty() {
            return Ok(None);
        }
        self.publish_generation(None, &initial).await?;
        let (head, id) = self
            .read_registry_head()
            .await?
            .ok_or(RepositoryFailure::PreconditionFailed)?;
        if id != candidate.id().checksum() || head.bytes() != head_bytes {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        self.repository
            .verify_control_inventory(&allowed, &head_bytes, Some(&candidate))
            .await?;
        if self
            .repository
            .registry_head_at(HeadSlot::registry())
            .await?
            .as_ref()
            != Some(&head)
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        Ok(Some(id))
    }
}
