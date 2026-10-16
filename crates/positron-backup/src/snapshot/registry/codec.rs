use super::*;
impl Generation {
    pub(super) fn encoded_length(&self) -> Result<u64, RepositoryFailure> {
        let records = self
            .snapshots
            .len()
            .checked_add(self.reservations.len())
            .and_then(|n| n.checked_add(self.claims.len()))
            .ok_or(RepositoryFailure::LimitExceeded)?;
        if records > MAX_REGISTERED_SNAPSHOTS
            || self.keys.len() > MAX_KEY_ENVELOPES
            || self.overlays.len() > overlay::MAX_OVERLAYS
        {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let remaining = self.claims.iter().try_fold(0usize, |n, claim| {
            n.checked_add(claim.remaining.len())
                .ok_or(RepositoryFailure::LimitExceeded)
        })?;
        if remaining > expiry::MAX_CLAIMED_OBJECTS {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let entries = self
            .snapshots
            .len()
            .checked_add(self.reservations.len())
            .ok_or(RepositoryFailure::LimitExceeded)?;
        [
            (entries, 64u64),
            (self.keys.len(), 120),
            (self.claims.len(), 97),
            (remaining, 32),
            (self.overlays.len(), 80),
        ]
        .into_iter()
        .try_fold(240u64, |n, (count, size)| {
            (count as u64)
                .checked_mul(size)
                .and_then(|v| n.checked_add(v))
                .ok_or(RepositoryFailure::LimitExceeded)
        })
    }
    pub(super) fn signed_bytes(
        &self,
        signer: &BackupControlSigner,
    ) -> Result<Vec<u8>, RepositoryFailure> {
        if self
            .snapshots
            .len()
            .checked_add(self.reservations.len())
            .and_then(|count| count.checked_add(self.claims.len()))
            .is_none_or(|count| count > MAX_REGISTERED_SNAPSHOTS)
            || self.keys.len() > MAX_KEY_ENVELOPES
            || self.overlays.len() > overlay::MAX_OVERLAYS
        {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let mut bytes = b"POSBKG05".to_vec();
        bytes.extend_from_slice(&self.number.to_be_bytes());
        bytes.extend_from_slice(&self.previous);
        bytes.extend_from_slice(&self.repository.encode());
        bytes.extend_from_slice(&(self.snapshots.len() as u32).to_be_bytes());
        for snapshot in &self.snapshots {
            bytes.extend_from_slice(&snapshot.snapshot);
            bytes.extend_from_slice(&snapshot.manifest.checksum());
            bytes.extend_from_slice(&snapshot.created.to_be_bytes());
            bytes.extend_from_slice(&snapshot.retain_until.to_be_bytes());
        }
        bytes.extend_from_slice(&(self.reservations.len() as u32).to_be_bytes());
        for reservation in &self.reservations {
            bytes.extend_from_slice(&reservation.snapshot);
            bytes.extend_from_slice(&reservation.manifest.checksum());
            bytes.extend_from_slice(&reservation.created.to_be_bytes());
            bytes.extend_from_slice(&reservation.retain_until.to_be_bytes());
        }
        bytes.extend_from_slice(&(self.keys.len() as u32).to_be_bytes());
        for key in &self.keys {
            bytes.extend_from_slice(&key.context);
            bytes.extend_from_slice(&key.tenant);
            bytes.extend_from_slice(&key.epoch.to_be_bytes());
            bytes.extend_from_slice(&key.fingerprint);
            bytes.extend_from_slice(&key.object.checksum());
        }
        super::expiry::codec::encode(&self.claims, &mut bytes)?;
        bytes.extend_from_slice(&(self.overlays.len() as u32).to_be_bytes());
        for overlay in &self.overlays {
            bytes.extend_from_slice(&overlay.snapshot);
            bytes.extend_from_slice(&overlay.target);
            bytes.extend_from_slice(&overlay.object.checksum());
        }
        super::super::codec::sign(bytes, signer)
    }
    pub(super) fn verify(
        bytes: &[u8],
        identity: &RepositoryIdentity,
        integrity: BootstrapIntegrityIdentity,
    ) -> Result<Self, RepositoryFailure> {
        let mut decoder =
            super::super::codec::Decoder::new(super::super::codec::verify(bytes, integrity)?);
        let version = decoder.take(8)?;
        if version != b"POSBKG04" && version != b"POSBKG05" {
            return Err(RepositoryFailure::CorruptState);
        }
        let number = decoder.u64()?;
        let previous = decoder.array()?;
        let repository = RepositoryIdentity::decode(decoder.take(108)?)?;
        if number == 0 || repository != *identity {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        let count = decoder.u32()? as usize;
        if count > MAX_REGISTERED_SNAPSHOTS {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let mut snapshots = Vec::new();
        snapshots
            .try_reserve_exact(count)
            .map_err(|_| RepositoryFailure::LimitExceeded)?;
        for _ in 0..count {
            let snapshot = decoder.array()?;
            let manifest = ObjectId::from_checksum(decoder.array()?);
            let created = decoder.u64()?;
            let retain_until = decoder.u64()?;
            if snapshot == [0; 16]
                || created == 0
                || retain_until < created
                || snapshots
                    .last()
                    .is_some_and(|last: &BackupReceipt| last.snapshot >= snapshot)
            {
                return Err(RepositoryFailure::CorruptState);
            }
            snapshots.push(BackupReceipt {
                snapshot,
                manifest,
                created,
                retain_until,
            });
        }
        let count = decoder.u32()? as usize;
        if count
            .checked_add(snapshots.len())
            .is_none_or(|total| total > MAX_REGISTERED_SNAPSHOTS)
        {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let mut reservations = Vec::new();
        reservations
            .try_reserve_exact(count)
            .map_err(|_| RepositoryFailure::LimitExceeded)?;
        for _ in 0..count {
            let snapshot = decoder.array()?;
            let manifest = ObjectId::from_checksum(decoder.array()?);
            let created = decoder.u64()?;
            let retain_until = decoder.u64()?;
            if snapshot == [0; 16]
                || created == 0
                || retain_until < created
                || snapshots.iter().any(|receipt| receipt.snapshot == snapshot)
                || reservations
                    .last()
                    .is_some_and(|last: &BackupReceipt| last.snapshot >= snapshot)
            {
                return Err(RepositoryFailure::CorruptState);
            }
            reservations.push(BackupReceipt {
                snapshot,
                manifest,
                created,
                retain_until,
            });
        }
        let count = decoder.u32()? as usize;
        if count > MAX_KEY_ENVELOPES {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let mut keys = Vec::new();
        keys.try_reserve_exact(count)
            .map_err(|_| RepositoryFailure::LimitExceeded)?;
        for _ in 0..count {
            let key = KeyReference {
                context: decoder.array()?,
                tenant: decoder.array()?,
                epoch: decoder.u64()?,
                fingerprint: decoder.array()?,
                object: ObjectId::from_checksum(decoder.array()?),
            };
            if key.tenant == [0; 16]
                || key.epoch == 0
                || key.fingerprint == [0; 32]
                || keys.last().is_some_and(|last: &KeyReference| {
                    (last.context, last.tenant, last.epoch, last.object)
                        >= (key.context, key.tenant, key.epoch, key.object)
                })
            {
                return Err(RepositoryFailure::CorruptState);
            }
            keys.push(key);
        }
        let claims =
            super::expiry::codec::decode(&mut decoder, snapshots.len() + reservations.len())?;
        if claims.iter().any(|claim| {
            snapshots
                .iter()
                .chain(&reservations)
                .any(|receipt| receipt.snapshot == claim.receipt.snapshot)
        }) {
            return Err(RepositoryFailure::CorruptState);
        }
        let mut overlays = Vec::new();
        if version == b"POSBKG05" {
            let count = decoder.u32()? as usize;
            if count > overlay::MAX_OVERLAYS {
                return Err(RepositoryFailure::LimitExceeded);
            }
            overlays
                .try_reserve_exact(count)
                .map_err(|_| RepositoryFailure::LimitExceeded)?;
            for _ in 0..count {
                let reference = OverlayReference {
                    snapshot: decoder.array()?,
                    target: decoder.array()?,
                    object: ObjectId::from_checksum(decoder.array()?),
                };
                if reference.snapshot == [0; 16]
                    || reference.target == [0; 32]
                    || reference.object.checksum() == [0; 32]
                    || overlays.last().is_some_and(|last: &OverlayReference| {
                        (last.snapshot, last.target) >= (reference.snapshot, reference.target)
                    })
                {
                    return Err(RepositoryFailure::CorruptState);
                }
                overlays.push(reference);
            }
        }
        decoder.finish()?;
        Ok(Self {
            number,
            previous,
            repository,
            snapshots,
            reservations,
            claims,
            keys,
            overlays,
        })
    }
}
