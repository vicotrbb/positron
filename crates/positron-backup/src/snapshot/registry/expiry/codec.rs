use super::*;
pub(in crate::snapshot::registry) fn encode(
    claims: &[DeletionClaim],
    bytes: &mut Vec<u8>,
) -> Result<(), RepositoryFailure> {
    if claims.len() > MAX_REGISTERED_SNAPSHOTS
        || claims
            .iter()
            .try_fold(0usize, |total, claim| {
                total.checked_add(claim.remaining.len())
            })
            .is_none_or(|count| count > MAX_CLAIMED_OBJECTS)
    {
        return Err(RepositoryFailure::LimitExceeded);
    }
    bytes.extend_from_slice(&(claims.len() as u32).to_be_bytes());
    for claim in claims {
        bytes.extend_from_slice(&claim.owner);
        bytes.push(match claim.reason {
            BackupCleanupReason::Retention => 1,
            BackupCleanupReason::Cancellation => 2,
        });
        bytes.extend_from_slice(&claim.receipt.snapshot);
        bytes.extend_from_slice(&claim.receipt.manifest.checksum());
        bytes.extend_from_slice(&claim.receipt.created.to_be_bytes());
        bytes.extend_from_slice(&claim.receipt.retain_until.to_be_bytes());
        for count in [
            claim.deleted,
            claim.absent,
            claim.shared,
            claim.remaining.len() as u32,
        ] {
            bytes.extend_from_slice(&count.to_be_bytes());
        }
        for object in &claim.remaining {
            bytes.extend_from_slice(&object.checksum());
        }
    }
    Ok(())
}
pub(in crate::snapshot::registry) fn decode(
    decoder: &mut super::super::super::codec::Decoder<'_>,
    retained: usize,
) -> Result<Vec<DeletionClaim>, RepositoryFailure> {
    let count = decoder.u32()? as usize;
    if count
        .checked_add(retained)
        .is_none_or(|count| count > MAX_REGISTERED_SNAPSHOTS)
    {
        return Err(RepositoryFailure::LimitExceeded);
    }
    let mut claims = Vec::new();
    claims
        .try_reserve_exact(count)
        .map_err(|_| RepositoryFailure::LimitExceeded)?;
    let mut total = 0usize;
    for _ in 0..count {
        let owner = decoder.array()?;
        let reason = match decoder.take(1)? {
            [1] => BackupCleanupReason::Retention,
            [2] => BackupCleanupReason::Cancellation,
            _ => return Err(RepositoryFailure::CorruptState),
        };
        let receipt = BackupReceipt {
            snapshot: decoder.array()?,
            manifest: ObjectId::from_checksum(decoder.array()?),
            created: decoder.u64()?,
            retain_until: decoder.u64()?,
        };
        let deleted = decoder.u32()?;
        let absent = decoder.u32()?;
        let shared = decoder.u32()?;
        let count = decoder.u32()? as usize;
        total = total
            .checked_add(count)
            .ok_or(RepositoryFailure::LimitExceeded)?;
        if total > MAX_CLAIMED_OBJECTS {
            return Err(RepositoryFailure::LimitExceeded);
        }
        if owner == [0; 16]
            || receipt.snapshot == [0; 16]
            || receipt.created == 0
            || receipt.retain_until < receipt.created
            || claims
                .last()
                .is_some_and(|claim: &DeletionClaim| claim.owner >= owner)
            || claims
                .iter()
                .any(|claim| claim.receipt.snapshot == receipt.snapshot)
            || u64::from(deleted) + u64::from(absent) + u64::from(shared) + count as u64
                > MAX_CLAIMED_OBJECTS as u64
        {
            return Err(RepositoryFailure::CorruptState);
        }
        let mut remaining = Vec::new();
        remaining
            .try_reserve_exact(count)
            .map_err(|_| RepositoryFailure::LimitExceeded)?;
        for _ in 0..count {
            let object = ObjectId::from_checksum(decoder.array()?);
            if remaining.last().is_some_and(|last| *last >= object)
                || claims
                    .iter()
                    .any(|claim| claim.remaining.binary_search(&object).is_ok())
            {
                return Err(RepositoryFailure::CorruptState);
            }
            remaining.push(object);
        }
        claims.push(DeletionClaim {
            owner,
            reason,
            receipt,
            remaining,
            deleted,
            absent,
            shared,
        });
    }
    Ok(claims)
}
