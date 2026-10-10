use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::{CommittedBlock, LedgerFailure, LedgerFailureCode, SegmentId};

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum SnapshotProtectionBinding {
    Segment([u8; 16], [u8; 32], u64),
    TenantEpoch([u8; 16], u64),
}
pub(crate) type SnapshotProtectionRegistry = Arc<Mutex<BTreeMap<SnapshotProtectionBinding, usize>>>;

/// A non-owning physical protection claim held by one immutable snapshot.
///
/// The registry is shared by readers and the writer for one Storage Kernel.
/// Retention may remove a segment from future snapshots, but it must retain the
/// bytes while any already-created snapshot still references that segment.
pub(crate) struct SnapshotProtection {
    registry: SnapshotProtectionRegistry,
    segments: Vec<SnapshotProtectionBinding>,
}

impl SnapshotProtection {
    pub(super) fn for_blocks(
        registry: SnapshotProtectionRegistry,
        barrier: &RwLock<()>,
        basis: &crate::CatalogSnapshot,
        blocks: &[CommittedBlock],
    ) -> Result<Self, LedgerFailure> {
        let barrier = barrier
            .read()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        Self::with_barrier(
            registry,
            barrier,
            basis,
            blocks.iter().map(CommittedBlock::segment_id),
        )
    }

    pub(super) fn for_segments(
        registry: SnapshotProtectionRegistry,
        barrier: &RwLock<()>,
        basis: &crate::CatalogSnapshot,
        segments: impl IntoIterator<Item = SegmentId>,
    ) -> Result<Self, LedgerFailure> {
        let barrier = Self::read_barrier(barrier)?;
        Self::with_barrier(registry, barrier, basis, segments)
    }

    pub(super) fn read_barrier<'kernel>(
        barrier: &'kernel RwLock<()>,
    ) -> Result<RwLockReadGuard<'kernel, ()>, LedgerFailure> {
        barrier
            .read()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))
    }

    pub(super) fn write_barrier<'kernel>(
        barrier: &'kernel RwLock<()>,
    ) -> Result<RwLockWriteGuard<'kernel, ()>, LedgerFailure> {
        barrier
            .write()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))
    }

    pub(super) fn with_barrier<'kernel>(
        registry: SnapshotProtectionRegistry,
        barrier: RwLockReadGuard<'kernel, ()>,
        basis: &crate::CatalogSnapshot,
        segments: impl IntoIterator<Item = SegmentId>,
    ) -> Result<Self, LedgerFailure> {
        let mut identities = Vec::new();
        for segment in segments {
            let identity = SnapshotProtectionBinding::Segment(
                segment.to_bytes(),
                basis.identity().to_bytes(),
                basis.number(),
            );
            if !identities.contains(&identity) {
                identities
                    .try_reserve(1)
                    .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
                identities.push(identity);
            }
        }
        Self::register(registry, barrier, identities)
    }

    pub(crate) fn for_tenant_epochs(
        registry: SnapshotProtectionRegistry,
        barrier: &RwLock<()>,
        tenant: positron_domain::identity::TenantId,
        epochs: impl IntoIterator<Item = u64>,
    ) -> Result<Self, LedgerFailure> {
        let barrier = barrier
            .try_read()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        let mut identities = Vec::new();
        identities
            .try_reserve_exact(16)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        for epoch in epochs {
            if epoch == 0 || identities.len() == 16 {
                return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
            }
            identities.push(SnapshotProtectionBinding::TenantEpoch(
                tenant.to_bytes(),
                epoch,
            ));
        }
        Self::register(registry, barrier, identities)
    }

    fn register(
        registry: SnapshotProtectionRegistry,
        barrier: RwLockReadGuard<'_, ()>,
        identities: Vec<SnapshotProtectionBinding>,
    ) -> Result<Self, LedgerFailure> {
        let mut counts = registry
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        if identities.iter().any(|identity| {
            counts
                .get(identity)
                .is_some_and(|count| *count == usize::MAX)
        }) {
            return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
        }
        for identity in &identities {
            let count = counts.entry(*identity).or_insert(0);
            *count = count
                .checked_add(1)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        }
        drop(counts);
        drop(barrier);
        Ok(Self {
            registry,
            segments: identities,
        })
    }

    pub(super) fn is_protected(
        registry: &SnapshotProtectionRegistry,
        segment: SegmentId,
    ) -> Result<bool, LedgerFailure> {
        registry
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))
            .map(|counts| {
                counts.iter().any(|(binding, count)| {
                    matches!(binding,
                        SnapshotProtectionBinding::Segment(identity, _, _) if
                        *identity == segment.to_bytes())
                        && *count != 0
                })
            })
    }
}

impl Drop for SnapshotProtection {
    fn drop(&mut self) {
        let Ok(mut counts) = self.registry.lock() else {
            return;
        };
        for identity in self.segments.drain(..) {
            match counts.get_mut(&identity) {
                Some(count) if *count > 1 => *count -= 1,
                Some(_) => {
                    counts.remove(&identity);
                },
                None => {},
            }
        }
    }
}
