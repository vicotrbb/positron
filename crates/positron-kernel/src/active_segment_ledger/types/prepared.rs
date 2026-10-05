use crate::ResourceReservation;
use crate::data_protection::DataProtection;
use std::sync::OnceLock;

use super::{
    AuthenticatedEventRange, EventRangeUnavailable, IngestTime, LedgerFailure, LedgerFailureCode,
    SegmentScope, StoreBlockIdentity,
};
use crate::active_segment_ledger::MAX_STORE_BLOCK_BYTES;

/// Move-only Storage Kernel authority to prepare one retention-authenticated Store Block.
///
/// The private ingest timestamp is minted by the ledger and is consumed with
/// the preparation capacity when the Signal Store finishes its canonical
/// bytes. Callers can observe the timestamp for encoding, but cannot replace
/// the authenticated retention upper bound carried by the finished block.
pub struct StoreBlockPreparation<'capacity> {
    pub(in crate::active_segment_ledger) scope: SegmentScope,
    pub(in crate::active_segment_ledger) identity: StoreBlockIdentity,
    pub(in crate::active_segment_ledger) ingest_time: IngestTime,
    pub(in crate::active_segment_ledger) retention_ingest_time: Option<IngestTime>,
    pub(in crate::active_segment_ledger) capacity: ResourceReservation<'capacity>,
}

impl<'capacity> StoreBlockPreparation<'capacity> {
    #[must_use]
    pub const fn scope(&self) -> SegmentScope {
        self.scope
    }

    #[must_use]
    pub const fn identity(&self) -> StoreBlockIdentity {
        self.identity
    }

    #[must_use]
    pub const fn ingest_time(&self) -> IngestTime {
        self.ingest_time
    }

    pub fn finish(self, bytes: Vec<u8>) -> Result<PreparedStoreBlock<'capacity>, LedgerFailure> {
        self.finish_with_event_range(
            bytes,
            AuthenticatedEventRange::unavailable(EventRangeUnavailable::LegacyFormat),
        )
    }

    /// Finishes canonical signal-store bytes with producer-owned Event Time
    /// evidence. The kernel authenticates this summary without inspecting the
    /// payload's store-specific format.
    pub fn finish_with_event_range(
        self,
        bytes: Vec<u8>,
        event_range: AuthenticatedEventRange,
    ) -> Result<PreparedStoreBlock<'capacity>, LedgerFailure> {
        PreparedStoreBlock::checked(
            self.scope,
            self.identity,
            bytes,
            Some(self.capacity),
            self.retention_ingest_time,
            event_range,
        )
    }
}

/// Opaque canonical Store Block bytes and their caller-owned stable identity.
pub struct PreparedStoreBlock<'capacity> {
    pub(in crate::active_segment_ledger) scope: SegmentScope,
    pub(in crate::active_segment_ledger) identity: StoreBlockIdentity,
    pub(in crate::active_segment_ledger) payload: Vec<u8>,
    pub(in crate::active_segment_ledger) content_digest: OnceLock<[u8; 32]>,
    pub(in crate::active_segment_ledger) preparation_capacity:
        Option<ResourceReservation<'capacity>>,
    pub(in crate::active_segment_ledger) retention_ingest_time: Option<IngestTime>,
    pub(in crate::active_segment_ledger) event_range: AuthenticatedEventRange,
}

impl PreparedStoreBlock<'static> {
    pub fn new(
        scope: SegmentScope,
        identity: StoreBlockIdentity,
        bytes: Vec<u8>,
    ) -> Result<Self, LedgerFailure> {
        Self::checked(
            scope,
            identity,
            bytes,
            None,
            None,
            AuthenticatedEventRange::unavailable(EventRangeUnavailable::LegacyFormat),
        )
    }

    #[cfg(any(test, fuzzing, feature = "test-support"))]
    #[doc(hidden)]
    pub fn new_with_event_range_for_test(
        scope: SegmentScope,
        identity: StoreBlockIdentity,
        bytes: Vec<u8>,
        event_range: AuthenticatedEventRange,
    ) -> Result<Self, LedgerFailure> {
        Self::checked(scope, identity, bytes, None, None, event_range)
    }

    #[cfg(any(test, fuzzing, feature = "test-support"))]
    #[doc(hidden)]
    #[cfg(test)]
    pub(crate) fn new_with_authenticated_ranges_for_test(
        scope: SegmentScope,
        identity: StoreBlockIdentity,
        bytes: Vec<u8>,
        event_range: AuthenticatedEventRange,
        ingest_time: IngestTime,
    ) -> Result<Self, LedgerFailure> {
        Self::checked(scope, identity, bytes, None, Some(ingest_time), event_range)
    }
}

impl<'capacity> PreparedStoreBlock<'capacity> {
    /// Computes the stable digest used to reconcile this canonical payload.
    pub fn content_digest(&self) -> Result<[u8; 32], LedgerFailure> {
        if let Some(digest) = self.content_digest.get() {
            return Ok(*digest);
        }
        let digest = DataProtection::hash(&self.payload)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?;
        Ok(publish_digest(&self.content_digest, digest))
    }

    pub fn new_with_preparation_capacity(
        scope: SegmentScope,
        identity: StoreBlockIdentity,
        bytes: Vec<u8>,
        capacity: ResourceReservation<'capacity>,
    ) -> Result<Self, LedgerFailure> {
        Self::checked(
            scope,
            identity,
            bytes,
            Some(capacity),
            None,
            AuthenticatedEventRange::unavailable(EventRangeUnavailable::LegacyFormat),
        )
    }

    fn checked(
        scope: SegmentScope,
        identity: StoreBlockIdentity,
        bytes: Vec<u8>,
        preparation_capacity: Option<ResourceReservation<'capacity>>,
        retention_ingest_time: Option<IngestTime>,
        event_range: AuthenticatedEventRange,
    ) -> Result<Self, LedgerFailure> {
        if bytes.is_empty() || bytes.len() > MAX_STORE_BLOCK_BYTES {
            return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
        }
        Ok(Self {
            scope,
            identity,
            payload: bytes,
            content_digest: OnceLock::new(),
            preparation_capacity,
            retention_ingest_time,
            event_range,
        })
    }
}

fn publish_digest(content_digest: &OnceLock<[u8; 32]>, digest: [u8; 32]) -> [u8; 32] {
    match content_digest.set(digest) {
        Ok(()) => digest,
        Err(existing) => content_digest
            .get()
            .copied()
            .map_or(existing, |stored| stored),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use positron_domain::time::UnixNanoseconds;

    use super::publish_digest;
    use crate::{AuthenticatedEventRange, EventRangeUnavailable};

    #[test]
    fn competing_digest_publication_keeps_the_first_value() {
        let content_digest = OnceLock::new();
        assert_eq!(publish_digest(&content_digest, [0x11; 32]), [0x11; 32]);
        assert_eq!(publish_digest(&content_digest, [0x22; 32]), [0x11; 32]);
    }

    #[test]
    fn authenticated_event_ranges_preserve_known_bounds_and_explicit_absence() {
        assert_eq!(
            AuthenticatedEventRange::known(UnixNanoseconds::new(4), UnixNanoseconds::new(9)),
            Ok(AuthenticatedEventRange::Known {
                earliest: UnixNanoseconds::new(4),
                latest: UnixNanoseconds::new(9),
            })
        );
        assert_eq!(
            AuthenticatedEventRange::known(UnixNanoseconds::new(9), UnixNanoseconds::new(4)),
            Err(EventRangeUnavailable::InvalidSourceTime)
        );
    }
}
