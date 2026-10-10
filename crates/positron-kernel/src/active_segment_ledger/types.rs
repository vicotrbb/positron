use std::fmt::Formatter;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;

use crate::data_protection::{SecretKeyBytes, SegmentEnvelopeRoute};

use crate::IngestTime;
use crate::ResourceReservation;

mod failure;
mod prepared;
#[cfg(test)]
mod protection_clone;
pub use failure::{LedgerCompletionState, LedgerFailure, LedgerFailureCode};
pub use prepared::{PreparedStoreBlock, StoreBlockPreparation};

/// Why a signal store cannot authenticate an Event Time range for a block.
///
/// This is authenticated alongside canonical block bytes. It deliberately
/// distinguishes a producer-derived absence from pre-range data so integrity
/// response never invents a localized time range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventRangeUnavailable {
    MissingSourceTime,
    InvalidSourceTime,
    LegacyFormat,
}

/// Signal-store supplied Event Time evidence carried opaquely by the kernel.
///
/// The Storage Kernel authenticates and transports this summary, but never
/// decodes Log or Trace payloads to derive it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatedEventRange {
    Known {
        earliest: UnixNanoseconds,
        latest: UnixNanoseconds,
    },
    Unavailable(EventRangeUnavailable),
}

/// Kernel-issued Ingest Time range retained with a sealed segment's trusted
/// Event Time evidence for integrity reporting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatedIngestRange {
    Known {
        earliest: UnixNanoseconds,
        latest: UnixNanoseconds,
    },
    Unavailable,
}

impl AuthenticatedIngestRange {
    #[must_use]
    pub const fn one(instant: IngestTime) -> Self {
        Self::Known {
            earliest: instant.instant(),
            latest: instant.instant(),
        }
    }

    #[must_use]
    pub const fn unavailable() -> Self {
        Self::Unavailable
    }

    #[must_use]
    pub(super) fn aggregate(self, next: Self) -> Self {
        match (self, next) {
            (
                Self::Known {
                    earliest: left_earliest,
                    latest: left_latest,
                },
                Self::Known {
                    earliest: right_earliest,
                    latest: right_latest,
                },
            ) => Self::Known {
                earliest: left_earliest.min(right_earliest),
                latest: left_latest.max(right_latest),
            },
            (Self::Unavailable, _) | (_, Self::Unavailable) => Self::Unavailable,
        }
    }
}

impl AuthenticatedEventRange {
    pub fn known(
        earliest: UnixNanoseconds,
        latest: UnixNanoseconds,
    ) -> Result<Self, EventRangeUnavailable> {
        if earliest > latest {
            return Err(EventRangeUnavailable::InvalidSourceTime);
        }
        Ok(Self::Known { earliest, latest })
    }

    #[must_use]
    pub const fn unavailable(reason: EventRangeUnavailable) -> Self {
        Self::Unavailable(reason)
    }

    #[must_use]
    pub(super) fn aggregate(self, next: Self) -> Self {
        match (self, next) {
            (
                Self::Known {
                    earliest: left_earliest,
                    latest: left_latest,
                },
                Self::Known {
                    earliest: right_earliest,
                    latest: right_latest,
                },
            ) => Self::Known {
                earliest: left_earliest.min(right_earliest),
                latest: left_latest.max(right_latest),
            },
            (Self::Unavailable(reason), _) | (_, Self::Unavailable(reason)) => {
                Self::Unavailable(reason)
            },
        }
    }
}

/// The immutable tenant, Signal Store, and Virtual Shard boundary of one active segment.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SegmentScope {
    pub(super) tenant: TenantId,
    pub(super) signal: SignalKind,
    pub(super) shard: VirtualShardId,
}

impl SegmentScope {
    #[must_use]
    pub const fn new(tenant: TenantId, signal: SignalKind, shard: VirtualShardId) -> Self {
        Self {
            tenant,
            signal,
            shard,
        }
    }

    #[must_use]
    pub const fn tenant_id(self) -> TenantId {
        self.tenant
    }

    #[must_use]
    pub const fn signal_kind(self) -> SignalKind {
        self.signal
    }

    #[must_use]
    pub const fn shard_id(self) -> VirtualShardId {
        self.shard
    }

    pub(super) fn lease_key(self) -> [u8; 22] {
        let mut key = [0_u8; 22];
        for (destination, source) in key.iter_mut().zip(self.tenant.to_bytes()) {
            *destination = source;
        }
        for signal in key.iter_mut().skip(16).take(1) {
            *signal = match self.signal {
                SignalKind::Logs => 1,
                SignalKind::Traces => 2,
            };
        }
        for (destination, source) in key
            .iter_mut()
            .skip(17)
            .zip(self.shard.value().to_be_bytes())
        {
            *destination = source;
        }
        if let Some(lifecycle) = key.last_mut() {
            *lifecycle = 1;
        }
        key
    }
}

/// Fixed ingest-time interval scoped to one tenant and Signal Store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionBucket {
    tenant: TenantId,
    signal: SignalKind,
    start: UnixNanoseconds,
    end_exclusive: UnixNanoseconds,
}

impl RetentionBucket {
    pub(crate) fn from_bounds(
        tenant: TenantId,
        signal: SignalKind,
        start: UnixNanoseconds,
        end_exclusive: UnixNanoseconds,
        duration_seconds: NonZeroU64,
    ) -> Result<Self, LedgerFailure> {
        let width = duration_seconds
            .get()
            .checked_mul(1_000_000_000)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        if start.value().rem_euclid(width) != 0
            || start
                .value()
                .checked_add(width)
                .filter(|end| *end == end_exclusive.value())
                .is_none()
        {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        Ok(Self {
            tenant,
            signal,
            start,
            end_exclusive,
        })
    }

    pub fn for_ingest_time(
        tenant: TenantId,
        signal: SignalKind,
        ingest_time: IngestTime,
        duration_seconds: NonZeroU64,
    ) -> Result<Self, LedgerFailure> {
        if !ingest_time.retention_authenticated() {
            return Err(LedgerFailure::new(LedgerFailureCode::UnsupportedFormat));
        }
        let width = duration_seconds
            .get()
            .checked_mul(1_000_000_000)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let start = ingest_time
            .instant()
            .value()
            .div_euclid(width)
            .checked_mul(width)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let end_exclusive = start
            .checked_add(width)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        Ok(Self {
            tenant,
            signal,
            start: UnixNanoseconds::new(start),
            end_exclusive: UnixNanoseconds::new(end_exclusive),
        })
    }

    #[must_use]
    pub const fn tenant(self) -> TenantId {
        self.tenant
    }

    #[must_use]
    pub const fn signal_kind(self) -> SignalKind {
        self.signal
    }

    #[must_use]
    pub const fn start(self) -> UnixNanoseconds {
        self.start
    }

    #[must_use]
    pub const fn end_exclusive(self) -> UnixNanoseconds {
        self.end_exclusive
    }
}

/// The immutable random identity of one physical segment.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SegmentId(pub(super) [u8; 16]);

impl SegmentId {
    pub(super) fn new(bytes: [u8; 16]) -> Result<Self, LedgerFailure> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, LedgerFailure> {
        Self::new(bytes)
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Stable caller-supplied identity of one canonical Store Block append operation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StoreBlockIdentity(pub(super) [u8; 16]);

impl StoreBlockIdentity {
    pub fn new(bytes: [u8; 16]) -> Result<Self, LedgerFailure> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

pub(super) type SegmentKeyRoute = SegmentEnvelopeRoute;

pub(super) enum SegmentKeyAccess<'a> {
    Borrowed(&'a SecretKeyBytes),
    Owned(SecretKeyBytes),
}
impl std::ops::Deref for SegmentKeyAccess<'_> {
    type Target = SecretKeyBytes;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(key) => key,
            Self::Owned(key) => key,
        }
    }
}

/// A one-shot secret capability and its non-secret provider recovery route.
pub struct SegmentProtectionKey {
    key: Option<SecretKeyBytes>,
    local_source: Option<crate::data_protection::LocalSegmentKeySource>,
    pub(super) route: SegmentKeyRoute,
    retained: Vec<(SegmentKeyRoute, SecretKeyBytes)>,
    capacity: Option<Box<crate::TransferredResourceReservation>>,
}

impl SegmentProtectionKey {
    pub(crate) fn is_only_epoch(&self, epoch: u64) -> bool {
        self.route.provider_key_epoch == epoch
            && self.retained.is_empty()
            && self
                .local_source
                .as_ref()
                .is_none_or(|source| matches!(source.is_single_route(self.route), Ok(true)))
    }

    pub(crate) fn from_local_source(
        source: crate::data_protection::LocalSegmentKeySource,
        route: SegmentKeyRoute,
    ) -> Self {
        Self {
            key: None,
            local_source: Some(source),
            route,
            retained: Vec::new(),
            capacity: None,
        }
    }
    pub(crate) fn with_capacity(mut self, capacity: crate::TransferredResourceReservation) -> Self {
        self.capacity = Some(Box::new(capacity));
        self
    }
    pub(super) fn key_for_route(
        &self,
        route: SegmentKeyRoute,
    ) -> Result<SegmentKeyAccess<'_>, LedgerFailure> {
        if let Some(source) = &self.local_source {
            return source
                .key(route)
                .map(SegmentKeyAccess::Owned)
                .map_err(|failure| {
                    LedgerFailure::new(match failure {
                        crate::BootstrapKeyFailure::Authentication => {
                            LedgerFailureCode::AuthenticationFailed
                        },
                        crate::BootstrapKeyFailure::LimitExceeded => {
                            LedgerFailureCode::ResourceAdmissionRefused
                        },
                        _ => LedgerFailureCode::RecoveryRequired,
                    })
                });
        }
        if route == self.route {
            return self
                .key
                .as_ref()
                .map(SegmentKeyAccess::Borrowed)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::AuthenticationFailed));
        }
        self.retained
            .iter()
            .find_map(|(candidate, key)| {
                (*candidate == route).then_some(SegmentKeyAccess::Borrowed(key))
            })
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::AuthenticationFailed))
    }
    pub(super) fn predecessor_route(
        &self,
        before: u64,
    ) -> Result<Option<SegmentKeyRoute>, LedgerFailure> {
        if let Some(source) = &self.local_source {
            return source
                .predecessor_route(before)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::AuthenticationFailed));
        }
        Ok(std::iter::once(self.route)
            .chain(self.retained.iter().map(|(route, _)| *route))
            .filter(|route| route.provider_key_epoch < before)
            .max_by_key(|route| route.provider_key_epoch))
    }

    #[must_use]
    pub fn from_owned(bytes: Box<[u8; 32]>) -> Self {
        Self {
            key: Some(SecretKeyBytes::from_owned(bytes)),
            local_source: None,
            route: SegmentKeyRoute {
                provider_family: 1,
                provider_reference: [1; 16],
                provider_key_epoch: 1,
            },
            retained: Vec::new(),
            capacity: None,
        }
    }

    pub fn from_owned_with_route(
        bytes: Box<[u8; 32]>,
        provider_reference: [u8; 16],
        provider_key_epoch: u64,
    ) -> Result<Self, LedgerFailure> {
        if provider_reference.iter().all(|byte| *byte == 0) || provider_key_epoch == 0 {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        Ok(Self {
            key: Some(SecretKeyBytes::from_owned(bytes)),
            local_source: None,
            route: SegmentKeyRoute {
                provider_family: 1,
                provider_reference,
                provider_key_epoch,
            },
            retained: Vec::new(),
            capacity: None,
        })
    }

    /// Retains bounded prior wrapping epochs for immutable segment reads.
    pub fn retain_predecessor(mut self, predecessor: Self) -> Result<Self, LedgerFailure> {
        if self.local_source.is_some() || predecessor.local_source.is_some() {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        let count = self
            .retained
            .len()
            .checked_add(predecessor.retained.len())
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        if count >= 16 {
            return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
        }
        for route in std::iter::once(&predecessor.route)
            .chain(predecessor.retained.iter().map(|(route, _)| route))
        {
            if route.provider_key_epoch >= self.route.provider_key_epoch
                || self.retained.iter().any(|(existing, _)| existing == route)
            {
                return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
            }
        }
        self.retained
            .try_reserve_exact(count - self.retained.len())
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        self.retained.push((
            predecessor.route,
            predecessor
                .key
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::AuthenticationFailed))?,
        ));
        self.retained.extend(predecessor.retained);
        if self.capacity.is_none() {
            self.capacity = predecessor.capacity;
        }
        Ok(self)
    }
}

impl std::fmt::Debug for SegmentProtectionKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SegmentProtectionKey { <redacted> }")
    }
}

/// Cooperative cancellation observed only before durability work is admitted.
#[derive(Clone, Debug)]
pub struct AppendCancellation(Arc<AtomicBool>);

impl AppendCancellation {
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

impl Default for AppendCancellation {
    fn default() -> Self {
        Self::new()
    }
}

/// Proof that the exact block and authenticated frontier completed local durability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    pub(super) segment: SegmentId,
    pub(super) position: CommitPosition,
    pub(super) frontier_authenticator: [u8; 32],
}

impl CommitReceipt {
    #[must_use]
    pub const fn segment_id(&self) -> SegmentId {
        self.segment
    }

    #[must_use]
    pub const fn position(&self) -> CommitPosition {
        self.position
    }

    #[must_use]
    pub const fn frontier_authenticator(&self) -> [u8; 32] {
        self.frontier_authenticator
    }
}

/// One authenticated committed Store Block visible through a stable snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedBlock {
    pub(super) identity: StoreBlockIdentity,
    pub(super) position: CommitPosition,
    pub(super) payload: Vec<u8>,
    pub(super) content_digest: [u8; 32],
    pub(super) segment: SegmentId,
    pub(super) frontier_authenticator: [u8; 32],
    pub(super) block_retention: SegmentRetention,
    pub(super) event_range: AuthenticatedEventRange,
}

/// A verified Log Store block prepared for kernel-owned copy-on-write
/// compaction. The source identity and position are retained so a replacement
/// segment cannot silently change query resume identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactionBlock {
    pub(super) scope: SegmentScope,
    pub(super) source_segment: SegmentId,
    pub(super) identity: StoreBlockIdentity,
    pub(super) position: CommitPosition,
    pub(super) payload: Vec<u8>,
    pub(super) content_digest: [u8; 32],
    pub(super) ingest_time: IngestTime,
    pub(super) event_range: AuthenticatedEventRange,
}

/// Source-owned time evidence retained by a compaction output block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactionBlockTime {
    ingest_time: IngestTime,
    event_range: AuthenticatedEventRange,
}

impl CompactionBlockTime {
    pub const fn new(ingest_time: IngestTime, event_range: AuthenticatedEventRange) -> Self {
        Self {
            ingest_time,
            event_range,
        }
    }
}

/// Capacity admitted before a caller materializes compaction inputs.
///
/// The reservation is move-only so every successful preparation is either
/// consumed by the kernel publication or released before the caller returns.
pub struct CompactionPreparation<'kernel> {
    pub(super) capacity: Option<ResourceReservation<'kernel>>,
    pub(super) granted: crate::ResourceAmounts,
    pub(super) coordinator_admitted: bool,
    pub(super) scope: SegmentScope,
    pub(super) catalog_instance: crate::InstanceId,
    pub(super) catalog_identity: crate::CatalogGenerationId,
    pub(super) catalog_generation: u64,
    pub(super) retention_policy: Option<crate::CatalogLogRetentionPolicy>,
    pub(super) frontier: CommitPosition,
    pub(super) source_digest: [u8; 32],
    pub(super) maximum_blocks: usize,
    pub(super) maximum_payload_bytes: usize,
}

impl CompactionBlock {
    /// Creates one immutable block for a kernel compaction publication.
    pub fn new(
        scope: SegmentScope,
        source_segment: SegmentId,
        identity: StoreBlockIdentity,
        position: CommitPosition,
        payload: Vec<u8>,
        content_digest: [u8; 32],
        ingest_time: IngestTime,
    ) -> Result<Self, LedgerFailure> {
        Self::new_with_time(
            scope,
            source_segment,
            identity,
            position,
            payload,
            content_digest,
            CompactionBlockTime::new(
                ingest_time,
                AuthenticatedEventRange::unavailable(EventRangeUnavailable::LegacyFormat),
            ),
        )
    }

    /// Creates one compaction input with source-owned authenticated Event Time
    /// evidence copied from the verified committed block.
    pub fn new_with_time(
        scope: SegmentScope,
        source_segment: SegmentId,
        identity: StoreBlockIdentity,
        position: CommitPosition,
        payload: Vec<u8>,
        content_digest: [u8; 32],
        time: CompactionBlockTime,
    ) -> Result<Self, LedgerFailure> {
        if payload.is_empty() || !time.ingest_time.retention_authenticated() {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        Ok(Self {
            scope,
            source_segment,
            identity,
            position,
            payload,
            content_digest,
            ingest_time: time.ingest_time,
            event_range: time.event_range,
        })
    }

    #[must_use]
    pub const fn source_segment(&self) -> SegmentId {
        self.source_segment
    }
}

/// Authenticated lifecycle metadata for a Store Block or its segment aggregate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SegmentRetention {
    Empty,
    Unavailable,
    Complete(IngestTime),
}

impl SegmentRetention {
    pub(super) const fn for_block(ingest_time: Option<IngestTime>) -> Self {
        match ingest_time {
            Some(instant) => Self::Complete(instant),
            None => Self::Unavailable,
        }
    }

    pub(super) fn append_block(self, block: Self) -> Self {
        match (self, block) {
            (Self::Empty, Self::Complete(instant)) => Self::Complete(instant),
            (Self::Complete(previous), Self::Complete(instant)) => {
                Self::Complete(previous.max(instant))
            },
            (Self::Empty | Self::Complete(_), Self::Unavailable)
            | (Self::Unavailable, Self::Complete(_) | Self::Unavailable) => Self::Unavailable,
            (_, Self::Empty) => Self::Unavailable,
        }
    }
}

impl CommittedBlock {
    #[must_use]
    pub const fn identity(&self) -> StoreBlockIdentity {
        self.identity
    }

    #[must_use]
    pub const fn position(&self) -> CommitPosition {
        self.position
    }

    /// Returns the immutable segment that durably contains this block.
    #[must_use]
    pub const fn segment_id(&self) -> SegmentId {
        self.segment
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns producer-owned authenticated Event Time evidence without
    /// decoding the Store Block payload.
    #[must_use]
    pub const fn event_range(&self) -> AuthenticatedEventRange {
        self.event_range
    }

    /// Verifies one encoded record timestamp against this authenticated v3 block.
    pub fn authenticate_ingest_time(
        &self,
        encoded: UnixNanoseconds,
    ) -> Result<IngestTime, LedgerFailure> {
        match self.block_retention {
            SegmentRetention::Complete(expected) if expected.instant() == encoded => Ok(expected),
            SegmentRetention::Complete(_) => {
                Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))
            },
            SegmentRetention::Empty | SegmentRetention::Unavailable => {
                Err(LedgerFailure::new(LedgerFailureCode::UnsupportedFormat))
            },
        }
    }

    /// Observes a record time through this block's format evidence without
    /// granting legacy data retention authority.
    pub fn observe_ingest_time(
        &self,
        encoded: UnixNanoseconds,
    ) -> Result<IngestTime, LedgerFailure> {
        match self.block_retention {
            SegmentRetention::Complete(expected) if expected.instant() == encoded => Ok(expected),
            SegmentRetention::Complete(_) => {
                Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))
            },
            SegmentRetention::Unavailable => Ok(IngestTime::from_unretained_observation(encoded)),
            SegmentRetention::Empty => {
                Err(LedgerFailure::new(LedgerFailureCode::UnsupportedFormat))
            },
        }
    }

    /// Returns the stable digest computed while the payload was admitted.
    pub fn content_digest(&self) -> Result<[u8; 32], LedgerFailure> {
        Ok(self.content_digest)
    }
}

/// A verified immutable view bounded by the published Durability Frontier.
pub struct LedgerSnapshot<'kernel> {
    pub(super) _capacity: ResourceReservation<'kernel>,
    pub(super) _protection: super::snapshot_protection::SnapshotProtection,
    pub(super) scope: SegmentScope,
    pub(super) frontier: CommitPosition,
    pub(super) catalog_generation: u64,
    pub(super) catalog_identity: crate::CatalogGenerationId,
    pub(super) blocks: Vec<CommittedBlock>,
    pub(super) quarantined_holes: Vec<super::IntegrityQuarantineFinding>,
}

impl LedgerSnapshot<'_> {
    /// Returns the authenticated physical tenant, signal, and shard scope.
    #[must_use]
    pub const fn scope(&self) -> SegmentScope {
        self.scope
    }

    #[must_use]
    pub const fn frontier(&self) -> CommitPosition {
        self.frontier
    }

    #[must_use]
    pub const fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }

    #[must_use]
    pub const fn catalog_identity(&self) -> crate::CatalogGenerationId {
        self.catalog_identity
    }

    #[must_use]
    pub fn blocks(&self) -> &[CommittedBlock] {
        &self.blocks
    }

    #[must_use]
    pub fn quarantined_holes(&self) -> &[super::IntegrityQuarantineFinding] {
        &self.quarantined_holes
    }
}

/// The immutable segment publication completed by an explicit seal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealedSegment {
    pub(super) segment: SegmentId,
    pub(super) frontier: CommitPosition,
}

impl SealedSegment {
    #[must_use]
    pub const fn segment_id(self) -> SegmentId {
        self.segment
    }

    #[must_use]
    pub const fn frontier(self) -> CommitPosition {
        self.frontier
    }
}
