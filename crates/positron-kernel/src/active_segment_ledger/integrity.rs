//! Bounded authenticated verification and quarantine for one ledger scope.

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::atomic::{AtomicBool, Ordering};

use sha2::{Digest, Sha256};

use super::{LedgerFailure, LedgerFailureCode, SegmentId, SegmentScope};

#[path = "integrity_quarantine_codec.rs"]
mod integrity_quarantine_codec;
use integrity_quarantine_codec::MAX_QUARANTINE_FINDINGS;
pub(super) use integrity_quarantine_codec::{decode_quarantine, encode_quarantine};

#[path = "integrity_quarantine.rs"]
mod integrity_quarantine;
#[path = "integrity_scrub.rs"]
mod integrity_scrub;
pub use integrity_quarantine::integrity_quarantine_findings;
pub(super) use integrity_quarantine::{publish_quarantine, quarantined_segment_ids};
pub use integrity_scrub::{
    CatalogIntegrityVerificationRequest, IntegrityVerificationRequest, OnlineQuarantinePublication,
};
const CONTINUATION_BYTES: usize = 1 + 7 + 32 + 16;

/// The bounded number of immutable segments one scrub pass may authenticate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntegrityScrubBudget(usize, u64);

impl IntegrityScrubBudget {
    pub const MAX_SEGMENTS: usize = 128;
    /// Reuses the Catalog Writer's established maximum retained-object budget,
    /// so verification cannot exceed the one atomic state publication it may
    /// need to create for a finding.
    pub const MAX_BYTES: u64 = crate::catalog::MAX_CATALOG_TOTAL_BYTES as u64;

    pub fn new(segments: usize) -> Result<Self, IntegrityFailureCode> {
        if segments == 0 || segments > Self::MAX_SEGMENTS {
            return Err(IntegrityFailureCode::InvalidInput);
        }
        Ok(Self(segments, Self::MAX_BYTES))
    }
    pub fn with_bytes(segments: usize, bytes: u64) -> Result<Self, IntegrityFailureCode> {
        if segments == 0 || segments > Self::MAX_SEGMENTS || bytes == 0 || bytes > Self::MAX_BYTES {
            return Err(IntegrityFailureCode::InvalidInput);
        }
        Ok(Self(segments, bytes))
    }
}

/// Cancellation handle checked between immutable objects.
#[derive(Clone, Default)]
pub struct IntegrityCancellation(std::sync::Arc<AtomicBool>);

/// Kernel-owned cancellation seam for one bounded verification pass. Runtime
/// task lifecycles adapt their cancellation handle here without giving the
/// storage kernel a dependency on runtime types.
pub trait IntegrityCancellationProbe {
    fn is_cancelled(&self) -> bool;
}

impl IntegrityCancellation {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

impl IntegrityCancellationProbe for IntegrityCancellation {
    fn is_cancelled(&self) -> bool {
        self.is_cancelled()
    }
}

/// How an integrity pass is being used. Online scans never mutate source bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrityVerificationMode {
    Startup,
    Online,
    Offline,
}

/// The exact object class a report covers. A successful report never claims
/// verification of a different scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrityVerificationScope {
    StartupFrontiers,
    ReachableImmutableSegments,
    ReachableDurableSegments,
}

/// The terminal truth of one bounded verification pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrityVerificationOutcome {
    Verified,
    Incomplete,
    Stale,
    Quarantined,
    Fenced,
}

/// One durable, authenticated quarantine finding for an authorized inspection
/// surface. Time ranges are absent when integrity damage prevents authenticated
/// recovery; base position identifies the sealed commit scope without inventing
/// a time value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntegrityQuarantineFinding {
    scope: SegmentScope,
    segment: SegmentId,
    abandoned: bool,
    base_position: u64,
    sealed_frontier: positron_domain::routing::CommitPosition,
    event_range: super::AuthenticatedEventRange,
    ingest_range: super::AuthenticatedIngestRange,
}

impl IntegrityQuarantineFinding {
    /// Encodes only authenticated identity and loss ranges, without telemetry.
    pub fn encode_evidence(self) -> Result<Vec<u8>, IntegrityFailure> {
        encode_quarantine(super::format::SegmentMetadata {
            scope: self.scope,
            id: self.segment,
            state: super::format::SegmentState::Sealed,
            base_position: super::format::position_from_value(self.base_position)
                .map_err(map_ledger_failure)?,
            sealed_frontier: Some(self.sealed_frontier),
            event_range: self.event_range,
            ingest_range: self.ingest_range,
        })
    }
    /// Decodes the bounded evidence carried by an authenticated audit record.
    pub fn decode_evidence(bytes: &[u8]) -> Result<Self, IntegrityFailure> {
        let (scope, segment, base_position, sealed_frontier, event_range, ingest_range) =
            decode_quarantine(bytes)?
                .ok_or(IntegrityFailure(IntegrityFailureCode::InvalidInput))?;
        Ok(Self {
            scope,
            segment,
            base_position,
            sealed_frontier,
            event_range,
            ingest_range,
            abandoned: bytes.starts_with(super::abandonment::ABANDONMENT_MAGIC),
        })
    }

    #[must_use]
    pub const fn is_abandoned(self) -> bool {
        self.abandoned
    }
    #[must_use]
    pub const fn scope(self) -> SegmentScope {
        self.scope
    }
    #[must_use]
    pub const fn segment(self) -> SegmentId {
        self.segment
    }
    #[must_use]
    pub const fn base_position(self) -> u64 {
        self.base_position
    }
    #[must_use]
    pub const fn sealed_frontier(self) -> positron_domain::routing::CommitPosition {
        self.sealed_frontier
    }
    #[must_use]
    pub const fn event_range(self) -> super::AuthenticatedEventRange {
        self.event_range
    }
    #[must_use]
    pub const fn ingest_range(self) -> super::AuthenticatedIngestRange {
        self.ingest_range
    }
}

/// A bounded, secret-free finding carried by a verification report. The
/// authenticated Catalog retains the matching quarantine only for localized
/// immutable damage; ambiguous findings never imply a repair or quarantine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrityFinding {
    LocalizedImmutableCorruption(SegmentId),
    AmbiguousIntegrity,
    SourceChanged,
}

/// A catalog-generation-bound scrub position. It contains no keys, payloads,
/// or tenant identifiers and is intended only for a maintenance checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntegrityScrubContinuation {
    source_identity: [u8; 32],
    last_segment: SegmentId,
}

impl IntegrityScrubContinuation {
    /// A scope has at most one cursor-producing pass per retained segment.
    /// This bound keeps a runtime's authenticated publication lineage finite.
    pub const MAX_PASSES: usize = super::storage::MAX_SEGMENTS;

    #[must_use]
    pub const fn source_identity(self) -> [u8; 32] {
        self.source_identity
    }

    /// Serializes the fixed-size, versioned checkpoint payload.
    #[must_use]
    pub fn encode(self) -> [u8; CONTINUATION_BYTES] {
        let mut bytes = [0_u8; CONTINUATION_BYTES];
        bytes[0] = 1;
        bytes[8..40].copy_from_slice(&self.source_identity);
        bytes[40..].copy_from_slice(&self.last_segment.to_bytes());
        bytes
    }

    /// Decodes one maintenance checkpoint. Unknown versions never resume a
    /// scrub against an assumed source generation.
    pub fn decode(bytes: &[u8]) -> Result<Self, IntegrityFailureCode> {
        if bytes.len() != CONTINUATION_BYTES || bytes.first().copied() != Some(1) {
            return Err(IntegrityFailureCode::InvalidInput);
        }
        let source_identity = bytes
            .get(8..40)
            .and_then(|value| value.try_into().ok())
            .ok_or(IntegrityFailureCode::InvalidInput)?;
        let id = bytes
            .get(40..)
            .and_then(|value| value.try_into().ok())
            .and_then(|value| SegmentId::new(value).ok())
            .ok_or(IntegrityFailureCode::InvalidInput)?;
        Ok(Self {
            source_identity,
            last_segment: id,
        })
    }
}

/// A secret-free, machine-readable verification result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntegrityVerificationReport {
    mode: IntegrityVerificationMode,
    verification_scope: IntegrityVerificationScope,
    scope: SegmentScope,
    catalog_generation: u64,
    examined_segments: usize,
    examined_bytes: u64,
    omitted_segments: usize,
    outcome: IntegrityVerificationOutcome,
    quarantined_segment: Option<SegmentId>,
    localized_finding: Option<IntegrityQuarantineFinding>,
    continuation: Option<IntegrityScrubContinuation>,
}

impl IntegrityVerificationReport {
    #[must_use]
    pub const fn mode(self) -> IntegrityVerificationMode {
        self.mode
    }
    #[must_use]
    pub const fn verification_scope(self) -> IntegrityVerificationScope {
        self.verification_scope
    }
    #[must_use]
    pub const fn scope(self) -> SegmentScope {
        self.scope
    }
    #[must_use]
    pub const fn catalog_generation(self) -> u64 {
        self.catalog_generation
    }
    #[must_use]
    pub const fn examined_segments(self) -> usize {
        self.examined_segments
    }
    #[must_use]
    pub const fn examined_bytes(self) -> u64 {
        self.examined_bytes
    }
    #[must_use]
    pub const fn omitted_segments(self) -> usize {
        self.omitted_segments
    }
    #[must_use]
    pub const fn outcome(self) -> IntegrityVerificationOutcome {
        self.outcome
    }
    #[must_use]
    pub const fn quarantined_segment(self) -> Option<SegmentId> {
        self.quarantined_segment
    }
    /// Read-only localized evidence from the exact authenticated Catalog
    /// snapshot scanned by this pass. Its presence never claims that an
    /// offline inspection published a durable quarantine.
    #[must_use]
    pub const fn localized_finding(self) -> Option<IntegrityQuarantineFinding> {
        self.localized_finding
    }
    pub(super) const fn with_localized_finding(
        mut self,
        finding: IntegrityQuarantineFinding,
    ) -> Self {
        self.localized_finding = Some(finding);
        self
    }
    #[must_use]
    pub fn finding(self) -> Option<IntegrityFinding> {
        match self.outcome {
            IntegrityVerificationOutcome::Quarantined => self
                .quarantined_segment
                .map(IntegrityFinding::LocalizedImmutableCorruption),
            IntegrityVerificationOutcome::Fenced => Some(IntegrityFinding::AmbiguousIntegrity),
            IntegrityVerificationOutcome::Stale => Some(IntegrityFinding::SourceChanged),
            IntegrityVerificationOutcome::Verified | IntegrityVerificationOutcome::Incomplete => {
                None
            },
        }
    }
    #[must_use]
    pub const fn continuation(self) -> Option<IntegrityScrubContinuation> {
        self.continuation
    }
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self.outcome, IntegrityVerificationOutcome::Verified)
    }

    /// SHA-256 over the fixed-version canonical report account. The digest
    /// covers every terminal fact exposed by the kernel report and contains no
    /// key, payload, or filesystem material.
    #[must_use]
    pub fn checksum(self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"positron/integrity-verification-report/v1");
        digest.update([verification_mode_code(self.mode)]);
        digest.update([verification_scope_code(self.verification_scope)]);
        digest.update(self.scope.tenant_id().to_bytes());
        digest.update([match self.scope.signal_kind() {
            positron_domain::routing::SignalKind::Logs => 1,
            positron_domain::routing::SignalKind::Traces => 2,
        }]);
        digest.update(self.scope.shard_id().value().to_be_bytes());
        digest.update(self.catalog_generation.to_be_bytes());
        digest.update(
            u64::try_from(self.examined_segments)
                .map_or(u64::MAX, |value| value)
                .to_be_bytes(),
        );
        digest.update(self.examined_bytes.to_be_bytes());
        digest.update(
            u64::try_from(self.omitted_segments)
                .map_or(u64::MAX, |value| value)
                .to_be_bytes(),
        );
        digest.update([verification_outcome_code(self.outcome)]);
        match self.quarantined_segment {
            Some(segment) => {
                digest.update([1]);
                digest.update(segment.to_bytes());
            },
            None => digest.update([0]),
        }
        match self.localized_finding {
            Some(finding) => {
                digest.update([1]);
                digest.update(finding.scope().tenant_id().to_bytes());
                digest.update([match finding.scope().signal_kind() {
                    positron_domain::routing::SignalKind::Logs => 1,
                    positron_domain::routing::SignalKind::Traces => 2,
                }]);
                digest.update(finding.scope().shard_id().value().to_be_bytes());
                digest.update(finding.segment().to_bytes());
                digest.update(finding.base_position().to_be_bytes());
                digest.update(finding.sealed_frontier().value().to_be_bytes());
                update_event_range_checksum(&mut digest, finding.event_range());
                update_ingest_range_checksum(&mut digest, finding.ingest_range());
            },
            None => digest.update([0]),
        }
        match self.continuation {
            Some(continuation) => {
                digest.update([1]);
                digest.update(continuation.encode());
            },
            None => digest.update([0]),
        }
        digest.finalize().into()
    }
}

fn update_event_range_checksum(digest: &mut Sha256, range: super::AuthenticatedEventRange) {
    match range {
        super::AuthenticatedEventRange::Known { earliest, latest } => {
            digest.update([1]);
            digest.update(earliest.value().to_be_bytes());
            digest.update(latest.value().to_be_bytes());
        },
        super::AuthenticatedEventRange::Unavailable(reason) => {
            digest.update([2]);
            digest.update([match reason {
                super::EventRangeUnavailable::MissingSourceTime => 1,
                super::EventRangeUnavailable::InvalidSourceTime => 2,
                super::EventRangeUnavailable::LegacyFormat => 3,
            }]);
        },
    }
}

fn update_ingest_range_checksum(digest: &mut Sha256, range: super::AuthenticatedIngestRange) {
    match range {
        super::AuthenticatedIngestRange::Known { earliest, latest } => {
            digest.update([1]);
            digest.update(earliest.value().to_be_bytes());
            digest.update(latest.value().to_be_bytes());
        },
        super::AuthenticatedIngestRange::Unavailable => digest.update([2]),
    }
}

const fn verification_mode_code(mode: IntegrityVerificationMode) -> u8 {
    match mode {
        IntegrityVerificationMode::Startup => 1,
        IntegrityVerificationMode::Online => 2,
        IntegrityVerificationMode::Offline => 3,
    }
}

const fn verification_scope_code(scope: IntegrityVerificationScope) -> u8 {
    match scope {
        IntegrityVerificationScope::StartupFrontiers => 1,
        IntegrityVerificationScope::ReachableImmutableSegments => 2,
        IntegrityVerificationScope::ReachableDurableSegments => 3,
    }
}

const fn verification_outcome_code(outcome: IntegrityVerificationOutcome) -> u8 {
    match outcome {
        IntegrityVerificationOutcome::Verified => 1,
        IntegrityVerificationOutcome::Incomplete => 2,
        IntegrityVerificationOutcome::Stale => 3,
        IntegrityVerificationOutcome::Quarantined => 4,
        IntegrityVerificationOutcome::Fenced => 5,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrityFailureCode {
    DurabilityFrontierAmbiguity,
    InvalidInput,
    Cancelled,
    StorageUnavailable,
    AmbiguousIntegrity,
    FindingCapacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntegrityFailure(pub(in crate::active_segment_ledger) IntegrityFailureCode);

impl IntegrityFailure {
    #[must_use]
    pub const fn code(self) -> IntegrityFailureCode {
        self.0
    }
}
impl Display for IntegrityFailure {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("integrity verification failed")
    }
}
impl Error for IntegrityFailure {}

// Authentication failure can mean a missing or mismatched key envelope, which
// is instance-wide ambiguity. Only structural damage that the storage layer
// has already localized to this immutable object is eligible for quarantine.
pub(super) fn is_isolated_corruption(code: LedgerFailureCode) -> bool {
    matches!(
        code,
        LedgerFailureCode::IntegrityCorruption
            | LedgerFailureCode::DurabilityFrontierAmbiguity
            | LedgerFailureCode::UnsupportedFormat
    )
}

pub(super) fn map_ledger_failure(failure: LedgerFailure) -> IntegrityFailure {
    IntegrityFailure(match failure.code() {
        LedgerFailureCode::DurabilityFrontierAmbiguity => {
            IntegrityFailureCode::DurabilityFrontierAmbiguity
        },
        LedgerFailureCode::Cancelled => IntegrityFailureCode::Cancelled,
        LedgerFailureCode::StorageUnavailable | LedgerFailureCode::StorageExhausted => {
            IntegrityFailureCode::StorageUnavailable
        },
        _ => IntegrityFailureCode::AmbiguousIntegrity,
    })
}

pub(super) fn map_catalog_failure(_failure: crate::CatalogFailure) -> IntegrityFailure {
    IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity)
}

pub(super) fn can_localize_quarantine(metadata: super::format::SegmentMetadata) -> bool {
    metadata
        .sealed_frontier
        .is_some_and(|frontier| frontier >= metadata.base_position)
        && matches!(
            metadata.ingest_range,
            super::AuthenticatedIngestRange::Known { .. }
        )
}

pub(super) fn localized_finding(
    scope: SegmentScope,
    metadata: super::format::SegmentMetadata,
) -> Option<IntegrityQuarantineFinding> {
    Some(IntegrityQuarantineFinding {
        abandoned: false,
        scope,
        segment: metadata.id,
        base_position: metadata.base_position.value(),
        sealed_frontier: metadata.sealed_frontier?,
        event_range: metadata.event_range,
        ingest_range: metadata.ingest_range,
    })
}

#[cfg(fuzzing)]
pub(super) fn fuzz_quarantine_record(data: &[u8]) {
    // The record is catalog-authenticated in production; fuzzing still proves
    // malformed retained evidence cannot panic or manufacture a valid scope.
    let Ok(Some(record)) = decode_quarantine(data) else {
        return;
    };
    let (scope, id, base_position, sealed_frontier, event_range, ingest_range) = record;
    let metadata = super::format::SegmentMetadata {
        scope,
        id,
        state: super::format::SegmentState::Sealed,
        base_position: super::format::position_from_value(base_position)
            .expect("decoded quarantine position is representable"),
        sealed_frontier: Some(sealed_frontier),
        event_range,
        ingest_range,
    };
    let encoded = encode_quarantine(metadata).expect("decoded quarantine record encodes");
    assert_eq!(
        encoded,
        data.strip_prefix(super::abandonment::ABANDONMENT_MAGIC)
            .unwrap_or(data)
    );
    assert_eq!(decode_quarantine(&encoded), Ok(Some(record)));
}
