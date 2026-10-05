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
const CONTINUATION_BYTES: usize = 1 + 7 + 32 + 16;

/// The bounded number of immutable segments one scrub pass may authenticate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntegrityScrubBudget(usize);

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
        Ok(Self(segments))
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
    base_position: u64,
    sealed_frontier: positron_domain::routing::CommitPosition,
    event_range: super::AuthenticatedEventRange,
    ingest_range: super::AuthenticatedIngestRange,
}

impl IntegrityQuarantineFinding {
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
    InvalidInput,
    Cancelled,
    StorageUnavailable,
    AmbiguousIntegrity,
    FindingCapacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntegrityFailure(IntegrityFailureCode);

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
        LedgerFailureCode::IntegrityCorruption | LedgerFailureCode::UnsupportedFormat
    )
}

pub(super) fn map_ledger_failure(failure: LedgerFailure) -> IntegrityFailure {
    IntegrityFailure(match failure.code() {
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
            metadata.event_range,
            super::AuthenticatedEventRange::Known { .. }
        )
        && matches!(
            metadata.ingest_range,
            super::AuthenticatedIngestRange::Known { .. }
        )
}

#[cfg(fuzzing)]
pub(super) fn fuzz_quarantine_record(data: &[u8]) {
    // The record is catalog-authenticated in production; fuzzing still proves
    // malformed retained evidence cannot panic or manufacture a valid scope.
    let _ = decode_quarantine(data);
}
