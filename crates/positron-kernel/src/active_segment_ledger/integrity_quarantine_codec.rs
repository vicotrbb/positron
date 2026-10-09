//! Bounded PQUAR2 evidence codec for quarantined sealed segments.

use super::super::format::{self, encode_event_range, encode_ingest_range};
use super::super::{AuthenticatedEventRange, AuthenticatedIngestRange, EventRangeUnavailable};
use super::{IntegrityFailure, IntegrityFailureCode, SegmentId, SegmentScope};

const QUARANTINE_V2_MAGIC: &[u8; 8] = b"PQUAR002";
const QUARANTINE_V1_BYTES: usize = 8 + 16 + 1 + 4 + 16 + 8;
const QUARANTINE_BYTES: usize = QUARANTINE_V1_BYTES + 8 + 17 + 17;
/// Retained findings share this Catalog-wide cap. A full retention set fences
/// later local damage rather than allowing unbounded authenticated evidence.
pub(super) const MAX_QUARANTINE_FINDINGS: usize = 64;

pub(in crate::active_segment_ledger) type QuarantineRecord = (
    SegmentScope,
    SegmentId,
    u64,
    positron_domain::routing::CommitPosition,
    AuthenticatedEventRange,
    AuthenticatedIngestRange,
);

pub(in crate::active_segment_ledger) fn encode_quarantine(
    metadata: format::SegmentMetadata,
) -> Result<Vec<u8>, IntegrityFailure> {
    let sealed_frontier = metadata
        .sealed_frontier
        .ok_or(IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity))?;
    let mut bytes = Vec::with_capacity(QUARANTINE_BYTES);
    bytes.extend_from_slice(QUARANTINE_V2_MAGIC);
    bytes.extend_from_slice(&metadata.scope.tenant.to_bytes());
    bytes.push(match metadata.scope.signal {
        positron_domain::routing::SignalKind::Logs => 1,
        positron_domain::routing::SignalKind::Traces => 2,
    });
    bytes.extend_from_slice(&metadata.scope.shard.value().to_be_bytes());
    bytes.extend_from_slice(&metadata.id.to_bytes());
    bytes.extend_from_slice(&metadata.base_position.value().to_be_bytes());
    bytes.extend_from_slice(&sealed_frontier.value().to_be_bytes());
    encode_event_range(&mut bytes, metadata.event_range);
    encode_ingest_range(&mut bytes, metadata.ingest_range);
    Ok(bytes)
}

pub(in crate::active_segment_ledger) fn decode_quarantine(
    bytes: &[u8],
) -> Result<Option<QuarantineRecord>, IntegrityFailure> {
    let abandoned = bytes.starts_with(super::super::abandonment::ABANDONMENT_MAGIC);
    let bytes = bytes
        .strip_prefix(super::super::abandonment::ABANDONMENT_MAGIC)
        .unwrap_or(bytes);
    if !bytes.starts_with(QUARANTINE_V2_MAGIC) {
        return if abandoned {
            Err(IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity))
        } else {
            Ok(None)
        };
    }
    if bytes.len() != QUARANTINE_BYTES {
        return Err(IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity));
    }
    let tenant = bytes
        .get(8..24)
        .and_then(|value| value.try_into().ok())
        .ok_or(IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity))?;
    let signal = match bytes.get(24).copied() {
        Some(1) => positron_domain::routing::SignalKind::Logs,
        Some(2) => positron_domain::routing::SignalKind::Traces,
        _ => return Err(IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity)),
    };
    let shard = bytes
        .get(25..29)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or(IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity))?;
    let id = bytes
        .get(29..45)
        .and_then(|value| value.try_into().ok())
        .and_then(|value| SegmentId::new(value).ok())
        .ok_or(IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity))?;
    let base_position = bytes
        .get(45..53)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_be_bytes)
        .ok_or(IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity))?;
    let tenant = positron_domain::identity::TenantId::from_bytes(tenant)
        .map_err(|_| IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity))?;
    let shard = positron_domain::routing::VirtualShardId::new(shard)
        .map_err(|_| IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity))?;
    let sealed_frontier = format::position_from_value(
        bytes
            .get(53..61)
            .and_then(|value| value.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or(IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity))?,
    )
    .map_err(|_| IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity))?;
    if sealed_frontier.value() < base_position {
        return Err(IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity));
    }
    let event_range = decode_event_range(bytes, QUARANTINE_V1_BYTES + 8)?;
    let ingest_range = decode_ingest_range(bytes, QUARANTINE_V1_BYTES + 8 + 17)?;
    Ok(Some((
        SegmentScope::new(tenant, signal, shard),
        id,
        base_position,
        sealed_frontier,
        event_range,
        ingest_range,
    )))
}

fn decode_event_range(
    bytes: &[u8],
    offset: usize,
) -> Result<AuthenticatedEventRange, IntegrityFailure> {
    let earliest = i64::from_be_bytes(read_exact(bytes, offset + 1)?);
    let latest = i64::from_be_bytes(read_exact(bytes, offset + 9)?);
    match bytes.get(offset).copied() {
        Some(1) => AuthenticatedEventRange::known(
            positron_domain::time::UnixNanoseconds::new(earliest),
            positron_domain::time::UnixNanoseconds::new(latest),
        )
        .map_err(|_| IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity)),
        Some(2) if earliest == 0 && latest == 0 => Ok(AuthenticatedEventRange::unavailable(
            EventRangeUnavailable::MissingSourceTime,
        )),
        Some(3) if earliest == 0 && latest == 0 => Ok(AuthenticatedEventRange::unavailable(
            EventRangeUnavailable::InvalidSourceTime,
        )),
        Some(4) if earliest == 0 && latest == 0 => Ok(AuthenticatedEventRange::unavailable(
            EventRangeUnavailable::LegacyFormat,
        )),
        _ => Err(IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity)),
    }
}

fn decode_ingest_range(
    bytes: &[u8],
    offset: usize,
) -> Result<AuthenticatedIngestRange, IntegrityFailure> {
    let earliest = i64::from_be_bytes(read_exact(bytes, offset + 1)?);
    let latest = i64::from_be_bytes(read_exact(bytes, offset + 9)?);
    match bytes.get(offset).copied() {
        Some(1) if earliest <= latest => Ok(AuthenticatedIngestRange::Known {
            earliest: positron_domain::time::UnixNanoseconds::new(earliest),
            latest: positron_domain::time::UnixNanoseconds::new(latest),
        }),
        Some(2) if earliest == 0 && latest == 0 => Ok(AuthenticatedIngestRange::Unavailable),
        _ => Err(IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity)),
    }
}

fn read_exact<const LENGTH: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; LENGTH], IntegrityFailure> {
    bytes
        .get(offset..offset.saturating_add(LENGTH))
        .and_then(|value| value.try_into().ok())
        .ok_or(IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity))
}
