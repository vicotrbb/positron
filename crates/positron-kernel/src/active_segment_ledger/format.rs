use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, SignalKind, VirtualShardId};

use super::{
    AuthenticatedEventRange, AuthenticatedIngestRange, EventRangeUnavailable, LedgerFailure,
    LedgerFailureCode, SegmentId, SegmentKeyRoute, SegmentScope,
};

const METADATA_MAGIC: &[u8; 8] = b"PSEGMET1";
const SEGMENT_MAGIC: &[u8; 8] = b"PSEGACT3";
const METADATA_VERSION: u16 = 2;
const SEGMENT_VERSION: u16 = 2;
const METADATA_V1_BYTES: usize = 8 + 2 + 1 + 16 + 1 + 4 + 16 + 8;
pub(super) const METADATA_BYTES: usize = METADATA_V1_BYTES + 17 + 17 + 1 + 8;
const FRAME_ALGORITHM_AES_256_GCM: u16 = 1;
const WRAPPING_ALGORITHM_AES_256_KWP: u16 = 1;
pub(super) const HEADER_PREFIX_BYTES: usize = 8 + 2 + 2 + 2 + 2 + 16 + 8 + 4;
const MAX_WRAPPED_KEY_BYTES: usize = 256;
const MAX_ENCRYPTED_METADATA_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SegmentState {
    Active,
    Sealed,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SegmentMetadata {
    pub(super) scope: SegmentScope,
    pub(super) id: SegmentId,
    pub(super) state: SegmentState,
    pub(super) base_position: CommitPosition,
    /// The authenticated final commit position for an immutable segment.
    ///
    /// Legacy records deliberately leave this absent.  They can be recovered
    /// normally, but cannot authorize skipping a quarantined continuity gap.
    pub(super) sealed_frontier: Option<CommitPosition>,
    pub(super) event_range: AuthenticatedEventRange,
    pub(super) ingest_range: AuthenticatedIngestRange,
}

pub(super) struct SegmentHeader<'a> {
    pub(super) route: SegmentKeyRoute,
    pub(super) wrapped_key: &'a [u8],
    pub(super) encrypted_metadata: &'a [u8],
    pub(super) encoded_bytes: usize,
}

pub(super) fn encode_metadata(metadata: SegmentMetadata) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(METADATA_BYTES);
    bytes.extend_from_slice(METADATA_MAGIC);
    bytes.extend_from_slice(&METADATA_VERSION.to_be_bytes());
    bytes.push(match metadata.state {
        SegmentState::Active => 1,
        SegmentState::Sealed => 2,
        SegmentState::Retired => 3,
    });
    bytes.extend_from_slice(&metadata.scope.tenant.to_bytes());
    bytes.push(match metadata.scope.signal {
        SignalKind::Logs => 1,
        SignalKind::Traces => 2,
    });
    bytes.extend_from_slice(&metadata.scope.shard.value().to_be_bytes());
    bytes.extend_from_slice(&metadata.id.to_bytes());
    bytes.extend_from_slice(&metadata.base_position.value().to_be_bytes());
    encode_event_range(&mut bytes, metadata.event_range);
    encode_ingest_range(&mut bytes, metadata.ingest_range);
    encode_sealed_frontier(&mut bytes, metadata.sealed_frontier);
    bytes
}

pub(super) fn decode_metadata(bytes: &[u8]) -> Result<Option<SegmentMetadata>, LedgerFailure> {
    if !bytes.starts_with(METADATA_MAGIC) {
        return Ok(None);
    }
    let version = u16::from_be_bytes(
        bytes
            .get(8..10)
            .and_then(|value| value.try_into().ok())
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::UnsupportedFormat))?,
    );
    if !matches!(version, 1..=METADATA_VERSION)
        || bytes.len()
            != match version {
                1 => METADATA_V1_BYTES,
                2 => METADATA_BYTES,
                _ => return Err(LedgerFailure::new(LedgerFailureCode::UnsupportedFormat)),
            }
    {
        return Err(LedgerFailure::new(LedgerFailureCode::UnsupportedFormat));
    }
    let state = match bytes.get(10).copied() {
        Some(1) => SegmentState::Active,
        Some(2) => SegmentState::Sealed,
        Some(3) => SegmentState::Retired,
        _ => return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption)),
    };
    let tenant: [u8; 16] = exact(bytes, 11, 16)?;
    let signal = match bytes.get(27).copied() {
        Some(1) => SignalKind::Logs,
        Some(2) => SignalKind::Traces,
        _ => return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption)),
    };
    let shard = u32::from_be_bytes(exact(bytes, 28, 4)?);
    let id = SegmentId::new(exact(bytes, 32, 16)?)?;
    let base = u64::from_be_bytes(exact(bytes, 48, 8)?);
    let event_range = if version >= 2 {
        decode_event_range(bytes, METADATA_V1_BYTES)?
    } else {
        AuthenticatedEventRange::unavailable(EventRangeUnavailable::LegacyFormat)
    };
    let ingest_range = if version >= 2 {
        decode_ingest_range(bytes, METADATA_V1_BYTES + 17)?
    } else {
        AuthenticatedIngestRange::unavailable()
    };
    let sealed_frontier = if version == 2 {
        decode_sealed_frontier(bytes, METADATA_V1_BYTES + 17 + 17)?
    } else {
        None
    };
    if matches!(state, SegmentState::Active) && sealed_frontier.is_some() {
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    Ok(Some(SegmentMetadata {
        scope: SegmentScope::new(
            TenantId::from_bytes(tenant)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?,
            signal,
            VirtualShardId::new(shard)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?,
        ),
        id,
        state,
        base_position: position_from_value(base)?,
        sealed_frontier,
        event_range,
        ingest_range,
    }))
}

fn encode_sealed_frontier(bytes: &mut Vec<u8>, frontier: Option<CommitPosition>) {
    match frontier {
        Some(frontier) => {
            bytes.push(1);
            bytes.extend_from_slice(&frontier.value().to_be_bytes());
        },
        None => bytes.extend_from_slice(&[0; 9]),
    }
}

fn decode_sealed_frontier(
    bytes: &[u8],
    offset: usize,
) -> Result<Option<CommitPosition>, LedgerFailure> {
    let value = u64::from_be_bytes(exact(bytes, offset + 1, 8)?);
    match bytes.get(offset).copied() {
        Some(0) if value == 0 => Ok(None),
        Some(1) => position_from_value(value).map(Some),
        _ => Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption)),
    }
}

fn encode_event_range(bytes: &mut Vec<u8>, range: AuthenticatedEventRange) {
    match range {
        AuthenticatedEventRange::Known { earliest, latest } => {
            bytes.push(1);
            bytes.extend_from_slice(&earliest.value().to_be_bytes());
            bytes.extend_from_slice(&latest.value().to_be_bytes());
        },
        AuthenticatedEventRange::Unavailable(EventRangeUnavailable::MissingSourceTime) => {
            bytes.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        },
        AuthenticatedEventRange::Unavailable(EventRangeUnavailable::InvalidSourceTime) => {
            bytes.extend_from_slice(&[3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        },
        AuthenticatedEventRange::Unavailable(EventRangeUnavailable::LegacyFormat) => {
            bytes.extend_from_slice(&[4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        },
    }
}

fn encode_ingest_range(bytes: &mut Vec<u8>, range: AuthenticatedIngestRange) {
    match range {
        AuthenticatedIngestRange::Known { earliest, latest } => {
            bytes.push(1);
            bytes.extend_from_slice(&earliest.value().to_be_bytes());
            bytes.extend_from_slice(&latest.value().to_be_bytes());
        },
        AuthenticatedIngestRange::Unavailable => {
            bytes.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        },
    }
}

fn decode_event_range(
    bytes: &[u8],
    offset: usize,
) -> Result<AuthenticatedEventRange, LedgerFailure> {
    let earliest = i64::from_be_bytes(exact(bytes, offset + 1, 8)?);
    let latest = i64::from_be_bytes(exact(bytes, offset + 9, 8)?);
    match bytes.get(offset).copied() {
        Some(1) => AuthenticatedEventRange::known(
            positron_domain::time::UnixNanoseconds::new(earliest),
            positron_domain::time::UnixNanoseconds::new(latest),
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption)),
        Some(2) if earliest == 0 && latest == 0 => Ok(AuthenticatedEventRange::unavailable(
            EventRangeUnavailable::MissingSourceTime,
        )),
        Some(3) if earliest == 0 && latest == 0 => Ok(AuthenticatedEventRange::unavailable(
            EventRangeUnavailable::InvalidSourceTime,
        )),
        Some(4) if earliest == 0 && latest == 0 => Ok(AuthenticatedEventRange::unavailable(
            EventRangeUnavailable::LegacyFormat,
        )),
        _ => Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption)),
    }
}

fn decode_ingest_range(
    bytes: &[u8],
    offset: usize,
) -> Result<AuthenticatedIngestRange, LedgerFailure> {
    let earliest = i64::from_be_bytes(exact(bytes, offset + 1, 8)?);
    let latest = i64::from_be_bytes(exact(bytes, offset + 9, 8)?);
    match bytes.get(offset).copied() {
        Some(1) if earliest <= latest => Ok(AuthenticatedIngestRange::Known {
            earliest: positron_domain::time::UnixNanoseconds::new(earliest),
            latest: positron_domain::time::UnixNanoseconds::new(latest),
        }),
        Some(2) if earliest == 0 && latest == 0 => Ok(AuthenticatedIngestRange::Unavailable),
        _ => Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption)),
    }
}

pub(super) fn encode_header(
    route: SegmentKeyRoute,
    wrapped_key: &[u8],
    encrypted_metadata: &[u8],
) -> Result<Vec<u8>, LedgerFailure> {
    if wrapped_key.is_empty()
        || wrapped_key.len() > MAX_WRAPPED_KEY_BYTES
        || encrypted_metadata.is_empty()
        || encrypted_metadata.len() > MAX_ENCRYPTED_METADATA_BYTES
    {
        return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
    }
    let wrapped_length = u32::try_from(wrapped_key.len())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let metadata_length = u32::try_from(encrypted_metadata.len())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let mut bytes =
        Vec::with_capacity(HEADER_PREFIX_BYTES + wrapped_key.len() + 4 + encrypted_metadata.len());
    bytes.extend_from_slice(SEGMENT_MAGIC);
    bytes.extend_from_slice(&SEGMENT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&FRAME_ALGORITHM_AES_256_GCM.to_be_bytes());
    bytes.extend_from_slice(&WRAPPING_ALGORITHM_AES_256_KWP.to_be_bytes());
    bytes.extend_from_slice(&route.provider_family.to_be_bytes());
    bytes.extend_from_slice(&route.provider_reference);
    bytes.extend_from_slice(&route.provider_key_epoch.to_be_bytes());
    bytes.extend_from_slice(&wrapped_length.to_be_bytes());
    bytes.extend_from_slice(wrapped_key);
    bytes.extend_from_slice(&metadata_length.to_be_bytes());
    bytes.extend_from_slice(encrypted_metadata);
    Ok(bytes)
}

pub(super) fn decode_header(bytes: &[u8]) -> Result<SegmentHeader<'_>, LedgerFailure> {
    if bytes.get(..8) != Some(SEGMENT_MAGIC.as_slice())
        || bytes.get(8..10) != Some(SEGMENT_VERSION.to_be_bytes().as_slice())
    {
        return Err(LedgerFailure::new(LedgerFailureCode::UnsupportedFormat));
    }
    if bytes.get(10..12) != Some(FRAME_ALGORITHM_AES_256_GCM.to_be_bytes().as_slice())
        || bytes.get(12..14) != Some(WRAPPING_ALGORITHM_AES_256_KWP.to_be_bytes().as_slice())
    {
        return Err(LedgerFailure::new(LedgerFailureCode::UnsupportedFormat));
    }
    let provider_family = u16::from_be_bytes(exact(bytes, 14, 2)?);
    let provider_reference = exact(bytes, 16, 16)?;
    let provider_key_epoch = u64::from_be_bytes(exact(bytes, 32, 8)?);
    if provider_family == 0
        || provider_reference.iter().all(|byte| *byte == 0)
        || provider_key_epoch == 0
    {
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    let wrapped_length = usize::try_from(u32::from_be_bytes(exact(bytes, 40, 4)?))
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    if wrapped_length == 0 || wrapped_length > MAX_WRAPPED_KEY_BYTES {
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    let metadata_length_offset = HEADER_PREFIX_BYTES
        .checked_add(wrapped_length)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let metadata_offset = metadata_length_offset
        .checked_add(4)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let metadata_length =
        usize::try_from(u32::from_be_bytes(exact(bytes, metadata_length_offset, 4)?))
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    if metadata_length == 0 || metadata_length > MAX_ENCRYPTED_METADATA_BYTES {
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    let encoded_bytes = metadata_offset
        .checked_add(metadata_length)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let wrapped_key = bytes
        .get(HEADER_PREFIX_BYTES..metadata_length_offset)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
    let encrypted_metadata = bytes
        .get(metadata_offset..encoded_bytes)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
    Ok(SegmentHeader {
        route: SegmentKeyRoute {
            provider_family,
            provider_reference,
            provider_key_epoch,
        },
        wrapped_key,
        encrypted_metadata,
        encoded_bytes,
    })
}

pub(super) fn position_from_value(value: u64) -> Result<CommitPosition, LedgerFailure> {
    if value == 0 {
        return Ok(CommitPosition::origin());
    }
    CommitPosition::origin()
        .advance_by(
            std::num::NonZeroU64::new(value)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?,
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))
}

fn exact<const N: usize>(
    bytes: &[u8],
    start: usize,
    length: usize,
) -> Result<[u8; N], LedgerFailure> {
    let end = start
        .checked_add(length)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    bytes
        .get(start..end)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))
}
