//! Additive envelopes in the authenticated Catalog preserve immutable segment headers.
use super::format::{SegmentHeader, SegmentMetadata};
use super::{
    LedgerFailure, LedgerFailureCode, SegmentProtectionKey, map_frame_failure, object_context,
};
use crate::data_protection::{DataProtection, ObjectDataKey, SegmentEnvelopeRoute};
use crate::{CatalogSnapshot, InstanceId};

const MAGIC: &[u8; 8] = b"POSDENV1";
const PREFIX: usize = 121;
const MAX_WRAPPED: usize = 256;
fn rejected() -> LedgerFailure {
    LedgerFailure::new(LedgerFailureCode::AuthenticationFailed)
}
pub(super) struct Envelope<'a> {
    instance: [u8; 16],
    tenant: [u8; 16],
    signal: u8,
    shard: u32,
    segment: [u8; 16],
    header_digest: [u8; 32],
    route: SegmentEnvelopeRoute,
    wrapped: &'a [u8],
}
fn exact<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N], LedgerFailure> {
    bytes
        .get(start..start.checked_add(N).ok_or_else(rejected)?)
        .ok_or_else(rejected)?
        .try_into()
        .map_err(|_| rejected())
}
fn decode(bytes: &[u8]) -> Result<Option<Envelope<'_>>, LedgerFailure> {
    if !bytes.starts_with(MAGIC) {
        return Ok(None);
    }
    let length = usize::from(u16::from_be_bytes(exact(bytes, 119)?));
    if length == 0 || length > MAX_WRAPPED || bytes.len() != PREFIX + length {
        return Err(rejected());
    }
    crate::InstanceId::new(exact(bytes, 8)?).map_err(|_| rejected())?;
    positron_domain::identity::TenantId::from_bytes(exact(bytes, 24)?).map_err(|_| rejected())?;
    super::SegmentId::from_bytes(exact(bytes, 45)?).map_err(|_| rejected())?;
    positron_domain::routing::VirtualShardId::new(u32::from_be_bytes(exact(bytes, 41)?))
        .map_err(|_| rejected())?;
    let signal = *bytes.get(40).ok_or_else(rejected)?;
    if !matches!(signal, 1 | 2) {
        return Err(rejected());
    }
    Ok(Some(Envelope {
        instance: exact(bytes, 8)?,
        tenant: exact(bytes, 24)?,
        signal,
        shard: u32::from_be_bytes(exact(bytes, 41)?),
        segment: exact(bytes, 45)?,
        header_digest: exact(bytes, 61)?,
        route: SegmentEnvelopeRoute::new(
            u16::from_be_bytes(exact(bytes, 93)?),
            exact(bytes, 95)?,
            u64::from_be_bytes(exact(bytes, 111)?),
        )
        .map_err(map_frame_failure)?,
        wrapped: bytes.get(PREFIX..).ok_or_else(rejected)?,
    }))
}
impl Envelope<'_> {
    fn matches(
        &self,
        metadata: SegmentMetadata,
        instance: InstanceId,
        route: SegmentEnvelopeRoute,
    ) -> bool {
        self.instance == instance.to_bytes()
            && self.tenant == metadata.scope.tenant_id().to_bytes()
            && self.signal == signal(metadata)
            && self.shard == metadata.scope.shard_id().value()
            && self.segment == metadata.id.to_bytes()
            && self.route == route
    }
}
fn signal(metadata: SegmentMetadata) -> u8 {
    match metadata.scope.signal_kind() {
        positron_domain::routing::SignalKind::Logs => 1,
        positron_domain::routing::SignalKind::Traces => 2,
    }
}
pub(super) fn find(
    snapshot: &CatalogSnapshot,
    metadata: SegmentMetadata,
    instance: InstanceId,
    route: SegmentEnvelopeRoute,
) -> Result<Option<Envelope<'_>>, LedgerFailure> {
    let mut found = None;
    for bytes in snapshot.plaintext_objects() {
        if let Some(envelope) = decode(bytes)?
            && envelope.segment == metadata.id.to_bytes()
            && envelope.route.provider_key_epoch == route.provider_key_epoch
        {
            if !envelope.matches(metadata, instance, route) || found.is_some() {
                return Err(rejected());
            }
            found = Some(envelope);
        }
    }
    Ok(found)
}
pub(super) fn open_key(
    snapshot: Option<&CatalogSnapshot>,
    metadata: SegmentMetadata,
    instance: InstanceId,
    protection: &SegmentProtectionKey,
    decoded: &SegmentHeader<'_>,
    header: &[u8],
) -> Result<ObjectDataKey, LedgerFailure> {
    let mut selected = protection.route;
    let mut overlay = None;
    if let Some(basis) = snapshot {
        // Canonical capability routes bound this search to at most 16 epochs.
        // Corrupt applicable metadata refuses before any older route.
        loop {
            overlay = find(basis, metadata, instance, selected)?;
            if overlay.is_some() {
                break;
            }
            let Some(previous) = protection.predecessor_route(selected.provider_key_epoch)? else {
                break;
            };
            selected = previous;
        }
    }
    let (route, wrapped) = match overlay {
        Some(envelope) => {
            let bytes = header.get(..decoded.encoded_bytes).ok_or_else(rejected)?;
            if DataProtection::hash(bytes).map_err(map_frame_failure)? != envelope.header_digest {
                return Err(rejected());
            }
            (selected, envelope.wrapped)
        },
        None => (decoded.route, decoded.wrapped_key),
    };
    DataProtection::unwrap_segment_key_with_route(
        &*protection.key_for_route(route)?,
        wrapped,
        instance.to_bytes(),
        object_context(metadata.scope, metadata.id)?,
        route,
    )
    .map_err(map_frame_failure)
}
pub(super) fn encode(
    metadata: SegmentMetadata,
    instance: InstanceId,
    route: SegmentEnvelopeRoute,
    digest: [u8; 32],
    wrapped: &[u8],
) -> Result<Vec<u8>, LedgerFailure> {
    if wrapped.is_empty() || wrapped.len() > MAX_WRAPPED {
        return Err(rejected());
    }
    let mut bytes = Vec::with_capacity(PREFIX + wrapped.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&instance.to_bytes());
    bytes.extend_from_slice(&metadata.scope.tenant_id().to_bytes());
    bytes.push(signal(metadata));
    bytes.extend_from_slice(&metadata.scope.shard_id().value().to_be_bytes());
    bytes.extend_from_slice(&metadata.id.to_bytes());
    bytes.extend_from_slice(&digest);
    bytes.extend_from_slice(&route.provider_family.to_be_bytes());
    bytes.extend_from_slice(&route.provider_reference);
    bytes.extend_from_slice(&route.provider_key_epoch.to_be_bytes());
    bytes.extend_from_slice(
        &u16::try_from(wrapped.len())
            .map_err(|_| rejected())?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(wrapped);
    Ok(bytes)
}

impl CatalogSnapshot {
    /// Selects the next scope with a live segment lacking the target epoch's envelope.
    pub fn next_unmigrated_ledger_scope(
        &self,
        tenant: positron_domain::identity::TenantId,
        epoch: u64,
    ) -> Result<Option<super::SegmentScope>, LedgerFailure> {
        if epoch == 0 {
            return Err(rejected());
        }
        let mut selected = None;
        for bytes in self.plaintext_objects() {
            let Some(metadata) = super::format::decode_metadata(bytes)? else {
                continue;
            };
            if metadata.scope.tenant_id() != tenant
                || metadata.state == super::format::SegmentState::Retired
            {
                continue;
            }
            let mut present = false;
            for row in self.plaintext_objects() {
                if let Some(envelope) = decode(row)?
                    && envelope.tenant == tenant.to_bytes()
                    && envelope.signal == signal(metadata)
                    && envelope.shard == metadata.scope.shard_id().value()
                    && envelope.segment == metadata.id.to_bytes()
                    && envelope.route.provider_key_epoch == epoch
                {
                    if present {
                        return Err(rejected());
                    }
                    present = true;
                }
            }
            if !present && selected.is_none_or(|scope| metadata.scope < scope) {
                selected = Some(metadata.scope);
            }
        }
        Ok(selected)
    }
}
