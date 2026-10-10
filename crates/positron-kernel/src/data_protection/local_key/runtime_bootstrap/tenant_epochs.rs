//! Canonical bounded tenant KEK envelopes remain in the existing tenant owner.
use super::*;
use crate::RootRewrapSession;

const MAGIC: &[u8; 8] = b"POSTKS01";
const MAX_EPOCHS: usize = 16;
const MAX_BYTES: usize = 16_384;
struct Epoch<'a> {
    envelope: &'a [u8],
    epoch: u64,
    reference: [u8; 16],
    route_epoch: u64,
}
fn identity(envelope: &[u8]) -> Result<([u8; 16], u64), BootstrapKeyFailure> {
    if envelope.get(..8) != Some(TENANT_KEK_ENVELOPE_MAGIC.as_slice()) {
        return Ok(([1; 16], 1));
    }
    let reference = envelope
        .get(8..24)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(BootstrapKeyFailure::Authentication)?;
    let epoch = envelope
        .get(24..32)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_be_bytes)
        .filter(|epoch| *epoch != 0)
        .ok_or(BootstrapKeyFailure::Authentication)?;
    Ok((reference, epoch))
}
struct EpochSet<'a> {
    entries: Vec<Epoch<'a>>,
    active: usize,
}
fn epochs(encoded: &[u8]) -> Result<EpochSet<'_>, BootstrapKeyFailure> {
    if encoded.is_empty() || encoded.len() > MAX_BYTES {
        return Err(BootstrapKeyFailure::LimitExceeded);
    }
    if encoded.get(..8) != Some(MAGIC.as_slice()) {
        let (_, epoch) = identity(encoded)?;
        return Ok(EpochSet {
            entries: vec![Epoch {
                envelope: encoded,
                epoch,
                reference: [1; 16],
                route_epoch: 1,
            }],
            active: 1,
        });
    }
    let count = usize::from(*encoded.get(8).ok_or(BootstrapKeyFailure::Authentication)?);
    let active = usize::from(*encoded.get(9).ok_or(BootstrapKeyFailure::Authentication)?);
    if !(1..=MAX_EPOCHS).contains(&count) || active == 0 || active > count || count - active > 1 {
        return Err(BootstrapKeyFailure::Authentication);
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
    let mut cursor = encoded
        .get(10..)
        .ok_or(BootstrapKeyFailure::Authentication)?;
    let mut previous: Option<u64> = None;
    for index in 0..count {
        let (header, tail) = cursor
            .split_at_checked(26)
            .ok_or(BootstrapKeyFailure::Authentication)?;
        let reference = header
            .get(..16)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(BootstrapKeyFailure::Authentication)?;
        let route_epoch = header
            .get(16..24)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or(BootstrapKeyFailure::Authentication)?;
        let length = header
            .get(24..26)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u16::from_be_bytes)
            .map(usize::from)
            .ok_or(BootstrapKeyFailure::Authentication)?;
        if length == 0 || length > 1024 {
            return Err(BootstrapKeyFailure::LimitExceeded);
        }
        let (envelope, tail) = tail
            .split_at_checked(length)
            .ok_or(BootstrapKeyFailure::Authentication)?;
        let (key_id, epoch) = identity(envelope)?;
        if previous.is_some_and(|previous| previous.checked_add(1) != Some(epoch))
            || !((index == 0 && reference == [1; 16] && route_epoch == 1)
                || (reference == key_id && route_epoch == epoch))
        {
            return Err(BootstrapKeyFailure::Authentication);
        }
        entries.push(Epoch {
            envelope,
            epoch,
            reference,
            route_epoch,
        });
        previous = Some(epoch);
        cursor = tail;
    }
    if !cursor.is_empty() {
        return Err(BootstrapKeyFailure::Authentication);
    }
    Ok(EpochSet { entries, active })
}
impl BootstrapKeyCustody {
    /// Returns an epoch only after every retained envelope authenticates its tenant context.
    pub fn tenant_key_epoch(
        &self,
        instance: InstanceId,
        tenant: TenantId,
        encoded: &[u8],
    ) -> Result<u64, BootstrapKeyFailure> {
        let entries = epochs(encoded)?;
        for entry in &entries.entries {
            drop(self.resolve_tenant_key_envelope(instance, tenant, entry.envelope)?);
        }
        entries
            .entries
            .get(entries.active - 1)
            .map(|entry| entry.epoch)
            .ok_or(BootstrapKeyFailure::Authentication)
    }
    pub fn pending_tenant_key_epoch(
        &self,
        instance: InstanceId,
        tenant: TenantId,
        encoded: &[u8],
    ) -> Result<Option<u64>, BootstrapKeyFailure> {
        let _ = self.tenant_key_epoch(instance, tenant, encoded)?;
        let entries = epochs(encoded)?;
        Ok(entries.entries.get(entries.active).map(|entry| entry.epoch))
    }
    pub(super) fn tenant_segment_keys(
        &self,
        instance: InstanceId,
        scope: SegmentScope,
        encoded: &[u8],
    ) -> Result<SegmentProtectionKey, BootstrapKeyFailure> {
        let entries = epochs(encoded)?;
        let _ = self.tenant_key_epoch(instance, scope.tenant_id(), encoded)?;
        if let Some(source) = self.leased_segment_source(instance, scope, encoded)? {
            let active = entries
                .entries
                .get(
                    entries
                        .active
                        .checked_sub(1)
                        .ok_or(BootstrapKeyFailure::Authentication)?,
                )
                .ok_or(BootstrapKeyFailure::Authentication)?;
            let route = crate::data_protection::SegmentEnvelopeRoute::new(
                1,
                active.reference,
                active.route_epoch,
            )
            .map_err(|_| BootstrapKeyFailure::Authentication)?;
            return Ok(SegmentProtectionKey::from_local_source(source, route));
        }
        let mut keys = entries
            .entries
            .into_iter()
            .take(entries.active)
            .map(|entry| {
                let tenant =
                    self.resolve_tenant_key_envelope(instance, scope.tenant_id(), entry.envelope)?;
                let mut context = Zeroizing::new(Vec::with_capacity(23));
                context.extend_from_slice(&scope.tenant_id().to_bytes());
                context.push(match scope.signal_kind() {
                    positron_domain::routing::SignalKind::Logs => 1,
                    positron_domain::routing::SignalKind::Traces => 2,
                });
                context.extend_from_slice(&scope.shard_id().value().to_be_bytes());
                let key =
                    derive_child(&tenant, instance, b"active-segment-wrapping-kek", &context)?;
                SegmentProtectionKey::from_owned_with_route(key, entry.reference, entry.route_epoch)
                    .map_err(|_| BootstrapKeyFailure::Authentication)
            });
        let mut retained = keys.next().ok_or(BootstrapKeyFailure::Authentication)??;
        for key in keys {
            retained = key?
                .retain_predecessor(retained)
                .map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
        }
        Ok(retained)
    }
}

pub(super) fn is_single_route(
    encoded: &[u8],
    route: crate::data_protection::SegmentEnvelopeRoute,
) -> Result<bool, BootstrapKeyFailure> {
    let set = epochs(encoded)?;
    Ok(set.active == 1
        && set.entries.len() == 1
        && set.entries.first().is_some_and(|entry| {
            route.provider_family == 1
                && entry.reference == route.provider_reference
                && entry.route_epoch == route.provider_key_epoch
        }))
}

pub(super) fn predecessor_route(
    encoded: &[u8],
    before: u64,
) -> Result<Option<crate::data_protection::SegmentEnvelopeRoute>, BootstrapKeyFailure> {
    epochs(encoded)?
        .entries
        .iter()
        .filter(|entry| entry.route_epoch < before)
        .max_by_key(|entry| entry.route_epoch)
        .map(|entry| {
            crate::data_protection::SegmentEnvelopeRoute::new(1, entry.reference, entry.route_epoch)
                .map_err(|_| BootstrapKeyFailure::Authentication)
        })
        .transpose()
}

pub(super) fn segment_key_from_system(
    system: &SecretKeyBytes,
    instance: InstanceId,
    scope: SegmentScope,
    encoded: &[u8],
    route: crate::data_protection::SegmentEnvelopeRoute,
) -> Result<SecretKeyBytes, BootstrapKeyFailure> {
    let entries = epochs(encoded)?;
    let entry = entries
        .entries
        .iter()
        .take(entries.active)
        .find(|entry| {
            route.provider_family == 1
                && entry.reference == route.provider_reference
                && entry.route_epoch == route.provider_key_epoch
        })
        .ok_or(BootstrapKeyFailure::Authentication)?;
    let tenant = BootstrapKeyCustody::resolve_tenant_from_system(
        system,
        instance,
        scope.tenant_id(),
        entry.envelope,
    )?;
    let mut context = Zeroizing::new(Vec::with_capacity(21));
    context.extend_from_slice(&scope.tenant_id().to_bytes());
    context.push(match scope.signal_kind() {
        positron_domain::routing::SignalKind::Logs => 1,
        positron_domain::routing::SignalKind::Traces => 2,
    });
    context.extend_from_slice(&scope.shard_id().value().to_be_bytes());
    derive_child(&tenant, instance, b"active-segment-wrapping-kek", &context)
        .map(SecretKeyBytes::from_owned)
}
impl RootRewrapSession<'_> {
    /// Builds the verified active route alone. The owning Catalog operation must
    /// independently prove all managed references before publishing retirement.
    pub fn retain_active_tenant_envelope(
        &self,
        key: &BootstrapKeyCustody,
        instance: InstanceId,
        tenant: TenantId,
        encoded: &[u8],
    ) -> Result<Vec<u8>, BootstrapKeyFailure> {
        let set = epochs(encoded)?;
        let _ = key.tenant_key_epoch(instance, tenant, encoded)?;
        if set.active != set.entries.len() {
            return Err(BootstrapKeyFailure::InvalidInput);
        }
        let entry = set
            .entries
            .last()
            .ok_or(BootstrapKeyFailure::Authentication)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(36 + entry.envelope.len())
            .map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&[1, 1]);
        bytes.extend_from_slice(&entry.reference);
        bytes.extend_from_slice(&entry.route_epoch.to_be_bytes());
        bytes.extend_from_slice(
            &u16::try_from(entry.envelope.len())
                .map_err(|_| BootstrapKeyFailure::LimitExceeded)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(entry.envelope);
        Ok(bytes)
    }

    pub fn activate_tenant_envelope(
        &self,
        key: &BootstrapKeyCustody,
        instance: InstanceId,
        tenant: TenantId,
        encoded: &[u8],
    ) -> Result<Vec<u8>, BootstrapKeyFailure> {
        let entries = epochs(encoded)?;
        let _ = key.tenant_key_epoch(instance, tenant, encoded)?;
        if entries.active == entries.entries.len() {
            return Err(BootstrapKeyFailure::InvalidInput);
        }
        let mut bytes = encoded.to_vec();
        *bytes
            .get_mut(9)
            .ok_or(BootstrapKeyFailure::Authentication)? =
            u8::try_from(entries.entries.len()).map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
        Ok(bytes)
    }
    /// Prepares a fresh successor and retains authenticated predecessor routes.
    pub fn prepare_tenant_envelope(
        &self,
        key: &BootstrapKeyCustody,
        instance: InstanceId,
        tenant: TenantId,
        encoded: &[u8],
    ) -> Result<Vec<u8>, BootstrapKeyFailure> {
        let entries = epochs(encoded)?;
        let current = key.tenant_key_epoch(instance, tenant, encoded)?;
        if entries.active < entries.entries.len() {
            return Ok(encoded.to_vec());
        }
        if entries.entries.len() >= MAX_EPOCHS {
            return Err(BootstrapKeyFailure::LimitExceeded);
        }
        let next = current
            .checked_add(1)
            .ok_or(BootstrapKeyFailure::LimitExceeded)?;
        let reference = key.random_identifier()?;
        let successor = key.provision_tenant_key_envelope(instance, tenant, reference, next)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(MAX_BYTES)
            .map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
        bytes.extend_from_slice(MAGIC);
        bytes.push(
            u8::try_from(entries.entries.len() + 1)
                .map_err(|_| BootstrapKeyFailure::LimitExceeded)?,
        );
        bytes.push(u8::try_from(entries.active).map_err(|_| BootstrapKeyFailure::LimitExceeded)?);
        for entry in entries.entries.iter().chain(std::iter::once(&Epoch {
            envelope: &successor,
            epoch: next,
            reference,
            route_epoch: next,
        })) {
            bytes.extend_from_slice(&entry.reference);
            bytes.extend_from_slice(&entry.route_epoch.to_be_bytes());
            bytes.extend_from_slice(
                &u16::try_from(entry.envelope.len())
                    .map_err(|_| BootstrapKeyFailure::LimitExceeded)?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(entry.envelope);
        }
        Ok(bytes)
    }
}

pub(super) fn register_segment_references(
    encoded: &[u8],
    tenant: TenantId,
    registry: crate::active_segment_ledger::snapshot_protection::SnapshotProtectionRegistry,
    barrier: &std::sync::RwLock<()>,
) -> Result<
    crate::active_segment_ledger::snapshot_protection::SnapshotProtection,
    BootstrapKeyFailure,
> {
    let set = epochs(encoded)?;
    crate::active_segment_ledger::snapshot_protection::SnapshotProtection::for_tenant_epochs(
        registry,
        barrier,
        tenant,
        set.entries.iter().map(|entry| entry.epoch),
    )
    .map_err(|_| BootstrapKeyFailure::LimitExceeded)
}
