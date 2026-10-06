use super::*;

pub(super) fn offline_scope(options: &VerifyOptions) -> Result<SegmentScope, VerifyFailure> {
    let tenant = TenantId::parse_canonical(options.tenant.as_deref().ok_or(VerifyFailure::Usage)?)
        .map_err(|_| VerifyFailure::Usage)?;
    let signal = match options.signal.as_deref() {
        Some("logs") => SignalKind::Logs,
        Some("traces") => SignalKind::Traces,
        _ => return Err(VerifyFailure::Usage),
    };
    let shard = VirtualShardId::new(options.shard.ok_or(VerifyFailure::Usage)?)
        .map_err(|_| VerifyFailure::Usage)?;
    Ok(SegmentScope::new(tenant, signal, shard))
}

pub(super) fn decode_offline_continuation(
    value: &str,
) -> Result<OfflineIntegrityContinuation, VerifyFailure> {
    if value.is_empty()
        || value.len() > 2048
        || !value.len().is_multiple_of(2)
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(VerifyFailure::Usage);
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_value(pair[0]).ok_or(VerifyFailure::Usage)?;
        let low = hex_value(pair[1]).ok_or(VerifyFailure::Usage)?;
        bytes.push((high << 4) | low);
    }
    OfflineIntegrityContinuation::from_encoded(bytes).map_err(|_| VerifyFailure::Usage)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(super) fn failure_status(failure: OfflineIntegrityFailure) -> &'static str {
    match failure {
        OfflineIntegrityFailure::OwnershipLocked => "storage_locked",
        OfflineIntegrityFailure::BootstrapUnavailable => "bootstrap_unavailable",
        OfflineIntegrityFailure::KeyUnavailable => "key_unavailable",
        OfflineIntegrityFailure::CatalogUnavailable => "catalog_busy",
        OfflineIntegrityFailure::CorruptState => "fenced",
        OfflineIntegrityFailure::CapacityUnavailable => "capacity_unavailable",
        OfflineIntegrityFailure::StorageUnavailable => "storage_unavailable",
    }
}
