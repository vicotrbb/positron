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
    let maximum_hex_characters = OfflineIntegrityContinuation::MAX_ENCODED_BYTES
        .checked_mul(2)
        .ok_or(VerifyFailure::Usage)?;
    if value.is_empty()
        || value.len() > maximum_hex_characters
        || !value.len().is_multiple_of(2)
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(VerifyFailure::Usage);
    }
    let decoded_length = value.len() / 2;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(decoded_length)
        .map_err(|_| VerifyFailure::Usage)?;
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

#[cfg(test)]
mod tests {
    use positron_runtime::OfflineIntegrityContinuation;

    use super::decode_offline_continuation;

    #[test]
    fn accepts_hex_as_long_as_a_real_bounded_aggregate_continuation() {
        let continuation = "ab".repeat(1_038);

        assert!(decode_offline_continuation(&continuation).is_ok());
    }

    #[test]
    fn admits_the_full_canonical_hex_bound_and_rejects_excess_before_decoding() {
        let at_bound = "ab".repeat(OfflineIntegrityContinuation::MAX_ENCODED_BYTES);
        let over_bound = format!("{at_bound}ab");

        assert!(decode_offline_continuation(&at_bound).is_ok());
        assert!(decode_offline_continuation(&over_bound).is_err());
    }

    #[test]
    fn rejects_empty_odd_and_non_hex_continuations() {
        for malformed in ["", "a", "0g"] {
            assert!(
                decode_offline_continuation(malformed).is_err(),
                "{malformed}"
            );
        }
    }
}
