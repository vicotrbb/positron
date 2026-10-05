use super::*;

#[test]
fn integrity_scrub_rejects_an_empty_budget() {
    let result = IntegrityScrubBudget::new(0);
    assert_eq!(result, Err(IntegrityFailureCode::InvalidInput));
}

#[test]
fn quarantine_v2_rejects_a_reversed_authenticated_continuity_interval() {
    let scope = SegmentScope::new(
        positron_domain::identity::TenantId::from_bytes([0x41; 16]).expect("fixed tenant"),
        positron_domain::routing::SignalKind::Logs,
        positron_domain::routing::VirtualShardId::new(1).expect("fixed shard"),
    );
    let base = super::format::position_from_value(2).expect("fixed base");
    let bytes = super::integrity::encode_quarantine(super::format::SegmentMetadata {
        scope,
        id: SegmentId::new([0x42; 16]).expect("fixed segment"),
        state: SegmentState::Sealed,
        base_position: base,
        sealed_frontier: Some(base),
        event_range: super::AuthenticatedEventRange::known(
            positron_domain::time::UnixNanoseconds::new(1),
            positron_domain::time::UnixNanoseconds::new(2),
        )
        .expect("fixed event range"),
        ingest_range: super::AuthenticatedIngestRange::Known {
            earliest: positron_domain::time::UnixNanoseconds::new(3),
            latest: positron_domain::time::UnixNanoseconds::new(3),
        },
    })
    .expect("complete sealed metadata encodes");
    let mut reversed = bytes;
    reversed[53..61].copy_from_slice(&1_u64.to_be_bytes());

    assert_eq!(
        super::integrity::decode_quarantine(&reversed)
            .expect_err("reversed continuity proof is rejected")
            .code(),
        IntegrityFailureCode::AmbiguousIntegrity
    );
}
