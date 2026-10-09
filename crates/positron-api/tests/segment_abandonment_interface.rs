use positron_api::maintenance::SegmentAbandonmentRequest;

#[test]
fn destructive_abandonment_requires_explicit_loss_acknowledgement_and_exact_preview() {
    let base = r#""tenant":"64646464-6464-6464-6464-646464646464","signal":"logs","shard":1,"segment":"abababababababababababababababab""#;
    assert!(SegmentAbandonmentRequest::decode(format!("{{{base}}}").as_bytes()).is_ok());
    for extra in [
        r#","accept_data_loss":true"#,
        r#","confirmation":"abcd"#,
        r#","unknown":1"#,
    ] {
        assert!(
            SegmentAbandonmentRequest::decode(format!("{{{base}{extra}}}").as_bytes()).is_err()
        );
    }
    let confirmed = format!(
        "{{{base},\"expected_catalog_generation\":1,\"confirmation\":\"{}\",\"idempotency_key\":\"abababab-abab-abab-abab-abababababab\",\"accept_data_loss\":true}}",
        "ab".repeat(32)
    );
    assert!(SegmentAbandonmentRequest::decode(confirmed.as_bytes()).is_ok());
}

#[test]
fn abandonment_wire_rejects_zero_scope_and_incoherent_success_receipts() {
    let request = br#"{"tenant":"64646464-6464-6464-6464-646464646464","signal":"logs","shard":0,"segment":"abababababababababababababababab"}"#;
    assert!(SegmentAbandonmentRequest::decode(request).is_err());
    let response = br#"{"catalog_generation":1,"status":"succeeded","irreversible_boundary":"not_crossed","finding":{"tenant":"64646464-6464-6464-6464-646464646464","signal":"logs","shard":1,"segment":"abababababababababababababababab","base_position":0,"event_range":{"provenance":"known","earliest_unix_nanos":1,"latest_unix_nanos":2},"ingest_range":{"provenance":"known","earliest_unix_nanos":3,"latest_unix_nanos":4}}}"#;
    assert!(positron_api::maintenance::SegmentAbandonmentResponse::decode(response).is_err());
    let coherent = std::str::from_utf8(response)
        .expect("literal UTF-8")
        .replace("\"not_crossed\"", "\"catalog_generation_published\"")
        .replace(
            "\"finding\":",
            "\"operation_id\":\"abababababababababababababababab\",\"finding\":",
        );
    assert!(
        positron_api::maintenance::SegmentAbandonmentResponse::decode(coherent.as_bytes()).is_ok()
    );
}
