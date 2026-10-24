use super::*;

#[test]
fn omitted_query_components_use_protojson_defaults() {
    macro_rules! empty {
        ($($kind:ty),+ $(,)?) => {$(
            let decoded: $kind = serde_json::from_str("{}").expect("omitted fields");
            assert_eq!(decoded, <$kind>::default());
            assert_eq!(serde_json::to_value(decoded).expect("default JSON"), json!({}));
        )+};
    }
    empty!(
        LogQueryRequest,
        LogQueryBudget,
        LogQueryColumn,
        LogQuerySnapshot,
        LogQueryOrdering,
        LogQueryLease,
        LogQueryHeader,
        LogQueryNull,
        LogQueryMissing,
        LogQueryValue,
        LogQueryArray,
        LogQueryKeyValue,
        LogQueryObject,
        LogQueryMarker,
        LogQueryTruncated,
        LogQueryOccurrences,
        LogQueryTimestamp,
        LogQueryCell,
        LogQueryRow,
        LogQueryBatch,
        LogQueryAffectedRange,
        LogQueryStats,
        LogQueryTerminal,
        LogQueryEvent,
    );
}

#[test]
fn optional_null_is_absent_while_present_zero_keeps_its_presence() {
    let absent: LogQueryTimestamp =
        serde_json::from_str(r#"{"unixNanoseconds":null,"sourceValue":null}"#)
            .expect("null optional timestamps");
    assert_eq!(absent.unix_nanoseconds, None);
    assert_eq!(absent.source_value, None);
    assert_eq!(
        serde_json::to_value(absent).expect("absent JSON"),
        json!({})
    );
    let present: LogQueryTimestamp =
        serde_json::from_str(r#"{"unixNanoseconds":0,"sourceValue":"0"}"#)
            .expect("present zero timestamps");
    assert_eq!(present.unix_nanoseconds, Some(0));
    assert_eq!(present.source_value, Some(0));
    assert_eq!(
        serde_json::to_value(present).expect("present JSON"),
        json!({"unixNanoseconds":"0","sourceValue":"0"})
    );
    let header: LogQueryHeader = serde_json::from_str(
        r#"{"snapshot":null,"effectiveBudget":null,"lease":null,"initialCursor":null}"#,
    )
    .expect("absent header metadata");
    assert_eq!(header, LogQueryHeader::default());
    let stats: LogQueryStats = serde_json::from_str(
        r#"{"lastSequence":null,"cumulativeBudget":null,"limitingBudget":null}"#,
    )
    .expect("absent statistics metadata");
    assert_eq!(stats, LogQueryStats::default());
    let terminal: LogQueryTerminal =
        serde_json::from_str(r#"{"stats":null,"continuationCursor":null}"#)
            .expect("absent terminal metadata");
    assert_eq!(terminal, LogQueryTerminal::default());
}

#[test]
fn null_oneof_members_do_not_hide_a_later_concrete_value() {
    let value: LogQueryValue = serde_json::from_str(r#"{"nullValue":null,"booleanValue":false}"#)
        .expect("null does not select the null-value message");
    assert_eq!(
        value.value,
        Some(log_query_value::Value::BooleanValue(false))
    );
    assert_eq!(
        serde_json::to_value(value).expect("false oneof JSON"),
        json!({"booleanValue":false})
    );
    let cell: LogQueryCell = serde_json::from_str(r#"{"nativeValue":null,"unsignedInteger":"0"}"#)
        .expect("null does not select a cell alternative");
    assert_eq!(cell.value, Some(log_query_cell::Value::UnsignedInteger(0)));
    assert_eq!(
        serde_json::to_value(cell).expect("zero oneof JSON"),
        json!({"unsignedInteger":"0"})
    );
    let event: LogQueryEvent = serde_json::from_str(r#"{"header":null,"batch":{"sequence":"1"}}"#)
        .expect("null does not select an event alternative");
    assert_eq!(
        event.event,
        Some(log_query_event::Event::Batch(LogQueryBatch {
            sequence: 1,
            ..Default::default()
        }))
    );
    for malformed in [
        r#"{"booleanValue":false,"integerValue":"0"}"#,
        r#"{"textValue":"","bytesValue":""}"#,
    ] {
        assert!(serde_json::from_str::<LogQueryValue>(malformed).is_err());
    }
}

#[test]
fn byte_fields_accept_standard_base64_forms_and_emit_one_canonical_form() {
    for encoded in ["+/8=", "+/8", "-_8=", "-_8"] {
        let snapshot: LogQuerySnapshot =
            serde_json::from_value(json!({"identity":encoded})).expect("standard ProtoJSON base64");
        assert_eq!(snapshot.identity, vec![251, 255]);
        assert_eq!(
            serde_json::to_value(snapshot).expect("canonical base64"),
            json!({"identity":"+/8="})
        );
    }
}

#[test]
fn wrong_json_kinds_are_rejected_at_component_boundaries() {
    macro_rules! rejects {
        ($kind:ty, [$($input:literal),+ $(,)?]) => {$(
            assert!(serde_json::from_str::<$kind>($input).is_err(),
                "{} accepted {}", stringify!($kind), $input);
        )+};
    }
    rejects!(LogQueryRequest, [r#"{"pipeline":17}"#, r#"{"budget":[]}"#]);
    rejects!(
        LogQueryColumn,
        [r#"{"name":true}"#, r#"{"nullable":"false"}"#]
    );
    rejects!(
        LogQueryHeader,
        [r#"{"columns":{}}"#, r#"{"ordering":{}}"#, r#"{"lease":1}"#]
    );
    rejects!(LogQueryArray, [r#"{"values":{}}"#]);
    rejects!(LogQueryObject, [r#"{"entries":{}}"#]);
    rejects!(LogQueryKeyValue, [r#"{"key":[]}"#, r#"{"value":false}"#]);
    rejects!(
        LogQueryValue,
        [
            r#"{"booleanValue":0}"#,
            r#"{"textValue":{}}"#,
            r#"{"bytesValue":[1]}"#
        ]
    );
    rejects!(LogQueryRow, [r#"{"cells":{}}"#, r#"{"replayed":1}"#]);
    rejects!(LogQueryBatch, [r#"{"rows":{}}"#, r#"{"digest":false}"#]);
    rejects!(
        LogQueryTerminal,
        [r#"{"affectedRanges":{}}"#, r#"{"state":1}"#]
    );
    rejects!(
        LogQueryEvent,
        [
            r#"{"header":[]}"#,
            r#"{"batch":false}"#,
            r#"{"terminal":1}"#
        ]
    );
}
