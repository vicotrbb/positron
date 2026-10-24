//! Public Query request bounds are enforced before a client performs I/O.
use positron_api::log_query::{LogQueryBudget, LogQueryRequest};

#[path = "log_query_interface/transport_deadline.rs"]
mod transport_deadline;

#[test]
fn bounded_log_query_request_round_trips_the_declared_pipeline_and_budget() {
    let request = LogQueryRequest {
        pipeline: "logs | range query_time 0 100 | limit 16".into(),
        budget: Some(LogQueryBudget {
            scanned_bytes: 1_048_576,
            decoded_records: 16,
            output_rows: 16,
            output_bytes: 16_384,
            memory_bytes: 1_048_576,
            cpu_work_units: 15,
            wall_seconds: 5,
            maximum_time_range_nanoseconds: 100,
        }),
    };
    let bytes = request.encode().unwrap();
    assert_eq!(LogQueryRequest::decode(&bytes).unwrap(), request);
    assert!(LogQueryRequest::decode(br#"{"pipeline":"logs","budget":null,"unknown":1}"#).is_err());
}

#[test]
fn query_client_rejects_absent_or_ambiguous_terminal_envelopes() {
    use positron_api::log_query::LogQueryResponse;
    assert!(LogQueryResponse::decode(br#"{"events":[]}"#).is_err());
    assert!(LogQueryResponse::decode(br#"{"events":[{"event":null}]}"#).is_err());
}

#[test]
fn generated_log_query_client_rejects_invalid_input_before_network_io() {
    use positron_api::log_query::{
        LogQueryServiceClient, LogQueryServiceClientFailure, LogQueryTransport,
    };
    let client = LogQueryServiceClient::new(LogQueryTransport::PlaintextOptOut {
        endpoint: "127.0.0.1:1".parse().unwrap(),
    })
    .unwrap();
    assert_eq!(
        client.execute("not-rendered", &LogQueryRequest::default()),
        Err(LogQueryServiceClientFailure::InvalidRequest)
    );
}

#[test]
fn native_float_bits_and_signed_values_keep_exact_64_bit_json_identity() {
    use positron_api::log_query::{LogQueryValue, log_query_value};
    for (value, field, expected) in [
        (
            log_query_value::Value::FloatBits(u64::MAX),
            "floatBits",
            "18446744073709551615",
        ),
        (
            log_query_value::Value::IntegerValue(i64::MIN),
            "integerValue",
            "-9223372036854775808",
        ),
    ] {
        let encoded = serde_json::to_value(LogQueryValue { value: Some(value) }).unwrap();
        assert_eq!(encoded[field].as_str(), Some(expected));
    }
}

#[test]
fn query_response_encoding_refuses_a_missing_terminal() {
    use positron_api::log_query::LogQueryResponse;
    assert!(LogQueryResponse::default().encode().is_err());
}

#[test]
fn canonical_protojson_preserves_bytes_and_rejects_ambiguous_oneof_fields() {
    use positron_api::log_query::{LogQueryValue, log_query_value};
    let value = LogQueryValue {
        value: Some(log_query_value::Value::BytesValue(vec![1, 2, 3, 255])),
    };
    assert_eq!(
        serde_json::to_value(value).unwrap(),
        serde_json::json!({"bytesValue":"AQID/w=="})
    );
    for input in [
        r#"{"textValue":"a","text_value":"b"}"#,
        r#"{"textValue":"a","booleanValue":true}"#,
        r#"{"unknown":1}"#,
    ] {
        assert!(serde_json::from_str::<LogQueryValue>(input).is_err());
    }
}

#[test]
fn protojson_accepts_standard_alternate_encodings_without_losing_integer_identity() {
    use positron_api::log_query::{LogQueryValue, log_query_value};
    for input in [
        r#"{"integerValue":"-9223372036854775808"}"#,
        r#"{"integer_value":-9223372036854775808}"#,
    ] {
        let decoded: LogQueryValue = serde_json::from_str(input).unwrap();
        assert_eq!(
            decoded.value,
            Some(log_query_value::Value::IntegerValue(i64::MIN))
        );
    }
    for input in [
        r#"{"bytesValue":"AQID/w=="}"#,
        r#"{"bytes_value":"AQID_w"}"#,
    ] {
        let decoded: LogQueryValue = serde_json::from_str(input).unwrap();
        assert_eq!(
            decoded.value,
            Some(log_query_value::Value::BytesValue(vec![1, 2, 3, 255]))
        );
    }
}

fn empty_complete_response() -> positron_api::log_query::LogQueryResponse {
    use positron_api::log_query::*;
    let budget = LogQueryBudget {
        scanned_bytes: 1,
        decoded_records: 1,
        output_rows: 1,
        output_bytes: 1,
        memory_bytes: 1,
        cpu_work_units: 1,
        wall_seconds: 1,
        maximum_time_range_nanoseconds: 1,
    };
    LogQueryResponse {
        events: vec![
            LogQueryEvent {
                event: Some(log_query_event::Event::Header(LogQueryHeader {
                    columns: vec![LogQueryColumn {
                        name: "body".into(),
                        value_type: "native_value".into(),
                        nullable: false,
                    }],
                    snapshot: Some(LogQuerySnapshot {
                        identity: vec![1; 32],
                        generation: 1,
                        frontier: 0,
                    }),
                    ordering: vec![LogQueryOrdering {
                        column: "query_time".into(),
                        value_type: "query_time".into(),
                        direction: "ascending".into(),
                    }],
                    effective_budget: Some(budget),
                    lease: Some(LogQueryLease {
                        identity: vec![1; 16],
                        expiry_unix_seconds: 1,
                    }),
                    initial_cursor: None,
                })),
            },
            LogQueryEvent {
                event: Some(log_query_event::Event::Terminal(LogQueryTerminal {
                    state: "complete".into(),
                    stats: Some(LogQueryStats {
                        result_digest: vec![0; 32],
                        cumulative_budget: Some(budget),
                        ..Default::default()
                    }),
                    ..Default::default()
                })),
            },
        ],
    }
}

#[test]
fn response_rejects_unknown_closed_vocabularies_and_invalid_ranges() {
    use positron_api::log_query::log_query_event::Event;
    assert!(empty_complete_response().validate().is_ok());
    for field in [
        "column_type",
        "ordering_type",
        "direction",
        "budget",
        "limiting_budget",
    ] {
        let mut response = empty_complete_response();
        if let Some(Event::Header(header)) = response.events[0].event.as_mut() {
            match field {
                "column_type" => header.columns[0].value_type = "future".into(),
                "ordering_type" => header.ordering[0].value_type = "future".into(),
                "direction" => header.ordering[0].direction = "future".into(),
                "budget" => header.effective_budget.as_mut().unwrap().output_rows = 0,
                _ => {},
            }
        }
        if field == "limiting_budget"
            && let Some(Event::Terminal(terminal)) = response.events[1].event.as_mut()
        {
            terminal.stats.as_mut().unwrap().limiting_budget = Some("future".into());
        }
        assert!(response.validate().is_err(), "{field}");
    }
}

#[test]
fn query_rejections_use_closed_canonical_error_and_completion_metadata() {
    use positron_api::log_query::{
        LogQueryServiceClientFailure, decode_query_rejection, query_rejection,
    };
    for (status, code, expected) in [
        (
            400,
            "invalid_request",
            LogQueryServiceClientFailure::InvalidRequest,
        ),
        (
            401,
            "authentication_rejected",
            LogQueryServiceClientFailure::AuthenticationRejected,
        ),
        (
            429,
            "capacity_unavailable",
            LogQueryServiceClientFailure::CapacityUnavailable,
        ),
        (
            503,
            "query_unavailable",
            LogQueryServiceClientFailure::QueryUnavailable,
        ),
    ] {
        let body = query_rejection(status, code).unwrap();
        assert_eq!(decode_query_rejection(status, &body), expected);
        let mut value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        value["completionState"] = serde_json::json!("COMPLETION_STATE_UNSPECIFIED");
        assert_eq!(
            decode_query_rejection(status, &serde_json::to_vec(&value).unwrap()),
            LogQueryServiceClientFailure::Transport
        );
        value["code"] = serde_json::json!(987);
        assert_eq!(
            decode_query_rejection(status, &serde_json::to_vec(&value).unwrap()),
            LogQueryServiceClientFailure::Transport
        );
    }
    assert!(query_rejection(200, "complete").is_err());
}

#[test]
fn query_response_rejects_unknown_native_marker_kinds_and_timestamp_provenance() {
    use positron_api::log_query::*;
    for cell in [
        log_query_cell::Value::NativeValue(LogQueryValue {
            value: Some(log_query_value::Value::MarkerValue(LogQueryMarker {
                action: "redacted".into(),
                original_kind: "future".into(),
            })),
        }),
        log_query_cell::Value::Timestamp(LogQueryTimestamp {
            unix_nanoseconds: Some(1),
            provenance: "future".into(),
            ..Default::default()
        }),
        log_query_cell::Value::Timestamp(LogQueryTimestamp {
            unix_nanoseconds: Some(1),
            quality: "future".into(),
            ..Default::default()
        }),
    ] {
        let mut response = empty_complete_response();
        response.events.insert(
            1,
            LogQueryEvent {
                event: Some(log_query_event::Event::Batch(LogQueryBatch {
                    sequence: 0,
                    rows: vec![LogQueryRow {
                        cells: vec![LogQueryCell { value: Some(cell) }],
                        replayed: false,
                    }],
                    prior_digest: vec![0; 32],
                    digest: vec![1; 32],
                })),
            },
        );
        if let Some(log_query_event::Event::Terminal(terminal)) = response.events[2].event.as_mut()
        {
            let stats = terminal.stats.as_mut().unwrap();
            stats.records = 1;
            stats.last_sequence = Some(0);
            stats.result_digest = vec![1; 32];
        }
        assert!(response.validate().is_err());
    }
}

#[test]
fn envelope_keeps_continued_distinct_and_refuses_digest_or_terminal_corruption() {
    use positron_api::log_query::*;
    let mut response = empty_complete_response();
    let Some(log_query_event::Event::Terminal(terminal)) = response.events[1].event.as_mut() else {
        panic!("terminal");
    };
    terminal.state = "continued".into();
    terminal.stats = None;
    terminal.continuation_cursor = Some(vec![1, 2, 3]);
    let decoded = LogQueryResponse::decode(&response.encode().unwrap()).unwrap();
    let Some(log_query_event::Event::Terminal(terminal)) = decoded.events[1].event.as_ref() else {
        panic!("terminal");
    };
    assert_eq!(terminal.state, "continued");
    assert!(terminal.stats.is_none());
    for corrupt in ["digest", "duplicate_terminal", "range"] {
        let mut response = empty_complete_response();
        if let Some(log_query_event::Event::Terminal(terminal)) = response.events[1].event.as_mut()
        {
            match corrupt {
                "digest" => terminal.stats.as_mut().unwrap().result_digest = vec![1; 32],
                "range" => {
                    terminal.state = "incomplete".into();
                    terminal.reason = "incomplete_data".into();
                    terminal.affected_ranges = vec![LogQueryAffectedRange {
                        temporal_axis: "event_time".into(),
                        earliest_nanoseconds: Some(2),
                        latest_nanoseconds: Some(1),
                    }];
                },
                _ => {},
            }
        }
        if corrupt == "duplicate_terminal" {
            response.events.push(response.events[1].clone());
        }
        assert!(response.encode().is_err(), "{corrupt}");
    }
}

#[test]
fn bounded_response_serialization_rejects_escape_expansion_before_exceeding_buffer() {
    use positron_api::log_query::*;
    let mut response = empty_complete_response();
    response.events.insert(
        1,
        LogQueryEvent {
            event: Some(log_query_event::Event::Batch(LogQueryBatch {
                sequence: 0,
                rows: vec![LogQueryRow {
                    cells: vec![LogQueryCell {
                        value: Some(log_query_cell::Value::NativeValue(LogQueryValue {
                            value: Some(log_query_value::Value::TextValue(
                                "\0".repeat(MAX_RESPONSE_BYTES / 5),
                            )),
                        })),
                    }],
                    replayed: false,
                }],
                prior_digest: vec![0; 32],
                digest: vec![1; 32],
            })),
        },
    );
    if let Some(log_query_event::Event::Terminal(terminal)) = response.events[2].event.as_mut() {
        let stats = terminal.stats.as_mut().unwrap();
        stats.records = 1;
        stats.last_sequence = Some(0);
        stats.result_digest = vec![1; 32];
    }
    assert!(response.validate().is_ok());
    assert!(response.encode().is_err());
    assert!(LogQueryResponse::decode(&vec![b' '; MAX_RESPONSE_BYTES + 1]).is_err());
}

#[test]
fn decoder_enforces_declared_cell_type_and_nullability() {
    use positron_api::log_query::*;
    for kind in ["commit_position", "unsigned_integer"] {
        for (value, nullable, valid) in [
            (log_query_cell::Value::UnsignedInteger(7), false, true),
            (
                log_query_cell::Value::NativeValue(LogQueryValue {
                    value: Some(log_query_value::Value::TextValue("wrong type".into())),
                }),
                false,
                false,
            ),
            (
                log_query_cell::Value::Missing(LogQueryMissing {}),
                false,
                false,
            ),
            (
                log_query_cell::Value::Missing(LogQueryMissing {}),
                true,
                true,
            ),
        ] {
            let mut response = empty_complete_response();
            if let Some(log_query_event::Event::Header(header)) = response.events[0].event.as_mut()
            {
                header.columns[0].value_type = kind.into();
                header.columns[0].nullable = nullable;
            }
            response.events.insert(
                1,
                LogQueryEvent {
                    event: Some(log_query_event::Event::Batch(LogQueryBatch {
                        sequence: 0,
                        rows: vec![LogQueryRow {
                            cells: vec![LogQueryCell { value: Some(value) }],
                            replayed: false,
                        }],
                        prior_digest: vec![0; 32],
                        digest: vec![1; 32],
                    })),
                },
            );
            if let Some(log_query_event::Event::Terminal(terminal)) =
                response.events[2].event.as_mut()
            {
                let stats = terminal.stats.as_mut().unwrap();
                stats.records = 1;
                stats.last_sequence = Some(0);
                stats.result_digest = vec![1; 32];
            }
            let wire = serde_json::to_vec(&response).unwrap();
            assert_eq!(
                LogQueryResponse::decode(&wire).is_ok(),
                valid,
                "{kind} nullable={nullable}"
            );
        }
    }
}

#[path = "log_query_interface/protojson_contract.rs"]
mod protojson_contract;
