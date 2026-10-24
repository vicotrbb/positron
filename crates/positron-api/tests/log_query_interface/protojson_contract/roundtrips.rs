use super::*;

#[test]
fn request_budget_and_header_components_preserve_canonical_json_identity() {
    let budget = LogQueryBudget {
        scanned_bytes: 17,
        decoded_records: 2,
        output_rows: 3,
        output_bytes: 128,
        memory_bytes: 1024,
        cpu_work_units: 4,
        wall_seconds: 5,
        maximum_time_range_nanoseconds: 100,
    };
    let budget_json = json!({"scannedBytes":"17","decodedRecords":"2","outputRows":"3","outputBytes":"128","memoryBytes":"1024","cpuWorkUnits":"4","wallSeconds":"5","maximumTimeRangeNanoseconds":"100"});
    representation(budget, budget_json.clone());
    representation(
        LogQueryRequest {
            pipeline: "logs | limit 1".into(),
            budget: Some(budget),
        },
        json!({"pipeline":"logs | limit 1","budget":budget_json}),
    );
    representation(
        LogQueryColumn {
            name: "sequence".into(),
            value_type: "unsigned_integer".into(),
            nullable: true,
        },
        json!({"name":"sequence","valueType":"unsigned_integer","nullable":true}),
    );
    representation(
        LogQuerySnapshot {
            identity: vec![0, 255],
            generation: u64::MAX,
            frontier: 9,
        },
        json!({"identity":"AP8=","generation":"18446744073709551615","frontier":"9"}),
    );
    representation(
        LogQueryOrdering {
            column: "sequence".into(),
            value_type: "unsigned_integer".into(),
            direction: "ascending".into(),
        },
        json!({"column":"sequence","valueType":"unsigned_integer","direction":"ascending"}),
    );
    representation(
        LogQueryLease {
            identity: vec![1, 2, 3],
            expiry_unix_seconds: u64::MAX,
        },
        json!({"identity":"AQID","expiryUnixSeconds":"18446744073709551615"}),
    );
    let header = LogQueryHeader {
        columns: vec![LogQueryColumn {
            name: "value".into(),
            value_type: "native".into(),
            nullable: false,
        }],
        snapshot: Some(LogQuerySnapshot {
            identity: vec![1],
            generation: 1,
            frontier: 2,
        }),
        ordering: vec![LogQueryOrdering {
            column: "sequence".into(),
            value_type: "unsigned_integer".into(),
            direction: "ascending".into(),
        }],
        effective_budget: Some(budget),
        lease: Some(LogQueryLease {
            identity: vec![2],
            expiry_unix_seconds: 3,
        }),
        initial_cursor: Some(vec![3]),
    };
    representation(
        header.clone(),
        json!({"columns":[{"name":"value","valueType":"native"}],"snapshot":{"identity":"AQ==","generation":"1","frontier":"2"},"ordering":[{"column":"sequence","valueType":"unsigned_integer","direction":"ascending"}],"effectiveBudget":budget_json,"lease":{"identity":"Ag==","expiryUnixSeconds":"3"},"initialCursor":"Aw=="}),
    );
    representation(
        LogQueryEvent {
            event: Some(log_query_event::Event::Header(header.clone())),
        },
        json!({"header":serde_json::to_value(header).unwrap()}),
    );
}

#[test]
fn recursive_values_cells_and_batches_preserve_distinct_native_values() {
    use log_query_value::Value as Native;
    let scalar_cases = [
        (Native::NullValue(LogQueryNull {}), json!({"nullValue":{}})),
        (Native::BooleanValue(true), json!({"booleanValue":true})),
        (
            Native::IntegerValue(i64::MIN),
            json!({"integerValue":"-9223372036854775808"}),
        ),
        (
            Native::FloatBits(u64::MAX),
            json!({"floatBits":"18446744073709551615"}),
        ),
        (
            Native::TextValue("text".into()),
            json!({"textValue":"text"}),
        ),
        (
            Native::BytesValue(vec![0, 255]),
            json!({"bytesValue":"AP8="}),
        ),
    ];
    for (value, wire) in scalar_cases {
        representation(LogQueryValue { value: Some(value) }, wire);
    }
    representation(LogQueryNull {}, json!({}));
    representation(LogQueryMissing {}, json!({}));
    let text = LogQueryValue {
        value: Some(Native::TextValue("first".into())),
    };
    representation(
        LogQueryArray {
            values: vec![text.clone()],
        },
        json!({"values":[{"textValue":"first"}]}),
    );
    representation(
        LogQueryKeyValue {
            key: "k".into(),
            value: Some(text.clone()),
        },
        json!({"key":"k","value":{"textValue":"first"}}),
    );
    let object = LogQueryObject {
        entries: vec![LogQueryKeyValue {
            key: "k".into(),
            value: Some(text.clone()),
        }],
    };
    representation(
        object.clone(),
        json!({"entries":[{"key":"k","value":{"textValue":"first"}}]}),
    );
    representation(
        LogQueryValue {
            value: Some(Native::ArrayValue(LogQueryArray {
                values: vec![text.clone()],
            })),
        },
        json!({"arrayValue":{"values":[{"textValue":"first"}]}}),
    );
    representation(
        LogQueryValue {
            value: Some(Native::ObjectValue(object)),
        },
        json!({"objectValue":{"entries":[{"key":"k","value":{"textValue":"first"}}]}}),
    );
    let marker = LogQueryMarker {
        action: "mask".into(),
        original_kind: "text".into(),
    };
    representation(
        marker.clone(),
        json!({"action":"mask","originalKind":"text"}),
    );
    representation(
        LogQueryValue {
            value: Some(Native::MarkerValue(marker)),
        },
        json!({"markerValue":{"action":"mask","originalKind":"text"}}),
    );
    let truncated = LogQueryTruncated {
        action: "truncate".into(),
        value: Some(Box::new(text.clone())),
    };
    representation(
        truncated.clone(),
        json!({"action":"truncate","value":{"textValue":"first"}}),
    );
    representation(
        LogQueryValue {
            value: Some(Native::TruncatedValue(Box::new(truncated))),
        },
        json!({"truncatedValue":{"action":"truncate","value":{"textValue":"first"}}}),
    );
    let occurrences = LogQueryOccurrences {
        values: vec![text.clone(), text.clone()],
    };
    representation(
        occurrences.clone(),
        json!({"values":[{"textValue":"first"},{"textValue":"first"}]}),
    );
    let timestamp = LogQueryTimestamp {
        unix_nanoseconds: Some(i64::MIN),
        provenance: "observed".into(),
        quality: "exact".into(),
        source_value: Some(0),
    };
    representation(
        timestamp.clone(),
        json!({"unixNanoseconds":"-9223372036854775808","provenance":"observed","quality":"exact","sourceValue":"0"}),
    );
    let cells = vec![
        LogQueryCell {
            value: Some(log_query_cell::Value::NativeValue(text)),
        },
        LogQueryCell {
            value: Some(log_query_cell::Value::Occurrences(occurrences)),
        },
        LogQueryCell {
            value: Some(log_query_cell::Value::Timestamp(timestamp)),
        },
        LogQueryCell {
            value: Some(log_query_cell::Value::UnsignedInteger(u64::MAX)),
        },
        LogQueryCell {
            value: Some(log_query_cell::Value::Missing(LogQueryMissing {})),
        },
    ];
    let wires = vec![
        json!({"nativeValue":{"textValue":"first"}}),
        json!({"occurrences":{"values":[{"textValue":"first"},{"textValue":"first"}]}}),
        json!({"timestamp":{"unixNanoseconds":"-9223372036854775808","provenance":"observed","quality":"exact","sourceValue":"0"}}),
        json!({"unsignedInteger":"18446744073709551615"}),
        json!({"missing":{}}),
    ];
    for (cell, wire) in cells.iter().zip(&wires) {
        representation(cell.clone(), wire.clone());
    }
    let row = LogQueryRow {
        cells,
        replayed: true,
    };
    let row_json = json!({"cells":wires,"replayed":true});
    representation(row.clone(), row_json.clone());
    let batch = LogQueryBatch {
        sequence: 1,
        rows: vec![row],
        prior_digest: vec![1],
        digest: vec![2],
    };
    let wire = json!({"sequence":"1","rows":[row_json],"priorDigest":"AQ==","digest":"Ag=="});
    representation(batch.clone(), wire.clone());
    representation(
        LogQueryEvent {
            event: Some(log_query_event::Event::Batch(batch)),
        },
        json!({"batch":wire}),
    );
}

#[test]
fn terminal_statistics_preserve_present_zero_and_optional_bounds() {
    representation(
        LogQueryAffectedRange {
            temporal_axis: "query_time".into(),
            earliest_nanoseconds: Some(i64::MIN),
            latest_nanoseconds: Some(i64::MAX),
        },
        json!({"temporalAxis":"query_time","earliestNanoseconds":"-9223372036854775808","latestNanoseconds":"9223372036854775807"}),
    );
    let stats = LogQueryStats {
        records: 1,
        scanned_bytes: 2,
        decoded_records: 3,
        output_bytes: 4,
        memory_peak_bytes: 5,
        cpu_work_units: 6,
        wall_seconds: 7,
        last_sequence: Some(0),
        result_digest: vec![255],
        cumulative_budget: Some(LogQueryBudget {
            output_rows: 1,
            ..Default::default()
        }),
        resume_count: 8,
        repeated_batch_count: 9,
        limiting_budget: Some("output_bytes".into()),
        reduced_pruning: true,
    };
    let wire = json!({"records":"1","scannedBytes":"2","decodedRecords":"3","outputBytes":"4","memoryPeakBytes":"5","cpuWorkUnits":"6","wallSeconds":"7","lastSequence":"0","resultDigest":"/w==","cumulativeBudget":{"outputRows":"1"},"resumeCount":"8","repeatedBatchCount":"9","limitingBudget":"output_bytes","reducedPruning":true});
    representation(stats.clone(), wire.clone());
    let terminal = LogQueryTerminal {
        state: "incomplete".into(),
        reason: "budget_exhausted".into(),
        stats: Some(stats),
        affected_ranges: vec![LogQueryAffectedRange {
            temporal_axis: "query_time".into(),
            earliest_nanoseconds: Some(0),
            latest_nanoseconds: None,
        }],
        continuation_cursor: Some(vec![1]),
    };
    let wire = json!({"state":"incomplete","reason":"budget_exhausted","stats":wire,"affectedRanges":[{"temporalAxis":"query_time","earliestNanoseconds":"0"}],"continuationCursor":"AQ=="});
    representation(terminal.clone(), wire.clone());
    representation(
        LogQueryEvent {
            event: Some(log_query_event::Event::Terminal(terminal)),
        },
        json!({"terminal":wire}),
    );
    // Full envelopes use the existing canonical validator, not just component serde.
    let response = super::super::empty_complete_response();
    let bytes = response.encode().expect("valid Complete");
    assert_eq!(
        LogQueryResponse::decode(&bytes).expect("valid envelope"),
        response
    );
}
