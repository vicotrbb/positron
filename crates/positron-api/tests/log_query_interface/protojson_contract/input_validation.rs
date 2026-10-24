use super::*;

fn integer_forms<T>(expected: T, canonical: Value, fields: &[&str])
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    for field in fields {
        let mut numeric = canonical.clone();
        let text = canonical[*field]
            .as_str()
            .expect("canonical decimal string");
        numeric[*field] = serde_json::from_str(text).expect("JSON integer");
        assert_eq!(
            serde_json::from_value::<T>(numeric).expect("numeric form"),
            expected
        );
        for invalid in [
            json!("18446744073709551616"),
            json!("-9223372036854775809"),
            json!(1.5),
            json!("not-an-integer"),
        ] {
            let mut malformed = canonical.clone();
            malformed[*field] = invalid;
            assert!(
                serde_json::from_value::<T>(malformed).is_err(),
                "invalid integer {field}"
            );
        }
    }
}

#[test]
fn protojson_integer_fields_accept_exact_numbers_but_refuse_overflow_and_fractions() {
    let budget = LogQueryBudget {
        scanned_bytes: 1,
        decoded_records: 2,
        output_rows: 3,
        output_bytes: 4,
        memory_bytes: 5,
        cpu_work_units: 6,
        wall_seconds: 5,
        maximum_time_range_nanoseconds: 8,
    };
    integer_forms(
        budget,
        json!({"scannedBytes":"1","decodedRecords":"2","outputRows":"3","outputBytes":"4","memoryBytes":"5","cpuWorkUnits":"6","wallSeconds":"5","maximumTimeRangeNanoseconds":"8"}),
        &[
            "scannedBytes",
            "decodedRecords",
            "outputRows",
            "outputBytes",
            "memoryBytes",
            "cpuWorkUnits",
            "wallSeconds",
            "maximumTimeRangeNanoseconds",
        ],
    );
    integer_forms(
        LogQuerySnapshot {
            identity: vec![1],
            generation: u64::MAX,
            frontier: 0,
        },
        json!({"identity":"AQ==","generation":"18446744073709551615","frontier":"0"}),
        &["generation", "frontier"],
    );
    integer_forms(
        LogQueryLease {
            identity: vec![1],
            expiry_unix_seconds: 1,
        },
        json!({"identity":"AQ==","expiryUnixSeconds":"1"}),
        &["expiryUnixSeconds"],
    );
    integer_forms(
        LogQueryTimestamp {
            unix_nanoseconds: Some(i64::MIN),
            source_value: Some(u64::MAX),
            provenance: String::new(),
            quality: String::new(),
        },
        json!({"unixNanoseconds":"-9223372036854775808","sourceValue":"18446744073709551615"}),
        &["unixNanoseconds", "sourceValue"],
    );
    integer_forms(
        LogQueryAffectedRange {
            temporal_axis: "query_time".into(),
            earliest_nanoseconds: Some(i64::MIN),
            latest_nanoseconds: Some(i64::MAX),
        },
        json!({"temporalAxis":"query_time","earliestNanoseconds":"-9223372036854775808","latestNanoseconds":"9223372036854775807"}),
        &["earliestNanoseconds", "latestNanoseconds"],
    );
    integer_forms(
        LogQueryBatch {
            sequence: 1,
            ..Default::default()
        },
        json!({"sequence":"1"}),
        &["sequence"],
    );
    integer_forms(
        LogQueryCell {
            value: Some(log_query_cell::Value::UnsignedInteger(u64::MAX)),
        },
        json!({"unsignedInteger":"18446744073709551615"}),
        &["unsignedInteger"],
    );
    integer_forms(
        LogQueryValue {
            value: Some(log_query_value::Value::IntegerValue(i64::MIN)),
        },
        json!({"integerValue":"-9223372036854775808"}),
        &["integerValue"],
    );
    integer_forms(
        LogQueryValue {
            value: Some(log_query_value::Value::FloatBits(u64::MAX)),
        },
        json!({"floatBits":"18446744073709551615"}),
        &["floatBits"],
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
        resume_count: 8,
        repeated_batch_count: 9,
        ..Default::default()
    };
    integer_forms(
        stats,
        json!({"records":"1","scannedBytes":"2","decodedRecords":"3","outputBytes":"4","memoryPeakBytes":"5","cpuWorkUnits":"6","wallSeconds":"7","lastSequence":"0","resumeCount":"8","repeatedBatchCount":"9"}),
        &[
            "records",
            "scannedBytes",
            "decodedRecords",
            "outputBytes",
            "memoryPeakBytes",
            "cpuWorkUnits",
            "wallSeconds",
            "lastSequence",
            "resumeCount",
            "repeatedBatchCount",
        ],
    );
}

#[test]
fn malformed_nested_protojson_never_becomes_a_valid_public_request_or_response() {
    let request = LogQueryRequest {
        pipeline: "logs | limit 1".into(),
        budget: Some(LogQueryBudget {
            scanned_bytes: 1024,
            decoded_records: 1,
            output_rows: 1,
            output_bytes: 1024,
            memory_bytes: 1024,
            cpu_work_units: 1,
            wall_seconds: 1,
            maximum_time_range_nanoseconds: 1,
        }),
    };
    let good = request.encode().expect("valid request");
    let value: Value = serde_json::from_slice(&good).unwrap();
    for malformed in [
        r#"{"pipeline":"logs | limit 1","budget":{"wallSeconds":"1","wall_seconds":"1"}}"#
            .to_owned(),
        r#"{"pipeline":"logs | limit 1","budget":{"unknown":1}}"#.to_owned(),
    ] {
        assert!(LogQueryRequest::decode(malformed.as_bytes()).is_err());
    }
    for invalid in [json!(-1), json!(1.5), json!("18446744073709551616")] {
        let mut malformed = value.clone();
        malformed["budget"]["wallSeconds"] = invalid;
        assert!(LogQueryRequest::decode(&serde_json::to_vec(&malformed).unwrap()).is_err());
    }
    let response = super::super::empty_complete_response();
    let good = response.encode().unwrap();
    let value: Value = serde_json::from_slice(&good).unwrap();
    for (path, invalid) in [
        ("identity", json!("not-base64!")),
        ("generation", json!("18446744073709551616")),
        ("unknown", json!(true)),
    ] {
        let mut malformed = value.clone();
        malformed["events"][0]["header"]["snapshot"][path] = invalid;
        assert!(LogQueryResponse::decode(&serde_json::to_vec(&malformed).unwrap()).is_err());
    }
    for malformed in [
        r#"{"header":{},"batch":{}}"#,
        r#"{"header":{},"terminal":{}}"#,
        r#"{"batch":{},"terminal":{}}"#,
    ] {
        assert!(serde_json::from_str::<LogQueryEvent>(malformed).is_err());
        assert!(
            LogQueryResponse::decode(format!(r#"{{"events":[{malformed}]}}"#).as_bytes()).is_err()
        );
    }
    for malformed in [
        r#"{"nativeValue":{},"missing":{}}"#,
        r#"{"timestamp":{},"unsignedInteger":"1"}"#,
        r#"{"occurrences":{},"missing":{}}"#,
    ] {
        assert!(serde_json::from_str::<LogQueryCell>(malformed).is_err());
    }
    for malformed in [
        r#"{"nullValue":{},"integerValue":"1"}"#,
        r#"{"arrayValue":{},"objectValue":{}}"#,
        r#"{"markerValue":{},"truncatedValue":{}}"#,
        r#"{"bytesValue":"not-base64!"}"#,
    ] {
        assert!(serde_json::from_str::<LogQueryValue>(malformed).is_err());
    }
}

#[test]
fn closed_public_errors_keep_protojson_enum_identity_and_refuse_forged_metadata() {
    use positron_api::api_keys::protobuf::{
        CompletionState, FailureSource, PublicError, PublicErrorCode, RetryClass, SafeDetail,
    };
    use positron_api::log_query::{
        LogQueryServiceClientFailure, decode_query_rejection, query_rejection,
    };
    let error = PublicError {
        code: PublicErrorCode::CapacityUnavailable as i32,
        retry_class: RetryClass::AfterBackoff as i32,
        completion_state: CompletionState::Rejected as i32,
        source: FailureSource::QueryExecution as i32,
        safe_detail: SafeDetail::CapacityUnavailable as i32,
    };
    representation(
        error,
        json!({"code":"PUBLIC_ERROR_CODE_CAPACITY_UNAVAILABLE","retryClass":"RETRY_CLASS_AFTER_BACKOFF","completionState":"COMPLETION_STATE_REJECTED","source":"FAILURE_SOURCE_QUERY_EXECUTION","safeDetail":"SAFE_DETAIL_CAPACITY_UNAVAILABLE"}),
    );
    assert_eq!(
        serde_json::from_value::<PublicError>(
            json!({"code":8,"retryClass":2,"completionState":1,"source":4,"safeDetail":8})
        )
        .unwrap(),
        error
    );
    let body = query_rejection(429, "capacity_unavailable").unwrap();
    let canonical: Value = serde_json::from_slice(&body).unwrap();
    for field in [
        "code",
        "retryClass",
        "completionState",
        "source",
        "safeDetail",
    ] {
        for invalid in [
            json!(i32::MAX),
            json!(-1),
            json!("UNRECOGNIZED_PRIVATE_CANARY"),
            json!(1.5),
        ] {
            let mut malformed = canonical.clone();
            malformed[field] = invalid;
            assert_eq!(
                decode_query_rejection(429, &serde_json::to_vec(&malformed).unwrap()),
                LogQueryServiceClientFailure::Transport
            );
        }
    }
    assert_eq!(
        decode_query_rejection(429, br#"{"code":8,"code":8}"#),
        LogQueryServiceClientFailure::Transport
    );
}
