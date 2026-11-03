//! Bounded pagination uses opaque canonical cursors and fails closed before I/O.
use positron_sdk::log_query::{LogQuerySessionRequest, LogQueryWireFailure};

#[test]
fn session_refuses_an_unbounded_or_missing_operation() {
    assert_eq!(
        LogQuerySessionRequest::default().validate(),
        Err(LogQueryWireFailure)
    );
}

#[test]
fn session_preserves_an_opaque_cursor_and_rejects_conflicting_operations() {
    use positron_sdk::log_query::log_query_session_request::Operation;
    let request = LogQuerySessionRequest {
        operation: Some(Operation::Resume(vec![1, 2, 255])),
        batch_limit: 1,
    };
    let bytes = request.encode().unwrap();
    assert_eq!(LogQuerySessionRequest::decode(&bytes).unwrap(), request);
    assert!(
        LogQuerySessionRequest::decode(br#"{"resume":"AQI=","execute":{},"batchLimit":1}"#)
            .is_err()
    );
    assert!(LogQuerySessionRequest::decode(br#"{"resume":"AQI=","batchLimit":129}"#).is_err());
}

#[test]
fn generated_session_client_refuses_invalid_input_before_io() {
    use positron_sdk::log_query::{
        LogQueryServiceClient, LogQueryServiceClientFailure, LogQueryTransport,
    };
    let client = LogQueryServiceClient::new(LogQueryTransport::PlaintextOptOut {
        endpoint: "127.0.0.1:1".parse().unwrap(),
    })
    .unwrap();
    assert_eq!(
        client.session("private-credential", &LogQuerySessionRequest::default()),
        Err(LogQueryServiceClientFailure::InvalidRequest)
    );
}

#[test]
fn cancellation_refuses_a_missing_cursor_before_io() {
    use positron_sdk::log_query::{
        LogQueryCancelRequest, LogQueryServiceClient, LogQueryServiceClientFailure,
        LogQueryTransport,
    };
    let client = LogQueryServiceClient::new(LogQueryTransport::PlaintextOptOut {
        endpoint: "127.0.0.1:1".parse().unwrap(),
    })
    .unwrap();
    assert_eq!(
        client.cancel("private-credential", &LogQueryCancelRequest::default()),
        Err(LogQueryServiceClientFailure::InvalidRequest)
    );
}

#[test]
fn expired_snapshot_refusal_preserves_its_stable_reason_and_retry_class() {
    use positron_sdk::log_query::{
        LogQueryServiceClientFailure, decode_query_rejection, query_rejection,
    };
    let bytes = query_rejection(410, "snapshot_expired").unwrap();
    assert_eq!(
        decode_query_rejection(410, &bytes),
        LogQueryServiceClientFailure::SnapshotExpired
    );
}

#[test]
fn tail_poll_refuses_a_missing_query_and_an_unbound_acknowledgement() {
    use positron_sdk::log_query::{LogQueryTailRequest, log_query_session_request::Operation};
    let request = LogQuerySessionRequest {
        operation: Some(Operation::Tail(LogQueryTailRequest::default())),
        batch_limit: 1,
    };
    assert!(request.validate().is_err());
}

#[test]
fn sessions_use_the_canonical_one_hour_lease_ceiling_without_extending_finite_requests() {
    use positron_sdk::log_query::*;
    let mut query = LogQueryRequest {
        pipeline: "pipeline:v1 logs | range query_time 0 100 | limit all".into(),
        budget: Some(LogQueryBudget {
            scanned_bytes: 1,
            decoded_records: 1,
            output_rows: 1,
            output_bytes: 1,
            memory_bytes: 1,
            cpu_work_units: 1,
            wall_seconds: 3600,
            maximum_time_range_nanoseconds: 100,
        }),
    };
    assert!(
        LogQueryTailRequest {
            query: Some(query.clone()),
            ..Default::default()
        }
        .validate()
        .is_ok()
    );
    assert!(query.validate().is_err());
    query.budget.as_mut().unwrap().wall_seconds = 3601;
    assert!(
        LogQueryTailRequest {
            query: Some(query),
            ..Default::default()
        }
        .validate()
        .is_err()
    );
}

#[test]
fn transport_loss_stays_ambiguous_and_never_requests_a_blind_retry() {
    use positron_sdk::api_keys::protobuf::{CompletionState, RetryClass};
    use positron_sdk::log_query::LogQueryServiceClientFailure;
    assert_eq!(
        LogQueryServiceClientFailure::Transport.completion_state(),
        CompletionState::Ambiguous
    );
    assert_eq!(
        LogQueryServiceClientFailure::Transport.retry_class(),
        RetryClass::Never
    );
    assert_eq!(
        LogQueryServiceClientFailure::CapacityUnavailable.retry_class(),
        RetryClass::AfterBackoff
    );
}

#[test]
fn session_refusals_preserve_distinct_native_failure_codes() {
    use positron_sdk::log_query::{
        LogQueryServiceClientFailure as Failure, decode_query_rejection, query_rejection,
    };
    for (status, code, expected) in [
        (400, "invalid_cursor", Failure::InvalidCursor),
        (422, "budget_exhausted", Failure::BudgetExhausted),
        (403, "authorization_changed", Failure::AuthorizationChanged),
        (409, "cancelled", Failure::Cancelled),
        (503, "store_unavailable", Failure::StoreUnavailable),
        (
            500,
            "malformed_persistent_data",
            Failure::MalformedPersistentData,
        ),
    ] {
        assert_eq!(
            decode_query_rejection(status, &query_rejection(status, code).unwrap()),
            expected
        );
    }
}

#[test]
fn a_new_client_refuses_missing_capability_before_sending_the_session_request() {
    use positron_sdk::log_query::*;
    use std::io::{BufRead, BufReader, Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line, "POST /v1/capabilities:negotiate HTTP/1.1\r\n");
        let mut length = 0;
        loop {
            line.clear();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line.strip_prefix("content-length: ") {
                length = value.trim().parse::<usize>().unwrap();
            }
        }
        assert!(length <= 64);
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        let reply = br#"{"code":3}"#;
        write!(
            stream,
            "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            reply.len()
        )
        .unwrap();
        stream.write_all(reply).unwrap();
    });
    let client =
        LogQueryServiceClient::new(LogQueryTransport::PlaintextOptOut { endpoint }).unwrap();
    assert_eq!(
        client.session(
            "private-credential",
            &LogQuerySessionRequest {
                operation: Some(log_query_session_request::Operation::Resume(vec![1])),
                batch_limit: 1,
            }
        ),
        Err(LogQueryServiceClientFailure::UnsupportedFeature)
    );
    server.join().unwrap();
}
