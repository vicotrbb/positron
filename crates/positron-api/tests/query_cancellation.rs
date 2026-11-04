use positron_api::api_keys::protobuf::{
    CapabilityAvailability, CapabilityResponse, CompletionState, PublicError, PublicErrorCode,
    RetryClass,
};
use positron_api::log_query::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::time::{Duration, Instant};

#[test]
fn cancellation_client_preserves_canonical_ambiguity_and_original_cause() {
    let fixtures: serde_json::Value = serde_json::from_str(include_str!(
        "../../../api/positron/v1/query-error-fixtures.json"
    ))
    .unwrap();
    let error = serde_json::to_vec(&fixtures["cancellation_ambiguous_store_unavailable"]).unwrap();
    let canonical: PublicError = serde_json::from_slice(&error).expect("valid canonical golden");
    assert_eq!(canonical.code, PublicErrorCode::StoreUnavailable as i32);
    let caps = serde_json::to_vec(&CapabilityResponse {
        api_major: 1,
        schema_digest: positron_api::generated::SchemaDigest::canonical()
            .as_str()
            .into(),
        capability: positron_api::generated::Capability::QueryTail as i32,
        availability: CapabilityAvailability::Implemented as i32,
        ..Default::default()
    })
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        for (path, status, reply) in [
            ("/v1/capabilities:negotiate", 200, caps),
            (CANCEL_HTTP_PATH, 503, error),
        ] {
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(value) => break value,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(2))
                    },
                    other => panic!("bounded accept: {other:?}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert_eq!(line, format!("POST {path} HTTP/1.1\r\n"));
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
            assert!(length <= MAX_CANCEL_REQUEST_BYTES);
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            write!(
                stream,
                "HTTP/1.1 {status} Response\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                reply.len()
            )
            .unwrap();
            stream.write_all(&reply).unwrap();
        }
    });
    let client =
        LogQueryServiceClient::new(LogQueryTransport::PlaintextOptOut { endpoint }).unwrap();
    let failure = client
        .cancel(
            "private-cancellation-credential",
            &LogQueryCancelRequest {
                cursor: Some(log_query_cancel_request::Cursor::Tail(vec![1])),
            },
        )
        .unwrap_err();
    server.join().unwrap();
    assert_eq!(
        failure,
        LogQueryServiceClientFailure::AmbiguousCancellation(PublicErrorCode::StoreUnavailable)
    );
    assert_eq!(failure.completion_state(), CompletionState::Ambiguous);
    assert_eq!(failure.retry_class(), RetryClass::Never);
}

#[test]
fn cancellation_refuses_forged_uncertainty_and_preserves_definite_rejection() {
    let fixtures: serde_json::Value = serde_json::from_str(include_str!(
        "../../../api/positron/v1/query-error-fixtures.json"
    ))
    .unwrap();
    let valid = serde_json::to_vec(&fixtures["cancellation_ambiguous_store_unavailable"]).unwrap();
    assert_eq!(
        decode_query_rejection(503, &valid),
        LogQueryServiceClientFailure::Transport
    );
    for field in ["retryClass", "source", "completionState", "code"] {
        let mut forged = fixtures["cancellation_ambiguous_store_unavailable"].clone();
        forged[field] = match field {
            "retryClass" => serde_json::json!("RETRY_CLASS_AFTER_BACKOFF"),
            "source" => serde_json::json!("FAILURE_SOURCE_HTTP_DECODE"),
            "completionState" => serde_json::json!("COMPLETION_STATE_UNSPECIFIED"),
            _ => serde_json::json!(999),
        };
        assert_eq!(
            decode_cancellation_rejection(503, &serde_json::to_vec(&forged).unwrap()),
            LogQueryServiceClientFailure::Transport
        );
    }
    let definite =
        decode_cancellation_rejection(503, &query_rejection(503, "store_unavailable").unwrap());
    assert_eq!(definite, LogQueryServiceClientFailure::StoreUnavailable);
    assert_eq!(definite.completion_state(), CompletionState::Rejected);
    assert_eq!(definite.retry_class(), RetryClass::AfterBackoff);
    assert!(
        cancellation_rejection(503, "store_unavailable", CompletionState::Unspecified).is_err()
    );
}
