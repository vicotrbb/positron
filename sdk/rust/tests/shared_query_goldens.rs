//! The portable v1 corpus is shared by generated SDKs, not Rust constructors.
use positron_sdk::api_keys::protobuf::{CompletionState, RetryClass};
use positron_sdk::log_query::*;
use serde_json::Value;

#[test]
fn shared_query_goldens_preserve_values_and_refuse_invalid_wire_outcomes() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../api/positron/v1/query-golden-fixtures.json"
    ))
    .expect("portable JSON");
    for case in corpus["representations"]
        .as_array()
        .expect("representations")
    {
        let input = case["input"].as_str().expect("raw JSON input");
        let actual = match case["type"].as_str().expect("public type") {
            "LogQueryValue" => {
                serde_json::from_str::<LogQueryValue>(input).and_then(serde_json::to_value)
            },
            "LogQueryCell" => {
                serde_json::from_str::<LogQueryCell>(input).and_then(serde_json::to_value)
            },
            "LogQuerySessionRequest" => LogQuerySessionRequest::decode(input.as_bytes())
                .map_err(|_| serde::de::Error::custom("invalid session"))
                .and_then(serde_json::to_value),
            _ => panic!("unknown public fixture type"),
        };
        if case["accepted"] == true {
            assert_eq!(
                actual.expect("accepted golden"),
                case["canonical"],
                "{}",
                case["id"]
            );
        } else {
            assert!(actual.is_err(), "{}", case["id"]);
        }
    }
    for case in corpus["responses"].as_array().expect("responses") {
        let input = serde_json::to_vec(&case["input"]).unwrap();
        let actual = match case["mode"].as_str().unwrap_or("execute") {
            "tail" => LogQueryResponse::decode_tail(&input),
            "session" => LogQueryResponse::decode_session(&input),
            "execute" => LogQueryResponse::decode(&input),
            _ => panic!("unknown response mode"),
        };
        assert_eq!(actual.is_ok(), case["accepted"], "{}", case["id"]);
        if let Ok(response) = actual {
            let encoded = match case["mode"].as_str().unwrap_or("execute") {
                "tail" => response.encode_tail(),
                "session" => response.encode_session(),
                "execute" => response.encode(),
                _ => panic!("unknown response mode"),
            };
            assert_eq!(
                serde_json::from_slice::<Value>(&encoded.unwrap()).unwrap(),
                case["input"]
            );
        }
    }
    for case in corpus["errors"].as_array().expect("errors") {
        let bytes = serde_json::to_vec(&case["input"]).unwrap();
        let status = u16::try_from(case["status"].as_u64().unwrap()).unwrap();
        let failure = if case["cancellation"] == true {
            decode_cancellation_rejection(status, &bytes)
        } else {
            decode_query_rejection(status, &bytes)
        };
        assert_eq!(
            format!("{failure:?}"),
            case["failure"].as_str().unwrap(),
            "{}",
            case["id"]
        );
        assert_eq!(failure.retry_class().as_str_name(), case["retryClass"]);
        assert_eq!(
            failure.completion_state().as_str_name(),
            case["completionState"]
        );
        if let Some(code) = case["rejection"].as_str() {
            let canonical = query_rejection(status, code).unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&canonical).unwrap(),
                case["input"]
            );
        }
        assert_ne!(failure.retry_class(), RetryClass::Unspecified);
        assert_ne!(failure.completion_state(), CompletionState::Unspecified);
    }
}

#[test]
fn shared_compatibility_goldens_negotiate_or_refuse_before_execution() {
    use positron_sdk::generated::{CapabilityService, Transport};
    let corpus: Value = serde_json::from_str(include_str!(
        "../api/positron/v1/query-golden-fixtures.json"
    ))
    .unwrap();
    for case in corpus["compatibility"]
        .as_array()
        .expect("shared compatibility cases")
    {
        let outcome = CapabilityService::decode_and_negotiate(
            Transport::HttpJson,
            case["input"].as_str().unwrap().as_bytes(),
        );
        if let Some(code) = case["decodeError"].as_str() {
            assert_eq!(outcome.unwrap_err().code().as_str_name(), code);
        } else {
            let response = outcome.unwrap();
            assert_eq!(response.availability().as_str_name(), case["availability"]);
            assert_eq!(
                response.refusal().map(|error| error.code().as_str_name()),
                case["refusal"].as_str()
            );
        }
    }
}

fn tail_golden(id: &str) -> LogQueryResponse {
    let corpus: Value = serde_json::from_str(include_str!(
        "../api/positron/v1/query-golden-fixtures.json"
    ))
    .unwrap();
    let case = corpus["responses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == id)
        .expect("named Tail golden");
    serde_json::from_value(case["input"].clone()).expect("typed public response")
}

#[test]
fn tail_refuses_historical_continued_without_advancing_receipt() {
    let invalid = tail_golden("tail-continued-refused");
    let bytes = serde_json::to_vec(&invalid).unwrap();
    let mut tracker = BatchTracker::tail();
    assert!(tracker.filter(&invalid).is_err());
    assert!(LogQueryResponse::decode_tail(&bytes).is_err());
    assert!(invalid.encode_tail().is_err());
    assert!(tracker.acknowledgement().is_none());
    let first = tail_golden("tail-single-incomplete");
    assert_eq!(tracker.filter(&first).unwrap().len(), 1);
    let receipt = tracker.acknowledgement();
    assert!(tracker.filter(&invalid).is_err());
    assert_eq!(tracker.acknowledgement(), receipt);
    assert!(tracker.filter(&first).unwrap().is_empty());
    let next = tail_golden("tail-next-incomplete");
    assert_eq!(tracker.filter(&next).unwrap().len(), 1);
    assert!(tracker.filter(&next).unwrap().is_empty());
}

#[test]
fn tail_refuses_multiple_pending_batches_without_advancing_receipt() {
    for id in [
        "tail-multiple-continued-refused",
        "tail-multiple-batches-refused",
    ] {
        let invalid = tail_golden(id);
        let bytes = serde_json::to_vec(&invalid).unwrap();
        let mut tracker = BatchTracker::tail();
        assert!(tracker.filter(&invalid).is_err(), "{id}");
        assert!(LogQueryResponse::decode_tail(&bytes).is_err(), "{id}");
        assert!(invalid.encode_tail().is_err(), "{id}");
        assert!(tracker.acknowledgement().is_none());
        let first = tail_golden("tail-single-incomplete");
        assert_eq!(tracker.filter(&first).unwrap().len(), 1);
        let receipt = tracker.acknowledgement();
        assert!(tracker.filter(&invalid).is_err(), "{id}");
        assert_eq!(tracker.acknowledgement(), receipt);
        assert!(tracker.filter(&first).unwrap().is_empty());
        let next = tail_golden("tail-next-incomplete");
        assert_eq!(tracker.filter(&next).unwrap().len(), 1);
        assert!(tracker.filter(&next).unwrap().is_empty());
    }
}

#[test]
fn tail_preserves_one_pending_batch_and_discards_verified_replays() {
    let first = tail_golden("tail-single-incomplete");
    let mut tracker = BatchTracker::tail();
    assert_eq!(tracker.filter(&first).unwrap().len(), 1);
    assert_eq!(
        tracker.acknowledgement(),
        Some(LogQueryAcknowledgement {
            sequence: 0,
            digest: vec![2; 32],
        })
    );
    let mut replay = first.clone();
    let Some(log_query_event::Event::Batch(batch)) = replay.events[1].event.as_mut() else {
        panic!("batch golden");
    };
    batch.rows[0].replayed = true;
    assert!(tracker.filter(&replay).unwrap().is_empty());
    let next = tail_golden("tail-next-incomplete");
    assert_eq!(tracker.filter(&next).unwrap().len(), 1);
    assert!(tracker.filter(&next).unwrap().is_empty());
}
