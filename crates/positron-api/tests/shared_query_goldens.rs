//! The portable v1 corpus is shared by generated SDKs, not Rust constructors.
use positron_api::api_keys::protobuf::{CompletionState, RetryClass};
use positron_api::log_query::*;
use serde_json::Value;

#[test]
fn shared_query_goldens_preserve_values_and_refuse_invalid_wire_outcomes() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../api/positron/v1/query-golden-fixtures.json"
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
        let actual = LogQueryResponse::decode(&input);
        assert_eq!(actual.is_ok(), case["accepted"], "{}", case["id"]);
        if let Ok(response) = actual {
            assert_eq!(
                serde_json::from_slice::<Value>(&response.encode().unwrap()).unwrap(),
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
    use positron_api::generated::{CapabilityService, Transport};
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../api/positron/v1/query-golden-fixtures.json"
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
