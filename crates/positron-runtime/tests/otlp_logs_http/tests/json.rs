use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceResponse;
use std::time::{Duration, Instant};

use super::support::{HttpEncoding, LiveHttpHarness, otlp_request};

#[test]
fn json_export_preserves_native_semantics_and_negotiates_json_response()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = LiveHttpHarness::start("json-success")?;
    let body = HttpEncoding::Json.encode(otlp_request("http-json"))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let response = loop {
        let response = harness.request_before(
            &[
                ("Authorization", format!("Bearer {}", harness.bearer())),
                ("Content-Type", HttpEncoding::Json.content_type().to_owned()),
            ],
            &body,
            Some(deadline),
        )?;
        if Instant::now() >= deadline {
            return Err("OTLP JSON admission exceeded its five-second budget".into());
        }
        if response.status() != 429 {
            break response;
        }
        assert_eq!(response.header("retry-after"), Some("1"));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(response.body())?,
            serde_json::json!({"code": 14, "message": "OTLP Logs ingest capacity is unavailable"}),
        );
        assert!(
            harness
                .query_log_bodies("logs | range query_time 0 100 | limit 16")?
                .is_empty()
        );
        if Instant::now() + Duration::from_secs(1) >= deadline {
            return Err("OTLP JSON admission exceeded its five-second budget".into());
        }
        std::thread::sleep(Duration::from_secs(1));
    };

    assert_eq!(response.status(), 200);
    assert_eq!(response.header("content-type"), Some("application/json"));
    assert!(
        serde_json::from_slice::<ExportLogsServiceResponse>(response.body())?
            .partial_success
            .is_none()
    );
    assert_eq!(
        harness.query_log_bodies("logs | range query_time 0 100 | limit 16")?,
        vec!["http-json"]
    );
    Ok(())
}

#[test]
fn json_container_fanout_is_rejected_before_materializing_decode()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = LiveHttpHarness::start("json-preflight-fanout")?;
    let body = format!("{{\"resourceLogs\":[{}]}}", vec!["{}"; 1_025].join(","));
    let response = harness.export_body(HttpEncoding::Json, None, body.as_bytes())?;

    assert_eq!(response.status(), 400);
    assert_eq!(
        response.body(),
        br#"{"code":3,"message":"OTLP Logs request was rejected"}"#,
    );
    Ok(())
}
