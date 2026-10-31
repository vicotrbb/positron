use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, ExportLogsServiceResponse,
};
use prost::Message;
use std::time::{Duration, Instant};

use super::support::{HttpEncoding, LiveHttpHarness};

#[test]
fn empty_exports_succeed_in_both_otlp_encodings() -> Result<(), Box<dyn std::error::Error>> {
    let harness = LiveHttpHarness::start("http-empty")?;
    for encoding in [HttpEncoding::Protobuf, HttpEncoding::Json] {
        let response = harness.export_admitted(
            encoding,
            ExportLogsServiceRequest::default(),
            Instant::now() + Duration::from_secs(5),
        )?;
        assert_eq!(response.status(), 200, "encoding={}", encoding.label());
        let decoded = match encoding {
            HttpEncoding::Protobuf => ExportLogsServiceResponse::decode(response.body())?,
            HttpEncoding::Json => serde_json::from_slice(response.body())?,
        };
        assert_eq!(decoded, ExportLogsServiceResponse::default());
    }
    Ok(())
}

#[test]
fn omitted_json_resource_logs_is_an_empty_export() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let harness = LiveHttpHarness::start("http-empty-omitted")?;
    for payload in [
        b"{}".as_slice(),
        br#"{"resourceLogs":null}"#,
        br#"{"resourceLogs":[]}"#,
        br#"{"unknown":{"nested":[null,1]}}"#,
    ] {
        for compressed in [false, true] {
            let body = if compressed {
                let mut encoder =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
                encoder.write_all(payload)?;
                encoder.finish()?
            } else {
                payload.to_vec()
            };
            let response = harness.export_body_admitted(
                HttpEncoding::Json,
                compressed.then_some("gzip"),
                &body,
                Instant::now() + Duration::from_secs(5),
            )?;
            assert_eq!(
                response.status(),
                200,
                "gzip={compressed}, body={:?}",
                response.body()
            );
            assert_eq!(
                serde_json::from_slice::<ExportLogsServiceResponse>(response.body())?,
                ExportLogsServiceResponse::default(),
            );
        }
    }
    assert!(
        harness
            .query_log_bodies("logs | range query_time 0 100 | limit 16")?
            .is_empty()
    );
    Ok(())
}
