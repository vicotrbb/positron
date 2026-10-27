use std::time::Duration;

use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, logs_service_client::LogsServiceClient,
};
use opentelemetry_proto::tonic::logs::v1::ResourceLogs;
use positron_runtime::{ExitOutcome, ShutdownTrigger};
use tonic::Code;

use super::support::{LiveGrpcHarness, otlp_request};

#[tokio::test(flavor = "current_thread")]
async fn structural_amplification_is_rejected_before_handler_and_releases_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = LiveGrpcHarness::start("structural-amplification")?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        LogsServiceClient::connect(format!("http://{}", harness.endpoint())),
    )
    .await??;
    let amplified = harness.authorize(tonic::Request::new(ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs::default(); 1_025],
    }))?;

    let failure = tokio::time::timeout(Duration::from_secs(2), client.export(amplified))
        .await?
        .expect_err("structural fanout above the receiver limit must be rejected");

    assert_eq!(failure.code(), Code::InvalidArgument);

    let follow_up = harness.authorize(tonic::Request::new(otlp_request("after-preflight")))?;
    let (metadata, _, body) = follow_up.into_parts();
    // Only this single-record positive probe may replay explicit precommit
    // capacity. A persistent admission leak still exhausts the same deadline.
    let response = super::authentication::single_record_export(
        tokio::time::Instant::now() + Duration::from_secs(2),
        || {
            let mut client = client.clone();
            let mut request = tonic::Request::new(body.clone());
            *request.metadata_mut() = metadata.clone();
            async move { client.export(request).await }
        },
    )
    .await?;
    assert!(response.into_inner().partial_success.is_none());
    assert_eq!(
        harness.query_log_bodies("logs | range query_time 0 100 | limit 16")?,
        vec!["after-preflight"]
    );
    drop(client);
    assert_eq!(
        harness.shutdown(ShutdownTrigger::FirstSignal).await?,
        ExitOutcome::Graceful
    );
    Ok(())
}
