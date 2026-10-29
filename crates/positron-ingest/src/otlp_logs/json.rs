use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::logs::v1::ResourceLogs;

use super::ReceiveFailure;

// The generated request's serde Vec requires a field that ProtoJSON permits
// to be omitted or null. Keep nested message decoding with the generated types.
#[derive(serde::Deserialize)]
struct Request {
    #[serde(rename = "resourceLogs")]
    resource_logs: Option<Vec<ResourceLogs>>,
}

pub(super) fn decode(bytes: &[u8]) -> Result<ExportLogsServiceRequest, ReceiveFailure> {
    let request: Request =
        serde_json::from_slice(bytes).map_err(|_| ReceiveFailure::MalformedPayload)?;
    Ok(ExportLogsServiceRequest {
        resource_logs: request.resource_logs.unwrap_or_default(),
    })
}
