use super::{ValidatedOperations, write_generated};
use std::error::Error;

pub(super) fn generate(operations: &ValidatedOperations) -> Result<(), Box<dyn Error>> {
    let operation = operations.operation("positron.v1.LogQueryService/Execute")?;
    write_generated(
        "log_query_service_client.rs",
        format!(
            r#"
// Generated from canonical LogQueryService/Execute and its HTTP mapping.
pub const HTTP_PATH: &str = {path:?};
pub const MAX_REQUEST_BYTES: usize = {request_limit};
pub const MAX_RESPONSE_BYTES: usize = {response_limit};
pub struct LogQueryServiceClient {{ http: crate::http_client::HttpClient }}
impl LogQueryServiceClient {{
    pub fn new(transport: super::LogQueryTransport) -> Result<Self, super::LogQueryServiceClientFailure> {{
        Ok(Self {{ http: crate::http_client::HttpClient::new(transport).map_err(|_| super::LogQueryServiceClientFailure::Transport)? }})
    }}
    pub fn execute(&self, bearer: &str, request: &super::LogQueryRequest) -> Result<super::LogQueryResponse, super::LogQueryServiceClientFailure> {{
        let body = request.encode().map_err(|_| super::LogQueryServiceClientFailure::InvalidRequest)?;
        let (status, bytes) = self.http.post(bearer, HTTP_PATH, body, MAX_RESPONSE_BYTES).map_err(|_| super::LogQueryServiceClientFailure::Transport)?;
        if status != 200 {{ return Err(super::client_failure(status, &bytes)); }}
        super::LogQueryResponse::decode(&bytes).map_err(|_| super::LogQueryServiceClientFailure::Transport)
    }}
}}
"#,
            path = operation.path(),
            request_limit = operation.request_limit(),
            response_limit = operation.response_limit()
        ),
    )
}
