use super::{ValidatedOperations, write_generated};
use std::error::Error;

pub(super) fn generate(operations: &ValidatedOperations) -> Result<(), Box<dyn Error>> {
    let operation = operations.operation("positron.v1.LogQueryService/Execute")?;
    let session = operations.operation("positron.v1.LogQueryService/Session")?;
    let cancel = operations.operation("positron.v1.LogQueryService/Cancel")?;
    write_generated(
        "log_query_service_client.rs",
        format!(
            r#"
// Generated from the canonical LogQueryService and its HTTP mapping.
pub const HTTP_PATH: &str = {path:?};
pub const CANCEL_HTTP_PATH: &str = {cancel_path:?};
pub const MAX_SESSION_REQUEST_BYTES: usize = {session_request_limit};
pub const MAX_CANCEL_REQUEST_BYTES: usize = {cancel_request_limit};
pub const MAX_CANCEL_RESPONSE_BYTES: usize = {cancel_response_limit};
pub const SESSION_HTTP_PATH: &str = {session_path:?};
pub const MAX_REQUEST_BYTES: usize = {request_limit};
pub const MAX_RESPONSE_BYTES: usize = {response_limit};
pub fn is_query_path(path: &str) -> bool {{ matches!(path, HTTP_PATH | SESSION_HTTP_PATH | CANCEL_HTTP_PATH) }}
pub struct LogQueryServiceClient {{ http: crate::http_client::HttpClient }}
impl LogQueryServiceClient {{
    pub fn cancel(&self, bearer: &str, request: &super::LogQueryCancelRequest) -> Result<super::LogQueryCancelResponse, super::LogQueryServiceClientFailure> {{
        let body = request.encode().map_err(|_| super::LogQueryServiceClientFailure::InvalidRequest)?;
        let capability = match request.cursor {{
            Some(super::log_query_cancel_request::Cursor::Tail(_)) => crate::generated::Capability::QueryTail,
            _ => crate::generated::Capability::QuerySessions,
        }};
        super::require_capability(&self.http, bearer, capability)?;
        let (status, bytes) = self.http.post_query(bearer, CANCEL_HTTP_PATH, body, MAX_CANCEL_RESPONSE_BYTES).map_err(|_| super::LogQueryServiceClientFailure::Transport)?;
        if status != 200 {{ return Err(super::decode_cancellation_rejection(status, &bytes)); }}
        let response: super::LogQueryCancelResponse = serde_json::from_slice(&bytes).map_err(|_| super::LogQueryServiceClientFailure::Transport)?;
        if !response.cancelled {{ return Err(super::LogQueryServiceClientFailure::Transport); }}
        Ok(response)
    }}
    pub fn session(&self, bearer: &str, request: &super::LogQuerySessionRequest) -> Result<super::LogQueryResponse, super::LogQueryServiceClientFailure> {{
        let body = request.encode().map_err(|_| super::LogQueryServiceClientFailure::InvalidRequest)?;
        let capability = if matches!(request.operation, Some(super::log_query_session_request::Operation::Tail(_))) {{ crate::generated::Capability::QueryTail }} else {{ crate::generated::Capability::QuerySessions }};
        super::require_capability(&self.http, bearer, capability)?;
        let (status, bytes) = self.http.post_query(bearer, SESSION_HTTP_PATH, body, MAX_RESPONSE_BYTES).map_err(|_| super::LogQueryServiceClientFailure::Transport)?;
        if status != 200 {{ return Err(super::client_failure(status, &bytes)); }}
        if matches!(request.operation, Some(super::log_query_session_request::Operation::Tail(_))) {{
            super::LogQueryResponse::decode_tail(&bytes)
        }} else {{ super::LogQueryResponse::decode_session(&bytes) }}.map_err(|_| super::LogQueryServiceClientFailure::Transport)
    }}
    pub fn new(transport: super::LogQueryTransport) -> Result<Self, super::LogQueryServiceClientFailure> {{
        Ok(Self {{ http: crate::http_client::HttpClient::new(transport).map_err(|_| super::LogQueryServiceClientFailure::Transport)? }})
    }}
    pub fn execute(&self, bearer: &str, request: &super::LogQueryRequest) -> Result<super::LogQueryResponse, super::LogQueryServiceClientFailure> {{
        let body = request.encode().map_err(|_| super::LogQueryServiceClientFailure::InvalidRequest)?;
        let (status, bytes) = self.http.post_query(bearer, HTTP_PATH, body, MAX_RESPONSE_BYTES).map_err(|_| super::LogQueryServiceClientFailure::Transport)?;
        if status != 200 {{ return Err(super::client_failure(status, &bytes)); }}
        super::LogQueryResponse::decode(&bytes).map_err(|_| super::LogQueryServiceClientFailure::Transport)
    }}
}}
"#,
            path = operation.path(),
            cancel_path = cancel.path(),
            cancel_request_limit = cancel.request_limit(),
            cancel_response_limit = cancel.response_limit(),
            session_request_limit = session.request_limit(),
            session_path = session.path(),
            request_limit = operation.request_limit(),
            response_limit = operation.response_limit()
        ),
    )
}
