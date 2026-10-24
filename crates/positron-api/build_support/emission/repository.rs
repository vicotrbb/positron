use super::{ValidatedOperations, write_generated};
use std::error::Error;

pub(super) fn generate(operations: &ValidatedOperations) -> Result<(), Box<dyn Error>> {
    let operation = operations.operation("positron.v1.RepositoryService/Manage")?;
    let source = format!(
        r#"
// Generated from the canonical RepositoryService/Manage descriptor and HTTP mapping.
pub struct RepositoryServiceClient {{ http: crate::http_client::HttpClient }}
impl RepositoryServiceClient {{
    pub fn new(transport: super::RepositoryTransport) -> Result<Self, super::RepositoryServiceClientFailure> {{
        let http = crate::http_client::HttpClient::new(transport).map_err(|_| super::RepositoryServiceClientFailure::Transport)?;
        Ok(Self {{ http }})
    }}
    pub fn manage(&self, bearer: &str, request: &super::RepositoryRequest) -> Result<super::RepositoryResponse, super::RepositoryServiceClientFailure> {{
        self.manage_with_timeout(bearer, request, crate::http_client::DEFAULT_REQUEST_TIMEOUT)
    }}
    /// Bounds this request by the supplied duration, capped at the default five seconds.
    pub fn manage_with_timeout(&self, bearer: &str, request: &super::RepositoryRequest, timeout: std::time::Duration) -> Result<super::RepositoryResponse, super::RepositoryServiceClientFailure> {{
        use super::RepositoryServiceClientFailure as Failure;
        let body = request.encode().map_err(|_| Failure::InvalidRequest)?;
        if body.len() > {request_limit} {{ return Err(Failure::InvalidRequest); }}
        let (status, bytes) = self.http.post_with_timeout(bearer, {path:?}, body, {response_limit}, timeout).map_err(|_| Failure::Transport)?;
        if !(200..300).contains(&status) {{
            return Err(crate::maintenance::administrative_failure(status,&bytes));
        }}
        super::RepositoryResponse::decode(&bytes).map_err(|_| Failure::Transport)
    }}
    /// Opts into a bounded request allowance capped at the API listener default of 30 seconds.
    /// This does not discover or negotiate a custom server deadline.
    pub fn manage_with_default_listener_timeout(&self, bearer: &str, request: &super::RepositoryRequest, timeout: std::time::Duration) -> Result<super::RepositoryResponse, super::RepositoryServiceClientFailure> {{
        use super::RepositoryServiceClientFailure as Failure;
        let timeout = timeout.min(crate::http_client::DEFAULT_LISTENER_REQUEST_TIMEOUT);
        let deadline = std::time::Instant::now().checked_add(timeout).ok_or(Failure::Transport)?;
        if timeout.is_zero() {{ return Err(Failure::Transport); }}
        let result = (|| {{
        let body = request.encode().map_err(|_| Failure::InvalidRequest)?;
        if body.len() > {request_limit} {{ return Err(Failure::InvalidRequest); }}
        let (status, bytes) = self.http.post_with_default_listener_timeout(bearer, {path:?}, body, {response_limit}, deadline.saturating_duration_since(std::time::Instant::now())).map_err(|_| Failure::Transport)?;
        if !(200..300).contains(&status) {{
            return Err(crate::maintenance::administrative_failure(status,&bytes));
        }}
        super::RepositoryResponse::decode(&bytes).map_err(|_| Failure::Transport)
        }})();
        if std::time::Instant::now() >= deadline {{ Err(Failure::Transport) }} else {{ result }}
    }}
}}
"#,
        path = operation.path(),
        request_limit = operation.request_limit(),
        response_limit = operation.response_limit()
    );
    write_generated("repository_service_client.rs", source)
}
