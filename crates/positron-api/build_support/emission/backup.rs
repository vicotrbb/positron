use super::{ValidatedOperations, write_generated};
use std::error::Error;

pub(super) fn generate(operations: &ValidatedOperations) -> Result<(), Box<dyn Error>> {
    let operation = operations.operation("positron.v1.BackupService/Manage")?;
    let list = operations.operation("positron.v1.BackupService/List")?;
    let source = format!(
        r#"
// Generated from the canonical BackupService/Manage descriptor and HTTP mapping.
pub struct BackupServiceClient {{ http: crate::http_client::HttpClient }}
impl BackupServiceClient {{
    pub fn new(transport: super::BackupTransport) -> Result<Self, super::BackupServiceClientFailure> {{
        let http = crate::http_client::HttpClient::new(transport).map_err(|_| super::BackupServiceClientFailure::Transport)?;
        Ok(Self {{ http }})
    }}
    pub fn manage(&self, bearer: &str, request: &super::BackupRequest) -> Result<super::BackupResponse, super::BackupServiceClientFailure> {{
        use super::BackupServiceClientFailure as Failure;
        let body = request.encode().map_err(|_| Failure::InvalidRequest)?;
        if body.len() > {request_limit} {{ return Err(Failure::InvalidRequest); }}
        let (status, bytes) = self.http.post(bearer, {path:?}, body, {response_limit}).map_err(|_| Failure::Transport)?;
        if !(200..300).contains(&status) {{
            let value = serde_json::from_slice::<serde_json::Value>(&bytes).ok();
            let code = value.as_ref().and_then(|value| value.get("code")?.as_str());
            return Err(match (status, code) {{
                (400, Some("invalid_request")) => Failure::InvalidRequest,
                (401, Some("authentication_rejected")) => Failure::AuthenticationRejected,
                (404, Some("source_unavailable")) => Failure::SourceUnavailable,
                (404, Some("task_unavailable")) => Failure::TaskUnavailable,
                (409, Some("stale_generation")) => Failure::StaleGeneration,
        (409, Some("precondition_failed")) => Failure::PreconditionFailed,
                (409, Some("idempotency_conflict")) => Failure::IdempotencyConflict,
                (503, Some("administration_unavailable")) => Failure::AdministrationUnavailable,
                (503, Some("capacity_unavailable")) => Failure::CapacityUnavailable,
                _ => Failure::Transport,
            }});
        }}
        super::BackupResponse::decode(&bytes).map_err(|_| Failure::Transport)
    }}
    pub fn list(&self, bearer: &str, request: &super::BackupListRequest) -> Result<super::BackupListResponse, super::BackupServiceClientFailure> {{
        use super::BackupServiceClientFailure as Failure;
        let body = request.encode().map_err(|_| Failure::InvalidRequest)?;
        if body.len() > {list_request_limit} {{ return Err(Failure::InvalidRequest); }}
        let (status, bytes) = self.http.post(bearer, {list_path:?}, body, {list_response_limit}).map_err(|_| Failure::Transport)?;
        if !(200..300).contains(&status) {{
            let value = serde_json::from_slice::<serde_json::Value>(&bytes).ok();
            let code = value.as_ref().and_then(|value| value.get("code")?.as_str());
            return Err(match (status, code) {{
                (400, Some("invalid_request")) => Failure::InvalidRequest,
                (401, Some("authentication_rejected")) => Failure::AuthenticationRejected,
                (404, Some("source_unavailable")) => Failure::SourceUnavailable,
                (404, Some("task_unavailable")) => Failure::TaskUnavailable,
                (409, Some("stale_generation")) => Failure::StaleGeneration,
        (409, Some("precondition_failed")) => Failure::PreconditionFailed,
                (409, Some("idempotency_conflict")) => Failure::IdempotencyConflict,
                (503, Some("administration_unavailable")) => Failure::AdministrationUnavailable,
                (503, Some("capacity_unavailable")) => Failure::CapacityUnavailable,
                _ => Failure::Transport,
            }});
        }}
        super::BackupListResponse::decode(&bytes).map_err(|_| Failure::Transport)
    }}
}}
"#,
        list_path = list.path(),
        list_request_limit = list.request_limit(),
        list_response_limit = list.response_limit(),
        path = operation.path(),
        request_limit = operation.request_limit(),
        response_limit = operation.response_limit()
    );
    write_generated("backup_service_client.rs", source)
}
