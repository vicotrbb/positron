use super::{ValidatedOperations, write_generated};
use std::error::Error;

pub(super) fn generate(operations: &ValidatedOperations) -> Result<(), Box<dyn Error>> {
    let operation = operations.operation("positron.v1.TenantPurgeService/Manage")?;
    let source = format!(
        r#"
// Generated from the canonical TenantPurgeService/Manage descriptor and HTTP mapping.
pub struct TenantPurgeServiceClient {{ http: crate::http_client::HttpClient }}
impl TenantPurgeServiceClient {{
    pub fn new(transport: super::TenantPurgeTransport) -> Result<Self, super::TenantPurgeServiceClientFailure> {{
        let http = crate::http_client::HttpClient::new(transport).map_err(|_| super::TenantPurgeServiceClientFailure::Transport)?;
        Ok(Self {{ http }})
    }}
    pub fn manage(&self, bearer: &str, request: &super::TenantPurgeRequest) -> Result<super::TenantPurgeResponse, super::TenantPurgeServiceClientFailure> {{
        use super::TenantPurgeServiceClientFailure as Failure;
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
                (409, Some("precondition_failed")) => Failure::PreconditionFailed,
                (409, Some("idempotency_conflict")) => Failure::IdempotencyConflict,
                (503, Some("administration_unavailable")) => Failure::AdministrationUnavailable,
                _ => Failure::Transport,
            }});
        }}
        super::TenantPurgeResponse::decode(&bytes).map_err(|_| Failure::Transport)
    }}
}}
"#,
        path = operation.path(),
        request_limit = operation.request_limit(),
        response_limit = operation.response_limit()
    );
    write_generated("tenant_purge_service_client.rs", source)
}
