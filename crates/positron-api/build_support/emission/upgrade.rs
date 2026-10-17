use super::{ValidatedOperations, write_generated};
use std::error::Error;

pub(super) fn generate(operations: &ValidatedOperations) -> Result<(), Box<dyn Error>> {
    let operation = operations.operation("positron.v1.UpgradeService/Manage")?;
    let source = format!(
        r#"
// Generated from the canonical UpgradeService/Manage descriptor and HTTP mapping.
pub struct UpgradeServiceClient {{ http: crate::http_client::HttpClient }}
impl UpgradeServiceClient {{
    pub fn new(transport: super::UpgradeTransport) -> Result<Self, super::UpgradeServiceClientFailure> {{
        let http = crate::http_client::HttpClient::new(transport).map_err(|_| super::UpgradeServiceClientFailure::Transport)?;
        Ok(Self {{ http }})
    }}
    pub fn manage(&self, bearer: &str, request: &super::UpgradeRequest) -> Result<super::UpgradeResponse, super::UpgradeServiceClientFailure> {{
        use super::UpgradeServiceClientFailure as Failure;
        let body = request.encode().map_err(|_| Failure::InvalidRequest)?;
        if body.len() > {request_limit} {{ return Err(Failure::InvalidRequest); }}
        let (status, bytes) = self.http.post(bearer, {path:?}, body, {response_limit}).map_err(|_| Failure::Transport)?;
        if !(200..300).contains(&status) {{
            return Err(crate::maintenance::administrative_failure(status,&bytes));
        }}
        super::UpgradeResponse::decode(&bytes).map_err(|_| Failure::Transport)
    }}
}}
"#,
        path = operation.path(),
        request_limit = operation.request_limit(),
        response_limit = operation.response_limit()
    );
    write_generated("upgrade_service_client.rs", source)
}
