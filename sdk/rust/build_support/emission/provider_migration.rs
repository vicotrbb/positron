use super::{ValidatedOperations, write_generated};
use std::error::Error;

pub(super) fn generate(operations: &ValidatedOperations) -> Result<(), Box<dyn Error>> {
    let operation = operations.operation("positron.v1.ProviderMigrationService/Manage")?;
    let source = format!(
        r#"
// Generated from the canonical ProviderMigrationService/Manage descriptor and HTTP mapping.
pub struct ProviderMigrationServiceClient {{ http: crate::http_client::HttpClient }}
impl ProviderMigrationServiceClient {{
    pub fn new(transport: super::ProviderMigrationTransport) -> Result<Self, super::ProviderMigrationServiceClientFailure> {{
        let http = crate::http_client::HttpClient::new(transport).map_err(|_| super::ProviderMigrationServiceClientFailure::Transport)?;
        Ok(Self {{ http }})
    }}
    pub fn manage(&self, bearer: &str, request: &super::ProviderMigrationRequest) -> Result<super::ProviderMigrationResponse, super::ProviderMigrationServiceClientFailure> {{
        use super::ProviderMigrationServiceClientFailure as Failure;
        let body = request.encode().map_err(|_| Failure::InvalidRequest)?;
        if body.len() > {request_limit} {{ return Err(Failure::InvalidRequest); }}
        let (status, bytes) = self.http.post(bearer, {path:?}, body, {response_limit}).map_err(|_| Failure::Transport)?;
        if !(200..300).contains(&status) {{
            return Err(crate::maintenance::administrative_failure(status,&bytes));
        }}
        super::ProviderMigrationResponse::decode(&bytes).map_err(|_| Failure::Transport)
    }}
}}
"#,
        path = operation.path(),
        request_limit = operation.request_limit(),
        response_limit = operation.response_limit()
    );
    write_generated("provider_migration_service_client.rs", source)
}
