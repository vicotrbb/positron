//! Bounded irreversible tenant purge administration within managed scope.
pub use crate::api_keys::ApiKeyTransport as TenantPurgeTransport;
pub use crate::maintenance::MaintenanceServiceClientFailure as TenantPurgeServiceClientFailure;
use crate::maintenance::MaintenanceWireFailure;
use crate::provider_migration::{ProviderMigrationOperation, operation_id};
use serde::{Deserialize, Serialize};
mod client {
    include!(concat!(env!("OUT_DIR"), "/tenant_purge_service_client.rs"));
}
pub use client::TenantPurgeServiceClient;
pub const HTTP_PATH: &str = "/v1/tenant-purges:manage";
pub const MAX_REQUEST_BYTES: usize = 4096;
pub const MAX_RESPONSE_BYTES: usize = 4096;
pub const MANAGED_SCOPE: &str = "managed_repositories_only;unmanaged_copies_not_revoked";
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantPurgeRequest {
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation_slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_catalog_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_lifecycle_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
}
impl TenantPurgeRequest {
    pub fn decode(bytes: &[u8]) -> Result<Self, MaintenanceWireFailure> {
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(MaintenanceWireFailure);
        }
        let request: Self = serde_json::from_slice(bytes).map_err(|_| MaintenanceWireFailure)?;
        request.validate()?;
        Ok(request)
    }
    pub fn encode(&self) -> Result<Vec<u8>, MaintenanceWireFailure> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| MaintenanceWireFailure)?;
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(MaintenanceWireFailure);
        }
        Ok(bytes)
    }
    fn validate(&self) -> Result<(), MaintenanceWireFailure> {
        let mutation = self.expected_catalog_generation.is_some_and(|n| n > 0)
            && self
                .idempotency_key
                .as_deref()
                .is_some_and(crate::validation::identifier);
        let no_tenant = self.tenant_id.is_none()
            && self.confirmation_slug.is_none()
            && self.expected_lifecycle_generation.is_none();
        let valid = match self.action.as_str() {
            "start" => {
                mutation
                    && self.operation_id.is_none()
                    && self
                        .tenant_id
                        .as_deref()
                        .is_some_and(crate::validation::identifier)
                    && self.expected_lifecycle_generation.is_some_and(|n| n > 0)
                    && self.confirmation_slug.as_deref().is_some_and(|slug| {
                        !slug.is_empty()
                            && slug.len() <= 63
                            && slug
                                .bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                            && !slug.starts_with('-')
                            && !slug.ends_with('-')
                    })
            },
            "status" => {
                no_tenant
                    && self.operation_id.as_deref().is_some_and(operation_id)
                    && self.expected_catalog_generation.is_none()
                    && self.idempotency_key.is_none()
            },
            "lookup" => {
                no_tenant
                    && self.operation_id.is_none()
                    && self.expected_catalog_generation.is_none()
                    && self
                        .idempotency_key
                        .as_deref()
                        .is_some_and(crate::validation::identifier)
            },
            "cancel" => {
                no_tenant && mutation && self.operation_id.as_deref().is_some_and(operation_id)
            },
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(MaintenanceWireFailure)
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantPurgeResponse {
    pub catalog_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<ProviderMigrationOperation>,
    pub managed_scope: String,
}
impl TenantPurgeResponse {
    pub fn encode(&self) -> Result<Vec<u8>, MaintenanceWireFailure> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| MaintenanceWireFailure)?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(MaintenanceWireFailure);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, MaintenanceWireFailure> {
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(MaintenanceWireFailure);
        }
        let response: Self = serde_json::from_slice(bytes).map_err(|_| MaintenanceWireFailure)?;
        response.validate()?;
        Ok(response)
    }
    fn validate(&self) -> Result<(), MaintenanceWireFailure> {
        if self.catalog_generation == 0 || self.managed_scope != MANAGED_SCOPE {
            return Err(MaintenanceWireFailure);
        }
        if let Some(operation) = &self.operation {
            operation.validate()?;
        }
        Ok(())
    }
}
