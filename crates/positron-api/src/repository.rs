//! Canonical bounded native Repository administration HTTP projection.
pub use crate::api_keys::ApiKeyTransport as RepositoryTransport;
pub use crate::maintenance::MaintenanceServiceClientFailure as RepositoryServiceClientFailure;
use crate::maintenance::MaintenanceWireFailure;
pub use crate::provider_migration::ProviderMigrationOperation as RepositoryOperation;
use serde::{Deserialize, Serialize};
mod client {
    include!(concat!(env!("OUT_DIR"), "/repository_service_client.rs"));
}
pub use client::RepositoryServiceClient;
pub const HTTP_PATH: &str = "/v1/repositories:manage";
pub const MAX_REQUEST_BYTES: usize = 4096;
pub const MAX_RESPONSE_BYTES: usize = 4096;
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryRequest {
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_catalog_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
}
impl std::fmt::Debug for RepositoryRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepositoryRequest")
            .field("action", &self.action)
            .finish_non_exhaustive()
    }
}
impl RepositoryRequest {
    pub fn encode(&self) -> Result<Vec<u8>, MaintenanceWireFailure> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| MaintenanceWireFailure)?;
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(MaintenanceWireFailure);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, MaintenanceWireFailure> {
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(MaintenanceWireFailure);
        }
        let input: Self = serde_json::from_slice(bytes).map_err(|_| MaintenanceWireFailure)?;
        input.validate()?;
        Ok(input)
    }
    fn validate(&self) -> Result<(), MaintenanceWireFailure> {
        if self
            .operation_id
            .as_deref()
            .is_some_and(|value| !crate::provider_migration::operation_id(value))
            || self
                .idempotency_key
                .as_deref()
                .is_some_and(|value| !crate::validation::identifier(value))
            || self
                .repository_id
                .as_deref()
                .is_some_and(|value| !crate::validation::identifier(value))
            || self.locator.as_deref().is_some_and(|path| {
                !path.starts_with('/')
                    || path.len() > 2048
                    || path.contains('\0')
                    || path.split('/').any(|part| matches!(part, "." | ".."))
            })
        {
            return Err(MaintenanceWireFailure);
        }
        let mutation = self
            .expected_catalog_generation
            .is_some_and(|generation| generation > 0)
            && self.idempotency_key.is_some();
        let no_locator = self.locator.is_none() && self.repository_id.is_none();
        let valid = match self.action.as_str() {
            "init" | "verify" | "doctor" => {
                mutation
                    && self.locator.is_some()
                    && self.repository_id.is_some()
                    && self.operation_id.is_none()
            },
            "status" => {
                no_locator
                    && self.expected_catalog_generation.is_none()
                    && self.idempotency_key.is_none()
            },
            "lookup" => {
                no_locator
                    && self.expected_catalog_generation.is_none()
                    && self.idempotency_key.is_some()
                    && self.operation_id.is_none()
            },
            "cancel" => no_locator && mutation && self.operation_id.is_some(),
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
pub struct RepositoryIdentity {
    pub repository_id: String,
    pub instance_id: String,
    pub provider_kind: String,
    pub format_epoch: u32,
    pub integrity_fingerprint: String,
    pub prefix_commitment: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryDoctorResult {
    pub verified: bool,
    pub probes_deleted: bool,
    pub external_retention: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryResponse {
    pub catalog_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<RepositoryOperation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<RepositoryIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doctor: Option<RepositoryDoctorResult>,
}
impl RepositoryResponse {
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
        let value: Self = serde_json::from_slice(bytes).map_err(|_| MaintenanceWireFailure)?;
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), MaintenanceWireFailure> {
        if self.catalog_generation == 0 {
            return Err(MaintenanceWireFailure);
        }
        if let Some(operation) = &self.operation {
            operation.validate()?;
        }
        if let Some(identity) = &self.identity {
            let hash = |text: &str| {
                text.len() == 64
                    && text.bytes().any(|byte| byte != b'0')
                    && text
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            };
            if !crate::validation::identifier(&identity.repository_id)
                || !crate::validation::identifier(&identity.instance_id)
                || identity.provider_kind != "local_filesystem"
                || identity.format_epoch != 1
                || !hash(&identity.integrity_fingerprint)
                || !hash(&identity.prefix_commitment)
            {
                return Err(MaintenanceWireFailure);
            }
        }
        if let Some(report) = &self.doctor
            && (!report.verified
                || !report.probes_deleted
                || report.external_retention != "not_observable"
                || self
                    .operation
                    .as_ref()
                    .is_none_or(|operation| operation.status != "succeeded"))
        {
            return Err(MaintenanceWireFailure);
        }
        Ok(())
    }
}
