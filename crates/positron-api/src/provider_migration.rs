//! Bounded online root-provider migration administration.
pub use crate::api_keys::ApiKeyTransport as ProviderMigrationTransport;
pub use crate::maintenance::MaintenanceServiceClientFailure as ProviderMigrationServiceClientFailure;
use crate::maintenance::MaintenanceWireFailure;
use serde::{Deserialize, Serialize};
mod client {
    include!(concat!(
        env!("OUT_DIR"),
        "/provider_migration_service_client.rs"
    ));
}
pub use client::ProviderMigrationServiceClient;

pub const HTTP_PATH: &str = "/v1/key-provider-migrations:manage";
pub const MAX_REQUEST_BYTES: usize = 4096;
pub const MAX_RESPONSE_BYTES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderMigrationRequest {
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_catalog_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
}

impl ProviderMigrationRequest {
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
        if self
            .operation_id
            .as_deref()
            .is_some_and(|value| !operation_id(value))
        {
            return Err(MaintenanceWireFailure);
        }
        if self.configuration_reference.as_deref().is_some_and(|path| {
            !path.starts_with('/')
                || path.len() > 2048
                || path.contains('\0')
                || path.split('/').any(|part| matches!(part, "." | ".."))
        }) {
            return Err(MaintenanceWireFailure);
        }
        match self.action.as_str() {
            "status"
                if self.configuration_reference.is_none()
                    && self.idempotency_key.is_none()
                    && self.expected_catalog_generation.is_none() =>
            {
                Ok(())
            },
            "lookup"
                if self.configuration_reference.is_none()
                    && self.operation_id.is_none()
                    && self.expected_catalog_generation.is_none()
                    && self
                        .idempotency_key
                        .as_deref()
                        .is_some_and(crate::validation::identifier) =>
            {
                Ok(())
            },
            "cancel_operation"
                if self.configuration_reference.is_none() && self.operation_id.is_some() =>
            {
                self.mutation_identity()
            },
            "prepare" | "activate" | "verify" | "retire"
                if self.configuration_reference.is_some() && self.operation_id.is_none() =>
            {
                self.mutation_identity()
            },
            "cancel" | "resume"
                if self.configuration_reference.is_none() && self.operation_id.is_none() =>
            {
                self.mutation_identity()
            },
            _ => Err(MaintenanceWireFailure),
        }
    }
    fn mutation_identity(&self) -> Result<(), MaintenanceWireFailure> {
        if self
            .expected_catalog_generation
            .is_some_and(|generation| generation > 0)
            && self
                .idempotency_key
                .as_deref()
                .is_some_and(crate::validation::identifier)
        {
            Ok(())
        } else {
            Err(MaintenanceWireFailure)
        }
    }
}

pub(crate) fn operation_id(value: &str) -> bool {
    value.len() == 32
        && value.bytes().any(|byte| byte != b'0')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderMigrationOperation {
    pub id: String,
    pub status: String,
    pub phase: String,
    pub progress_percent: u32,
    pub retry: String,
    pub cancellation: String,
    pub irreversible_boundary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookup_expires_at_unix_seconds: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderMigrationIdentity {
    /// Stable ProviderFamily code, 1 through 8, as declared by the canonical API.
    pub family: u32,
    pub locator: String,
    pub version: String,
}
impl ProviderMigrationIdentity {
    fn is_valid(&self) -> bool {
        let text = |value: &str, maximum| {
            !value.is_empty()
                && value.len() <= maximum
                && value.bytes().all(|byte| byte.is_ascii_graphic())
                && !value.contains(['?', '#', '@'])
        };
        (1..=8).contains(&self.family) && text(&self.locator, 512) && text(&self.version, 128)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderMigrationResponse {
    pub catalog_generation: u64,
    pub root_phase: String,
    pub active_epoch: u64,
    pub active_provider: ProviderMigrationIdentity,
    pub source_provider: ProviderMigrationIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_provider: Option<ProviderMigrationIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successor_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<ProviderMigrationOperation>,
}
impl ProviderMigrationResponse {
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
        if self.catalog_generation == 0
            || self.active_epoch == 0
            || !self.active_provider.is_valid()
            || !self.source_provider.is_valid()
            || self
                .target_provider
                .as_ref()
                .is_some_and(|identity| !identity.is_valid())
            || !matches!(
                self.root_phase.as_str(),
                "active" | "prepared" | "verifying" | "retiring" | "cancelled"
            )
            || self
                .successor_epoch
                .is_some_and(|epoch| epoch <= self.active_epoch)
            || self
                .predecessor_epoch
                .is_some_and(|epoch| epoch >= self.active_epoch)
        {
            return Err(MaintenanceWireFailure);
        }
        if let Some(operation) = &self.operation {
            operation.validate()?;
        }
        Ok(())
    }
}

impl ProviderMigrationOperation {
    pub(crate) fn validate(&self) -> Result<(), MaintenanceWireFailure> {
        let operation = self;
        if !operation_id(&operation.id)
            || operation.progress_percent > 100
            || !matches!(
                operation.status.as_str(),
                "pending" | "running" | "succeeded" | "failed" | "cancelled"
            )
            || !matches!(
                operation.phase.as_str(),
                "accepted"
                    | "preflight"
                    | "draining"
                    | "catalog_publication"
                    | "published"
                    | "cancelled"
            )
            || !matches!(
                operation.retry.as_str(),
                "inspect_by_operation_id" | "retry_after_recovery_capacity" | "never"
            )
            || !matches!(
                operation.cancellation.as_str(),
                "allowed_before_drain" | "not_allowed_after_drain" | "cancelled"
            )
            || !matches!(
                operation.irreversible_boundary.as_str(),
                "not_crossed" | "catalog_generation_published"
            )
            || matches!(operation.status.as_str(), "pending" | "running")
                && operation.lookup_expires_at_unix_seconds.is_some()
        {
            return Err(MaintenanceWireFailure);
        }
        Ok(())
    }
}
