//! Declarative Upgrade selects the server's independently authenticated staged release.
pub use crate::api_keys::ApiKeyTransport as UpgradeTransport;
pub use crate::maintenance::MaintenanceServiceClientFailure as UpgradeServiceClientFailure;
use crate::maintenance::MaintenanceWireFailure;
use crate::provider_migration::operation_id;
use serde::{Deserialize, Serialize};
mod client {
    include!(concat!(env!("OUT_DIR"), "/upgrade_service_client.rs"));
}
pub use client::UpgradeServiceClient;
pub const HTTP_PATH: &str = "/v1/upgrades:manage";
pub const MAX_REQUEST_BYTES: usize = 4096;
pub const MAX_RESPONSE_BYTES: usize = 4096;
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeRequest {
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_manifest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_catalog_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
}
impl UpgradeRequest {
    pub fn decode(bytes: &[u8]) -> Result<Self, MaintenanceWireFailure> {
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(MaintenanceWireFailure);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| MaintenanceWireFailure)?;
        value.validate()?;
        Ok(value)
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
        let no_candidate = self.candidate_manifest.is_none()
            && self.repository_id.is_none()
            && self.retention_seconds.is_none();
        let valid = match self.action.as_str() {
            "start" => {
                mutation
                    && self.operation_id.is_none()
                    && self.candidate_manifest.as_deref().is_some_and(|s| {
                        s.len() == 64
                            && s.bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
                    && self
                        .repository_id
                        .as_deref()
                        .is_some_and(crate::validation::identifier)
                    && self.retention_seconds.is_some_and(|n| n > 0)
            },
            "status" => {
                no_candidate
                    && self.operation_id.as_deref().is_some_and(operation_id)
                    && self.expected_catalog_generation.is_none()
                    && self.idempotency_key.is_none()
            },
            "lookup" => {
                no_candidate
                    && self.operation_id.is_none()
                    && self.expected_catalog_generation.is_none()
                    && self
                        .idempotency_key
                        .as_deref()
                        .is_some_and(crate::validation::identifier)
            },
            "cancel" => {
                no_candidate && mutation && self.operation_id.as_deref().is_some_and(operation_id)
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u32)]
pub enum UpgradePhase {
    Preflight = 1,
    Draining = 2,
    Snapshot = 3,
    Publishing = 4,
    AwaitingRestart = 5,
    Verifying = 6,
    Succeeded = 7,
}
impl std::fmt::Display for UpgradePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Preflight => "preflight",
            Self::Draining => "draining",
            Self::Snapshot => "snapshot",
            Self::Publishing => "publishing",
            Self::AwaitingRestart => "awaiting_restart",
            Self::Verifying => "verifying",
            Self::Succeeded => "succeeded",
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeOperation {
    pub id: String,
    pub status: String,
    pub phase: UpgradePhase,
    pub progress_percent: u32,
    pub retry: String,
    pub cancellation: String,
    pub irreversible_boundary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookup_expires_at_unix_seconds: Option<u64>,
}
impl UpgradeOperation {
    fn validate(&self) -> Result<(), MaintenanceWireFailure> {
        if !operation_id(&self.id)
            || self.progress_percent > 100
            || !matches!(
                self.status.as_str(),
                "pending" | "running" | "succeeded" | "failed" | "cancelled"
            )
            || !matches!(
                self.retry.as_str(),
                "inspect_by_operation_id" | "retry_after_recovery_capacity" | "never"
            )
            || !matches!(
                self.cancellation.as_str(),
                "allowed_before_publication" | "unavailable_after_publication" | "cancelled"
            )
            || !matches!(
                self.irreversible_boundary.as_str(),
                "not_crossed" | "catalog_generation_published"
            )
            || matches!(self.status.as_str(), "pending" | "running")
                && self.lookup_expires_at_unix_seconds.is_some()
            || (self.status == "succeeded") != (self.phase == UpgradePhase::Succeeded)
        {
            return Err(MaintenanceWireFailure);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeDetails {
    pub source_version: String,
    pub target_version: String,
    pub source_manifest: String,
    pub target_manifest: String,
    pub source_artifact: String,
    pub target_artifact: String,
    pub configuration: String,
    pub format_epoch: u32,
    pub repository_id: String,
    pub rollback_available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_manifest: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeResponse {
    pub catalog_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<UpgradeDetails>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<UpgradeOperation>,
}
impl UpgradeResponse {
    pub fn encode(&self) -> Result<Vec<u8>, MaintenanceWireFailure> {
        self.validate()?;
        let b = serde_json::to_vec(self).map_err(|_| MaintenanceWireFailure)?;
        if b.len() > MAX_RESPONSE_BYTES {
            return Err(MaintenanceWireFailure);
        }
        Ok(b)
    }
    pub fn decode(b: &[u8]) -> Result<Self, MaintenanceWireFailure> {
        if b.len() > MAX_RESPONSE_BYTES {
            return Err(MaintenanceWireFailure);
        }
        let v: Self = serde_json::from_slice(b).map_err(|_| MaintenanceWireFailure)?;
        v.validate()?;
        Ok(v)
    }
    fn validate(&self) -> Result<(), MaintenanceWireFailure> {
        if self.catalog_generation == 0 {
            return Err(MaintenanceWireFailure);
        }
        if let Some(op) = &self.operation {
            op.validate()?;
        }
        if self.details.is_some() != self.operation.is_some() {
            return Err(MaintenanceWireFailure);
        }
        if let Some(d) = &self.details {
            let digest = |s: &str| {
                s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            };
            let version = |s: &str| {
                s.len() <= 32
                    && s.split('.').count() == 3
                    && s.split('.').all(|p| {
                        !p.is_empty()
                            && p.bytes().all(|byte| byte.is_ascii_digit())
                            && p.parse::<u32>().is_ok()
                            && (!p.starts_with('0') || p == "0")
                    })
            };
            if !version(&d.source_version)
                || !version(&d.target_version)
                || ![
                    &d.source_manifest,
                    &d.target_manifest,
                    &d.source_artifact,
                    &d.target_artifact,
                    &d.configuration,
                ]
                .iter()
                .all(|v| digest(v))
                || !matches!(d.format_epoch, 1 | 2)
                || !crate::validation::identifier(&d.repository_id)
                || d.snapshot_manifest.as_deref().is_some_and(|v| !digest(v))
            {
                return Err(MaintenanceWireFailure);
            }
        }
        Ok(())
    }
}
