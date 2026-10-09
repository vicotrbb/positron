//! Explicit, bounded segment-loss preview and confirmation wire contract.
use crate::maintenance::{IntegrityQuarantineDescriptor, MaintenanceWireFailure};
use serde::{Deserialize, Serialize};

pub const ABANDON_HTTP_PATH: &str = "/v1/maintenance:abandon-segment";
pub const MAX_ABANDON_REQUEST_BYTES: usize = 768;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SegmentAbandonmentRequest {
    pub tenant: String,
    pub signal: String,
    pub shard: u32,
    pub segment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_catalog_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub accept_data_loss: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
}

impl SegmentAbandonmentRequest {
    pub fn decode(bytes: &[u8]) -> Result<Self, MaintenanceWireFailure> {
        if bytes.len() > MAX_ABANDON_REQUEST_BYTES {
            return Err(MaintenanceWireFailure);
        }
        let request: Self = serde_json::from_slice(bytes).map_err(|_| MaintenanceWireFailure)?;
        request.validate()?;
        Ok(request)
    }
    pub fn encode(&self) -> Result<Vec<u8>, MaintenanceWireFailure> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| MaintenanceWireFailure)?;
        if bytes.len() > MAX_ABANDON_REQUEST_BYTES {
            return Err(MaintenanceWireFailure);
        }
        Ok(bytes)
    }
    pub fn validate(&self) -> Result<(), MaintenanceWireFailure> {
        if !crate::validation::identifier(&self.tenant) {
            return Err(MaintenanceWireFailure);
        }
        if self.shard == 0
            || !matches!(self.signal.as_str(), "logs" | "traces")
            || !valid_hex(&self.segment, 32)
        {
            return Err(MaintenanceWireFailure);
        }
        let any_confirmation = self.confirmation.is_some()
            || self.idempotency_key.is_some()
            || self.expected_catalog_generation.is_some()
            || self.accept_data_loss;
        if let Some(operation) = &self.operation_id {
            if !valid_hex(operation, 32) || any_confirmation {
                return Err(MaintenanceWireFailure);
            }
        } else if any_confirmation
            && (!self.accept_data_loss
                || self
                    .expected_catalog_generation
                    .is_none_or(|generation| generation == 0)
                || self
                    .confirmation
                    .as_deref()
                    .is_none_or(|value| !valid_hex(value, 64))
                || self
                    .idempotency_key
                    .as_deref()
                    .is_none_or(|value| !crate::validation::identifier(value)))
        {
            return Err(MaintenanceWireFailure);
        }
        Ok(())
    }
}

fn valid_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SegmentAbandonmentResponse {
    pub catalog_generation: u64,
    pub status: String,
    pub irreversible_boundary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    pub finding: IntegrityQuarantineDescriptor,
}
impl SegmentAbandonmentResponse {
    pub fn encode(&self) -> Result<Vec<u8>, MaintenanceWireFailure> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| MaintenanceWireFailure)?;
        if bytes.len() > crate::maintenance::MAX_RESPONSE_BYTES {
            return Err(MaintenanceWireFailure);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, MaintenanceWireFailure> {
        if bytes.len() > crate::maintenance::MAX_RESPONSE_BYTES {
            return Err(MaintenanceWireFailure);
        }
        let response: Self = serde_json::from_slice(bytes).map_err(|_| MaintenanceWireFailure)?;
        response.validate()?;
        Ok(response)
    }
    fn validate(&self) -> Result<(), MaintenanceWireFailure> {
        let coherent = match self.status.as_str() {
            "preview" => {
                self.irreversible_boundary == "not_crossed"
                    && self.operation_id.is_none()
                    && self
                        .confirmation
                        .as_deref()
                        .is_some_and(|value| valid_hex(value, 64))
            },
            "succeeded" => {
                self.irreversible_boundary == "catalog_generation_published"
                    && self.confirmation.is_none()
                    && self
                        .operation_id
                        .as_deref()
                        .is_some_and(|value| valid_hex(value, 32))
            },
            _ => false,
        };
        if self.catalog_generation == 0
            || !coherent
            || !super::valid_integrity_finding(&self.finding)
        {
            return Err(MaintenanceWireFailure);
        }
        Ok(())
    }
}
