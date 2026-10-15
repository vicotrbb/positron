//! Canonical bounded native Repository administration HTTP projection.
pub use crate::api_keys::ApiKeyTransport as RepositoryTransport;
pub use crate::maintenance::MaintenanceServiceClientFailure as RepositoryServiceClientFailure;
use crate::maintenance::MaintenanceWireFailure;
pub use crate::provider_migration::ProviderMigrationOperation as RepositoryOperation;
use serde::{Deserialize, Serialize};
mod policy;
pub use policy::{
    RepositoryDefaultRetention, RepositoryEventHold, RepositoryLifecyclePolicy,
    RepositoryObjectProtection, RepositoryObjectRetention, RepositoryPolicyObservation,
    RepositoryPolicyReceipt,
};
mod client {
    include!(concat!(env!("OUT_DIR"), "/repository_service_client.rs"));
}
pub use client::RepositoryServiceClient;
pub const HTTP_PATH: &str = "/v1/repositories:manage";
pub const MAX_REQUEST_BYTES: usize = 4096;
pub const MAX_RESPONSE_BYTES: usize = 4096;
#[cfg(test)]
#[test]
fn google_native_selector_requires_exactly_one_target() {
    let value=br#"{"action":"init","expected_catalog_generation":1,"idempotency_key":"00000000-0000-0000-0000-000000000001","repository_id":"00000000-0000-0000-0000-000000000002","google_cloud_storage":{"bucket":"positron-backup","project_number":"123456789012","location":"US-CENTRAL1","prefix":"owned/"}}"#;
    let request = RepositoryRequest::decode(value).expect("native selector");
    assert!(request.google_cloud_storage.is_some());
    let mut ambiguous = request.clone();
    ambiguous.locator = Some("/local".into());
    assert!(ambiguous.encode().is_err());
    let mut status = request;
    status.action = "status".into();
    assert!(status.encode().is_err());
}
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws_s3: Option<RepositoryAwsS3Target>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub google_cloud_storage: Option<RepositoryGoogleCloudStorageTarget>,
}
/// Non-secret native selector. Credentials are resolved by the serving owner.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryAwsS3Target {
    pub bucket: String,
    pub region: String,
    pub endpoint: String,
    pub expected_owner: String,
    pub prefix: String,
}
impl std::fmt::Debug for RepositoryAwsS3Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepositoryAwsS3Target")
            .finish_non_exhaustive()
    }
}
impl RepositoryAwsS3Target {
    fn validate(&self) -> Result<(), MaintenanceWireFailure> {
        if [
            (&self.bucket, 63),
            (&self.region, 32),
            (&self.endpoint, 256),
            (&self.expected_owner, 12),
            (&self.prefix, 512),
        ]
        .iter()
        .any(|(text, bound)| {
            text.is_empty() || text.len() > *bound || text.chars().any(char::is_control)
        }) {
            return Err(MaintenanceWireFailure);
        }
        Ok(())
    }
}
/// Native bucket/project/location binding, with credentials resolved separately.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryGoogleCloudStorageTarget {
    pub bucket: String,
    pub project_number: String,
    pub location: String,
    pub prefix: String,
}
impl std::fmt::Debug for RepositoryGoogleCloudStorageTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepositoryGoogleCloudStorageTarget")
            .finish_non_exhaustive()
    }
}
impl RepositoryGoogleCloudStorageTarget {
    fn validate(&self) -> Result<(), MaintenanceWireFailure> {
        if [
            (&self.bucket, 222),
            (&self.project_number, 20),
            (&self.location, 64),
            (&self.prefix, 512),
        ]
        .iter()
        .any(|(text, bound)| {
            text.is_empty() || text.len() > *bound || text.chars().any(char::is_control)
        }) {
            return Err(MaintenanceWireFailure);
        }
        Ok(())
    }
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
        if let Some(target) = &self.aws_s3 {
            target.validate()?;
        }
        if let Some(target) = &self.google_cloud_storage {
            target.validate()?;
        }
        let mutation = self
            .expected_catalog_generation
            .is_some_and(|generation| generation > 0)
            && self.idempotency_key.is_some();
        let no_locator = self.locator.is_none()
            && self.aws_s3.is_none()
            && self.google_cloud_storage.is_none()
            && self.repository_id.is_none();
        let valid = match self.action.as_str() {
            "init" | "verify" | "doctor" => {
                mutation
                    && ([
                        self.locator.is_some(),
                        self.aws_s3.is_some(),
                        self.google_cloud_storage.is_some(),
                    ]
                    .into_iter()
                    .filter(|selected| *selected)
                    .count()
                        == 1)
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<RepositoryPolicyReceipt>,
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
                || !matches!(
                    identity.provider_kind.as_str(),
                    "local_filesystem" | "aws_s3" | "google_cloud_storage"
                )
                || identity.format_epoch != 1
                || !hash(&identity.integrity_fingerprint)
                || !hash(&identity.prefix_commitment)
            {
                return Err(MaintenanceWireFailure);
            }
        }
        if let Some(policy) = &self.policy {
            policy.validate()?;
            if self
                .operation
                .as_ref()
                .is_none_or(|operation| operation.status != "succeeded")
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
