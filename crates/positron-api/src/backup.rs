//! Bounded online Backup Snapshot administration.
use crate::maintenance::MaintenanceWireFailure;
pub use crate::repository::{
    RepositoryAwsS3Target, RepositoryAzureBlobTarget, RepositoryGoogleCloudStorageTarget,
    RepositoryIdentity, RepositoryOperation,
    RepositoryServiceClientFailure as BackupServiceClientFailure,
    RepositoryTransport as BackupTransport,
};
use serde::{Deserialize, Serialize};
mod client {
    include!(concat!(env!("OUT_DIR"), "/backup_service_client.rs"));
}
pub use client::BackupServiceClient;
mod list;
pub use list::{
    BackupListEntry, BackupListRequest, BackupListResponse, LIST_HTTP_PATH, MAX_LIST_RESPONSE_BYTES,
};
mod response;
pub use response::{BackupResponse, BackupRetentionReceipt, BackupSnapshotReceipt};
pub const HTTP_PATH: &str = "/v1/backups:manage";
pub const MAX_REQUEST_BYTES: usize = 4096;
pub const MAX_RESPONSE_BYTES: usize = 4096;
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRequest {
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_operation_revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_manifest_checksum: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_seconds: Option<u64>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure_blob: Option<RepositoryAzureBlobTarget>,
}
impl std::fmt::Debug for BackupRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupRequest")
            .field("action", &self.action)
            .finish_non_exhaustive()
    }
}
impl BackupRequest {
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
        if let Some(target) = &self.azure_blob {
            target.validate()?;
        }
        let mutation = self
            .expected_catalog_generation
            .is_some_and(|generation| generation > 0)
            && self.idempotency_key.is_some();
        let no_locator = self.retention_seconds.is_none()
            && self.locator.is_none()
            && self.aws_s3.is_none()
            && self.google_cloud_storage.is_none()
            && self.azure_blob.is_none()
            && self.repository_id.is_none();
        if self.action != "cancel" && self.expected_operation_revision.is_some() {
            return Err(MaintenanceWireFailure);
        }
        let expiry_fields = self.snapshot_id.is_some() || self.expected_manifest_checksum.is_some();
        if self.action != "expire" && expiry_fields {
            return Err(MaintenanceWireFailure);
        }
        let valid = match self.action.as_str() {
            "expire" => {
                mutation
                    && self.repository_id.is_some()
                    && self.operation_id.is_none()
                    && self.locator.is_none()
                    && self.aws_s3.is_none()
                    && self.google_cloud_storage.is_none()
                    && self.azure_blob.is_none()
                    && self.retention_seconds.is_none()
                    && self
                        .snapshot_id
                        .as_deref()
                        .is_some_and(crate::provider_migration::operation_id)
                    && self.expected_manifest_checksum.as_deref().is_some_and(hash)
            },
            "create" => {
                if !self
                    .retention_seconds
                    .is_some_and(|value| (60..=315_360_000).contains(&value))
                {
                    return Err(MaintenanceWireFailure);
                }
                mutation
                    && ([
                        self.locator.is_some(),
                        self.aws_s3.is_some(),
                        self.google_cloud_storage.is_some(),
                        self.azure_blob.is_some(),
                    ]
                    .into_iter()
                    .filter(|selected| *selected)
                    .count()
                        == 1)
                    && self.repository_id.is_some()
                    && self.operation_id.is_none()
            },
            "status" => {
                self.operation_id.is_some()
                    && no_locator
                    && self.expected_catalog_generation.is_none()
                    && self.idempotency_key.is_none()
            },
            "lookup" => {
                no_locator
                    && self.expected_catalog_generation.is_none()
                    && self.idempotency_key.is_some()
                    && self.operation_id.is_none()
            },
            "cancel" => {
                no_locator
                    && self.idempotency_key.is_some()
                    && self.operation_id.is_some()
                    && self.expected_catalog_generation.is_none()
                    && self
                        .expected_operation_revision
                        .is_some_and(|revision| revision > 0)
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

fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}
