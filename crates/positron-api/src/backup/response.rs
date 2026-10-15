use super::{
    MAX_RESPONSE_BYTES, MaintenanceWireFailure, RepositoryIdentity, RepositoryOperation, hash,
};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSnapshotReceipt {
    pub registry_generation_checksum: String,
    pub manifest_checksum: String,
    pub catalog_generation: u64,
    pub catalog_identity: String,
    pub uploaded_bytes: u64,
    pub reused_bytes: u64,
    pub retain_until_unix_seconds: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupResponse {
    pub operation_revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_error_code: Option<String>,
    pub kind: String,
    pub cleanup_pending: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_receipt: Option<BackupRetentionReceipt>,
    pub operation: RepositoryOperation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<RepositoryIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<BackupSnapshotReceipt>,
}
impl BackupResponse {
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
        let op = &self.operation;
        let snapshot = self.kind == "snapshot";
        let retention = self.kind == "retention";
        let phase = op.phase.as_str();
        let boundary = op.irreversible_boundary.as_str();
        if (op.status == "failed") != self.terminal_error_code.is_some()
            || self.terminal_error_code.as_deref().is_some_and(|code| {
                !matches!(
                    code,
                    "handler_rejected" | "legacy_unknown" | "backup_retention_not_due"
                )
            })
            || self.operation_revision == 0
            || (!snapshot && !retention)
            || !crate::provider_migration::operation_id(&op.id)
            || op.progress_percent > 100
            || !matches!(
                op.status.as_str(),
                "pending" | "running" | "succeeded" | "failed" | "cancelled"
            )
            || !(matches!(
                phase,
                "accepted" | "preflight" | "backup_cancellation" | "published" | "cancelled"
            ) || snapshot
                && matches!(
                    phase,
                    "backup_capture"
                        | "backup_transfer"
                        | "backup_verification"
                        | "backup_publication"
                )
                || retention
                    && matches!(
                        phase,
                        "backup_retention_scan"
                            | "backup_retention_publication"
                            | "backup_retention_cleanup"
                    ))
            || !matches!(
                op.retry.as_str(),
                "inspect_by_operation_id" | "retry_after_recovery_capacity" | "never"
            )
            || !matches!(
                op.cancellation.as_str(),
                "allowed_before_publication"
                    | "not_allowed_during_publication"
                    | "cancel_requested_cleanup_pending"
                    | "cancelled"
            )
            || !(boundary == "not_crossed"
                || snapshot && boundary == "backup_registry_published"
                || retention && boundary == "backup_registry_expired")
            || matches!(op.status.as_str(), "pending" | "running")
                && op.lookup_expires_at_unix_seconds.is_some()
            || phase == "backup_cancellation"
                && (op.status != "running"
                    || !self.cleanup_pending
                    || op.cancellation != "cancel_requested_cleanup_pending"
                    || boundary != "not_crossed")
            || op.cancellation == "cancel_requested_cleanup_pending"
                && phase != "backup_cancellation"
            || op.status == "cancelled"
                && (self.cleanup_pending
                    || phase != "cancelled"
                    || op.cancellation != "cancelled"
                    || boundary != "not_crossed")
            || phase == "backup_retention_cleanup"
                && (!self.cleanup_pending
                    || boundary != "backup_registry_expired"
                    || op.cancellation != "not_allowed_during_publication")
            || matches!(phase, "backup_publication" | "backup_retention_publication")
                && op.cancellation != "not_allowed_during_publication"
            || retention && op.status == "succeeded" && self.cleanup_pending
        {
            return Err(MaintenanceWireFailure);
        }
        if let Some(identity) = &self.repository {
            crate::repository::RepositoryResponse {
                catalog_generation: 1,
                operation: None,
                identity: Some(identity.clone()),
                doctor: None,
                policy: None,
            }
            .validate()?;
        }
        if let Some(receipt) = &self.receipt
            && (!snapshot
                || self.retention_receipt.is_some()
                || op.status != "succeeded"
                || phase != "published"
                || boundary != "backup_registry_published"
                || self.repository.is_none()
                || receipt.catalog_generation == 0
                || receipt.retain_until_unix_seconds == 0
                || !hash(&receipt.manifest_checksum)
                || !hash(&receipt.catalog_identity)
                || !hash(&receipt.registry_generation_checksum))
        {
            return Err(MaintenanceWireFailure);
        }
        if let Some(receipt) = &self.retention_receipt
            && (!retention
                || self.receipt.is_some()
                || op.status != "succeeded"
                || phase != "published"
                || boundary != "backup_registry_expired"
                || self.repository.is_none()
                || !crate::provider_migration::operation_id(&receipt.snapshot_id)
                || !hash(&receipt.manifest_checksum)
                || !hash(&receipt.registry_generation_checksum))
        {
            return Err(MaintenanceWireFailure);
        }
        if op.status == "succeeded"
            && (snapshot && self.receipt.is_none() || retention && self.retention_receipt.is_none())
        {
            return Err(MaintenanceWireFailure);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRetentionReceipt {
    pub snapshot_id: String,
    pub manifest_checksum: String,
    pub registry_generation_checksum: String,
    pub deleted_objects: u32,
    pub already_absent_objects: u32,
    pub retained_shared_objects: u32,
}
