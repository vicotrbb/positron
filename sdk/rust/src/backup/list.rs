use super::{MaintenanceWireFailure, RepositoryIdentity, hash};
use serde::{Deserialize, Serialize};
pub const LIST_HTTP_PATH: &str = "/v1/backups:list";
pub const MAX_LIST_RESPONSE_BYTES: usize = 65536;
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupListRequest {
    pub repository_id: String,
    pub limit: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}
impl BackupListRequest {
    pub fn encode(&self) -> Result<Vec<u8>, MaintenanceWireFailure> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| MaintenanceWireFailure)?;
        if bytes.len() > super::MAX_REQUEST_BYTES {
            return Err(MaintenanceWireFailure);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, MaintenanceWireFailure> {
        if bytes.len() > super::MAX_REQUEST_BYTES {
            return Err(MaintenanceWireFailure);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| MaintenanceWireFailure)?;
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), MaintenanceWireFailure> {
        if !crate::validation::identifier(&self.repository_id)
            || !(1..=128).contains(&self.limit)
            || self.cursor.as_deref().is_some_and(|value| !cursor(value))
        {
            return Err(MaintenanceWireFailure);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupListEntry {
    pub snapshot_id: String,
    pub manifest_checksum: String,
    pub created_unix_seconds: u64,
    pub retain_until_unix_seconds: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupListResponse {
    pub repository: RepositoryIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_generation_checksum: Option<String>,
    pub entries: Vec<BackupListEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}
impl BackupListResponse {
    pub fn encode(&self) -> Result<Vec<u8>, MaintenanceWireFailure> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| MaintenanceWireFailure)?;
        if bytes.len() > MAX_LIST_RESPONSE_BYTES {
            return Err(MaintenanceWireFailure);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, MaintenanceWireFailure> {
        if bytes.len() > MAX_LIST_RESPONSE_BYTES {
            return Err(MaintenanceWireFailure);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| MaintenanceWireFailure)?;
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), MaintenanceWireFailure> {
        crate::repository::RepositoryResponse {
            catalog_generation: 1,
            operation: None,
            identity: Some(self.repository.clone()),
            doctor: None,
            policy: None,
        }
        .validate()?;
        if self.entries.len() > 128
            || self
                .registry_generation_checksum
                .as_deref()
                .is_some_and(|value| !hash(value))
            || (self.registry_generation_checksum.is_none()
                && (!self.entries.is_empty() || self.next_cursor.is_some()))
        {
            return Err(MaintenanceWireFailure);
        }
        let mut previous = None;
        for entry in &self.entries {
            if !crate::provider_migration::operation_id(&entry.snapshot_id)
                || !hash(&entry.manifest_checksum)
                || entry.created_unix_seconds == 0
                || entry.retain_until_unix_seconds < entry.created_unix_seconds
                || previous.is_some_and(|previous: &str| previous >= entry.snapshot_id.as_str())
            {
                return Err(MaintenanceWireFailure);
            }
            previous = Some(entry.snapshot_id.as_str());
        }
        if let Some(next) = &self.next_cursor
            && (!cursor(next)
                || self
                    .entries
                    .last()
                    .is_none_or(|entry| next.get(144..176) != Some(entry.snapshot_id.as_str()))
                || next.get(80..144) != self.registry_generation_checksum.as_deref())
        {
            return Err(MaintenanceWireFailure);
        }
        Ok(())
    }
}
fn cursor(value: &str) -> bool {
    value.len() == 176
        && value.starts_with("504f53424c533031")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && [(16, 80), (80, 144), (144, 176)]
            .into_iter()
            .all(|(start, end)| {
                value
                    .get(start..end)
                    .is_some_and(|part| part.bytes().any(|byte| byte != b'0'))
            })
}
