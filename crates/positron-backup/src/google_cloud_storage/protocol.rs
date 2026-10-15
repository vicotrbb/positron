use crate::RepositoryFailure;
use crate::*;
use base64::Engine;
use serde_json::Value;
pub(super) fn json(bytes: &[u8]) -> Result<Value, RepositoryFailure> {
    if bytes.len() > 131072 {
        return Err(RepositoryFailure::LimitExceeded);
    }
    serde_json::from_slice(bytes).map_err(|_| RepositoryFailure::CorruptState)
}
pub(super) fn string<'a>(value: &'a Value, field: &str) -> Result<&'a str, RepositoryFailure> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 4096 && !s.chars().any(char::is_control))
        .ok_or(RepositoryFailure::CorruptState)
}
pub(super) fn number(value: &Value, field: &str) -> Result<u64, RepositoryFailure> {
    let text = string(value, field)?;
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(RepositoryFailure::CorruptState);
    }
    text.parse().map_err(|_| RepositoryFailure::CorruptState)
}
pub(super) fn bucket(
    bytes: &[u8],
    target: &GoogleCloudStorageTarget,
) -> Result<Value, RepositoryFailure> {
    let value = json(bytes)?;
    if string(&value, "name")? != target.bucket()
        || string(&value, "projectNumber")? != target.project_number()
        || string(&value, "location")? != target.location()
    {
        return Err(RepositoryFailure::IdentityMismatch);
    }
    Ok(value)
}
pub(super) struct Metadata {
    pub generation: u64,
    pub metageneration: u64,
    pub size: u64,
    pub crc32c: u32,
    pub protection: ObjectProtection,
}
impl Metadata {
    pub fn verify(&self, bytes: &[u8]) -> Result<(), RepositoryFailure> {
        if bytes.len() as u64 != self.size || crc32c::crc32c(bytes) != self.crc32c {
            return Err(RepositoryFailure::ChecksumMismatch);
        }
        Ok(())
    }
}
pub(super) fn metadata(bytes: &[u8], expected: &str) -> Result<Metadata, RepositoryFailure> {
    metadata_value(&json(bytes)?, expected)
}
pub(super) fn metadata_value(value: &Value, expected: &str) -> Result<Metadata, RepositoryFailure> {
    if string(value, "name")? != expected {
        return Err(RepositoryFailure::IdentityMismatch);
    }
    let generation = number(value, "generation")?;
    let metageneration = number(value, "metageneration")?;
    let size = number(value, "size")?;
    if generation == 0 || metageneration == 0 || size > crate::MAX_OBJECT_BYTES + 65536 {
        return Err(RepositoryFailure::LimitExceeded);
    }
    let crc = base64::engine::general_purpose::STANDARD
        .decode(string(value, "crc32c")?)
        .map_err(|_| RepositoryFailure::CorruptState)?;
    let crc: [u8; 4] = crc
        .try_into()
        .map_err(|_| RepositoryFailure::CorruptState)?;
    let mut metadata = Metadata {
        generation,
        metageneration,
        size,
        crc32c: u32::from_be_bytes(crc),
        protection: ObjectProtection {
            retention: match value.get("retention") {
                Some(retention) => match (
                    retention.get("mode").and_then(Value::as_str),
                    retention
                        .get("retainUntilTime")
                        .and_then(Value::as_str)
                        .and_then(timestamp),
                ) {
                    (Some(mode), Some(until)) if matches!(mode, "Locked" | "Unlocked") => {
                        PolicyObservation::Observed(ObjectRetention {
                            mode: if mode == "Locked" {
                                RetentionMode::Compliance
                            } else {
                                RetentionMode::Governance
                            },
                            retain_until_unix_seconds: until,
                        })
                    },
                    _ => PolicyObservation::Unavailable(RepositoryFailure::CorruptState),
                },
                None => PolicyObservation::Unobservable,
            },
            legal_hold: match value.get("temporaryHold") {
                Some(Value::Bool(b)) => PolicyObservation::Observed(*b),
                None => PolicyObservation::Unobservable,
                _ => PolicyObservation::Unavailable(RepositoryFailure::CorruptState),
            },
            event_hold: match value.get("eventBasedHold") {
                Some(Value::Bool(false)) => PolicyObservation::Observed(None),
                Some(Value::Bool(true)) => {
                    PolicyObservation::Observed(Some(RetentionPeriod::UntilRelease))
                },
                None => PolicyObservation::Unobservable,
                _ => PolicyObservation::Unavailable(RepositoryFailure::CorruptState),
            },
        },
    };
    if let Some(value) = value.get("retentionExpirationTime") {
        match value.as_str().and_then(timestamp) {
            Some(until) => match metadata.protection.retention {
                PolicyObservation::Observed(existing)
                    if existing.retain_until_unix_seconds >= until => {},
                _ => {
                    metadata.protection.retention = PolicyObservation::Observed(ObjectRetention {
                        mode: RetentionMode::ProviderEnforced,
                        retain_until_unix_seconds: until,
                    })
                },
            },
            None => {
                metadata.protection.retention =
                    PolicyObservation::Unavailable(RepositoryFailure::CorruptState)
            },
        }
    }
    Ok(metadata)
}
fn timestamp(text: &str) -> Option<u64> {
    time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
        .ok()
        .and_then(|v| {
            let seconds = u64::try_from(v.unix_timestamp()).ok()?;
            seconds.checked_add(u64::from(v.nanosecond() != 0))
        })
        .filter(|n| *n > 0)
}
pub(super) fn policy(value: &Value) -> RepositoryPolicy {
    let unavailable = PolicyObservation::Unavailable(RepositoryFailure::CorruptState);
    let versioning = match value.pointer("/versioning/enabled") {
        Some(Value::Bool(true)) => PolicyObservation::Observed(VersioningPolicy::Enabled),
        Some(Value::Bool(false)) => PolicyObservation::Observed(VersioningPolicy::Disabled),
        None => PolicyObservation::Unobservable,
        _ => unavailable,
    };
    let object_lock = match value.get("retentionPolicy") {
        Some(retention) => match (
            number(retention, "retentionPeriod")
                .ok()
                .and_then(|n| u32::try_from(n).ok())
                .filter(|n| *n > 0),
            retention.get("isLocked").and_then(Value::as_bool),
        ) {
            (Some(seconds), Some(locked)) => {
                PolicyObservation::Observed(ObjectLockPolicy::Enabled {
                    default_retention: Some(RetentionPolicy {
                        mode: if locked {
                            RetentionMode::Compliance
                        } else {
                            RetentionMode::Governance
                        },
                        period: RetentionPeriod::Seconds(seconds),
                    }),
                })
            },
            _ => PolicyObservation::Unavailable(RepositoryFailure::CorruptState),
        },
        None => match value.pointer("/objectRetention/mode") {
            Some(Value::String(mode)) if mode == "Enabled" => {
                PolicyObservation::Observed(ObjectLockPolicy::Enabled {
                    default_retention: None,
                })
            },
            Some(Value::String(mode)) if mode == "Disabled" => {
                PolicyObservation::Observed(ObjectLockPolicy::Disabled)
            },
            None => PolicyObservation::Unobservable,
            _ => PolicyObservation::Unavailable(RepositoryFailure::CorruptState),
        },
    };
    let soft_delete = Some(match value.get("softDeletePolicy") {
        Some(v) => match number(v, "retentionDurationSeconds") {
            Ok(seconds) => PolicyObservation::Observed(seconds),
            Err(e) => PolicyObservation::Unavailable(e),
        },
        None => PolicyObservation::Unobservable,
    });
    let lifecycle = match value.pointer("/lifecycle/rule") {
        Some(Value::Array(rules)) if rules.len() <= 100 => {
            let mut result = LifecyclePolicy {
                current_expiration: false,
                noncurrent_expiration: false,
                transition: false,
                abandoned_upload_expiration: false,
            };
            let mut valid = true;
            for rule in rules {
                match rule.pointer("/action/type").and_then(Value::as_str) {
                    Some("Delete") => {
                        let live = rule.pointer("/condition/isLive").and_then(Value::as_bool);
                        result.current_expiration |= live != Some(false);
                        result.noncurrent_expiration |= live != Some(true);
                    },
                    Some("SetStorageClass") => result.transition = true,
                    Some("AbortIncompleteMultipartUpload") => {
                        result.abandoned_upload_expiration = true
                    },
                    _ => valid = false,
                }
            }
            if valid {
                PolicyObservation::Observed(result)
            } else {
                PolicyObservation::Unavailable(RepositoryFailure::CorruptState)
            }
        },
        None => PolicyObservation::Unobservable,
        _ => PolicyObservation::Unavailable(RepositoryFailure::CorruptState),
    };
    RepositoryPolicy {
        versioning,
        object_lock,
        lifecycle,
        soft_delete,
        doctor_probe: None,
    }
}
pub(super) fn escape(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}
pub(super) fn range(
    header: Option<&str>,
    offset: u64,
    length: u64,
    size: u64,
    actual: usize,
) -> Result<(), RepositoryFailure> {
    let end = offset
        .checked_add(length)
        .and_then(|v| v.checked_sub(1))
        .ok_or(RepositoryFailure::InvalidInput)?;
    if length == 0
        || end >= size
        || actual as u64 != length
        || header != Some(format!("bytes {offset}-{end}/{size}").as_str())
    {
        return Err(RepositoryFailure::CorruptState);
    }
    Ok(())
}
pub(super) fn uploaded(range: Option<&str>, size: u64) -> Result<u64, RepositoryFailure> {
    let Some(range) = range else { return Ok(0) };
    let last = range
        .strip_prefix("bytes=0-")
        .and_then(|s| s.parse::<u64>().ok())
        .and_then(|n| n.checked_add(1))
        .ok_or(RepositoryFailure::CorruptState)?;
    if last >= size {
        return Err(RepositoryFailure::CorruptState);
    }
    Ok(last)
}
pub(super) fn session(url: &str, bucket: &str) -> Result<(), RepositoryFailure> {
    let prefix = format!("https://storage.googleapis.com/upload/storage/v1/b/{bucket}/o?");
    let query = url
        .strip_prefix(&prefix)
        .ok_or(RepositoryFailure::CorruptState)?;
    if url.len() > 3072
        || url.chars().any(char::is_control)
        || url.contains('#')
        || !query.split('&').any(|p| {
            p.strip_prefix("upload_id=")
                .is_some_and(|id| !id.is_empty())
        })
    {
        return Err(RepositoryFailure::CorruptState);
    }
    Ok(())
}
pub(super) fn status(code: u16, mutation: bool, retry: Option<&str>) -> RepositoryFailure {
    match code {
        400 => RepositoryFailure::InvalidInput,
        401 | 403 => RepositoryFailure::PermissionDenied,
        404 => RepositoryFailure::NotFound,
        409 => RepositoryFailure::Busy,
        412 => RepositoryFailure::PreconditionFailed,
        429 => RepositoryFailure::Throttled {
            retry_after_millis: retry
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(1)
                .saturating_mul(1000)
                .clamp(100, 60000) as u32,
        },
        500..=599 if mutation => RepositoryFailure::OutcomeUnknown,
        _ => RepositoryFailure::StorageUnavailable,
    }
}
