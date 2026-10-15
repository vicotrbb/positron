//! Canonical policy receipt projection; unknown controls never imply absence.
use crate::maintenance::MaintenanceWireFailure;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryPolicyReceipt {
    pub observed_at_unix_seconds: u64,
    pub versioning: RepositoryPolicyObservation,
    pub object_lock: RepositoryPolicyObservation,
    pub lifecycle: RepositoryPolicyObservation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doctor_probe: Option<RepositoryObjectProtection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soft_delete: Option<RepositoryPolicyObservation>,
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryPolicyObservation {
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_millis: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_retention: Option<RepositoryDefaultRetention>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<RepositoryLifecyclePolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_retention: Option<RepositoryObjectRetention>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_hold: Option<RepositoryEventHold>,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryDefaultRetention {
    pub mode: String,
    pub period_unit: String,
    pub period: u32,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryLifecyclePolicy {
    pub current_expiration: bool,
    pub noncurrent_expiration: bool,
    pub transition: bool,
    pub abandoned_upload_expiration: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryObjectProtection {
    pub retention: RepositoryPolicyObservation,
    pub legal_hold: RepositoryPolicyObservation,
    pub event_hold: RepositoryPolicyObservation,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryObjectRetention {
    pub mode: String,
    pub retain_until_unix_seconds: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryEventHold {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period_unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<u32>,
}
#[derive(Clone, Copy)]
enum Field {
    Versioning,
    ObjectLock,
    Lifecycle,
    Retention,
    LegalHold,
    EventHold,
    SoftDelete,
}
impl RepositoryPolicyReceipt {
    pub(super) fn validate(&self) -> Result<(), MaintenanceWireFailure> {
        if self.observed_at_unix_seconds == 0 {
            return Err(MaintenanceWireFailure);
        }
        self.versioning.validate(Field::Versioning)?;
        self.object_lock.validate(Field::ObjectLock)?;
        self.lifecycle.validate(Field::Lifecycle)?;
        if let Some(value) = &self.soft_delete {
            value.validate(Field::SoftDelete)?;
        }
        if let Some(probe) = &self.doctor_probe {
            probe.retention.validate(Field::Retention)?;
            probe.legal_hold.validate(Field::LegalHold)?;
            probe.event_hold.validate(Field::EventHold)?;
        }
        Ok(())
    }
}
impl RepositoryPolicyObservation {
    fn validate(&self, field: Field) -> Result<(), MaintenanceWireFailure> {
        let no_value = self.value.is_none()
            && self.default_retention.is_none()
            && self.lifecycle.is_none()
            && self.object_retention.is_none()
            && self.event_hold.is_none();
        let common = self.default_retention.is_none() && self.lifecycle.is_none();
        if !matches!(field, Field::Retention) && self.object_retention.is_some()
            || !matches!(field, Field::EventHold) && self.event_hold.is_some()
        {
            return Err(MaintenanceWireFailure);
        }
        let valid = match self.state.as_str() {
            "unobservable" => {
                no_value && self.failure.is_none() && self.retry_after_millis.is_none()
            },
            "unavailable" => {
                no_value
                    && self.failure.as_deref().is_some_and(|failure| {
                        matches!(
                            failure,
                            "invalid_input"
                                | "identity_mismatch"
                                | "foreign_prefix"
                                | "permission_denied"
                                | "not_found"
                                | "already_exists"
                                | "precondition_failed"
                                | "busy"
                                | "checksum_mismatch"
                                | "corrupt_state"
                                | "storage_unavailable"
                                | "outcome_unknown"
                                | "limit_exceeded"
                                | "interrupted"
                                | "throttled"
                        )
                    })
                    && if self.failure.as_deref() == Some("throttled") {
                        self.retry_after_millis
                            .is_some_and(|duration| (100..=60_000).contains(&duration))
                    } else {
                        self.retry_after_millis.is_none()
                    }
            },
            "observed" if self.failure.is_none() && self.retry_after_millis.is_none() => {
                match field {
                    Field::SoftDelete => {
                        common
                            && self.object_retention.is_none()
                            && self.event_hold.is_none()
                            && self.value.as_deref().is_some_and(|v| {
                                !v.is_empty()
                                    && v.bytes().all(|b| b.is_ascii_digit())
                                    && v.parse::<u64>().is_ok()
                            })
                    },
                    Field::Versioning => {
                        matches!(
                            self.value.as_deref(),
                            Some("disabled" | "enabled" | "suspended")
                        ) && self.default_retention.is_none()
                            && self.lifecycle.is_none()
                    },
                    Field::ObjectLock => {
                        self.lifecycle.is_none()
                            && match self.value.as_deref() {
                                Some("disabled") => self.default_retention.is_none(),
                                Some("enabled") => {
                                    self.default_retention.as_ref().is_none_or(|retention| {
                                        matches!(
                                            retention.mode.as_str(),
                                            "governance" | "compliance" | "provider_enforced"
                                        ) && matches!(
                                            retention.period_unit.as_str(),
                                            "days" | "years" | "seconds"
                                        ) && retention.period > 0
                                    })
                                },
                                _ => false,
                            }
                    },
                    Field::Lifecycle => {
                        self.value.is_none()
                            && self.default_retention.is_none()
                            && self.lifecycle.is_some()
                    },
                    Field::Retention => {
                        common
                            && self.value.is_none()
                            && self.object_retention.as_ref().is_some_and(|value| {
                                matches!(
                                    value.mode.as_str(),
                                    "governance" | "compliance" | "provider_enforced"
                                ) && value.retain_until_unix_seconds > 0
                            })
                    },
                    Field::LegalHold => {
                        common && matches!(self.value.as_deref(), Some("on" | "off"))
                    },
                    Field::EventHold => {
                        common
                            && self.value.is_none()
                            && self.event_hold.as_ref().is_some_and(|value| {
                                if value.enabled {
                                    (matches!(
                                        value.period_unit.as_deref(),
                                        Some("days" | "years" | "seconds")
                                    ) && value.period.is_some_and(|period| period > 0))
                                        || (value.period_unit.as_deref() == Some("until_release")
                                            && value.period.is_none())
                                } else {
                                    value.period.is_none() && value.period_unit.is_none()
                                }
                            })
                    },
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn probe_protection_roundtrip_rejects_false_absence_and_invalid_retention()
    -> Result<(), Box<dyn std::error::Error>> {
        let valid = br#"{"observed_at_unix_seconds":1,"versioning":{"state":"unobservable"},"object_lock":{"state":"unobservable"},"lifecycle":{"state":"unobservable"},"doctor_probe":{"retention":{"state":"observed","object_retention":{"mode":"compliance","retain_until_unix_seconds":1900000000}},"legal_hold":{"state":"unavailable","failure":"permission_denied"},"event_hold":{"state":"observed","event_hold":{"enabled":true,"period_unit":"days","period":7}}}}"#;
        let value: RepositoryPolicyReceipt = serde_json::from_slice(valid)?;
        assert!(value.validate().is_ok());
        let mut invalid = value.clone();
        invalid
            .doctor_probe
            .as_mut()
            .ok_or("probe")?
            .retention
            .object_retention
            .as_mut()
            .ok_or("retention")?
            .retain_until_unix_seconds = 0;
        assert!(invalid.validate().is_err());
        let encoded = serde_json::to_vec(&value)?;
        assert_eq!(
            serde_json::from_slice::<RepositoryPolicyReceipt>(&encoded)?,
            value
        );
        Ok(())
    }
}
