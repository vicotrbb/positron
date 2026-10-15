//! Projects authenticated terminal observations, never native error strings.
use positron_api::repository as wire;
use positron_domain::repository as domain;
pub(super) fn receipt(
    policy: domain::RepositoryPolicy,
    observed_at_unix_seconds: u64,
) -> wire::RepositoryPolicyReceipt {
    wire::RepositoryPolicyReceipt {
        observed_at_unix_seconds,
        soft_delete: policy.soft_delete.map(|value| {
            observation(value, |output, seconds| {
                output.value = Some(seconds.to_string())
            })
        }),
        doctor_probe: policy
            .doctor_probe
            .map(|probe| wire::RepositoryObjectProtection {
                retention: observation(probe.retention, |output, value| {
                    output.object_retention = Some(wire::RepositoryObjectRetention {
                        mode: match value.mode {
                            domain::RetentionMode::Governance => "governance",
                            domain::RetentionMode::Compliance => "compliance",
                            domain::RetentionMode::ProviderEnforced => "provider_enforced",
                        }
                        .into(),
                        retain_until_unix_seconds: value.retain_until_unix_seconds,
                    });
                }),
                legal_hold: observation(probe.legal_hold, |output, value| {
                    output.value = Some(if value { "on" } else { "off" }.into())
                }),
                event_hold: observation(probe.event_hold, |output, value| {
                    let (period_unit, period) = match value {
                        None => (None, None),
                        Some(domain::RetentionPeriod::Days(period)) => {
                            (Some("days".into()), Some(period))
                        },
                        Some(domain::RetentionPeriod::Years(period)) => {
                            (Some("years".into()), Some(period))
                        },
                        Some(domain::RetentionPeriod::Seconds(period)) => {
                            (Some("seconds".into()), Some(period))
                        },
                        Some(domain::RetentionPeriod::UntilRelease) => {
                            (Some("until_release".into()), None)
                        },
                    };
                    output.event_hold = Some(wire::RepositoryEventHold {
                        enabled: value.is_some(),
                        period_unit,
                        period,
                    });
                }),
            }),
        versioning: observation(policy.versioning, |output, value| {
            output.value = Some(
                match value {
                    domain::VersioningPolicy::Disabled => "disabled",
                    domain::VersioningPolicy::Enabled => "enabled",
                    domain::VersioningPolicy::Suspended => "suspended",
                }
                .into(),
            );
        }),
        object_lock: observation(policy.object_lock, |output, value| match value {
            domain::ObjectLockPolicy::Disabled => output.value = Some("disabled".into()),
            domain::ObjectLockPolicy::Enabled { default_retention } => {
                output.value = Some("enabled".into());
                output.default_retention = default_retention.map(|retention| {
                    let (unit, period) = match retention.period {
                        domain::RetentionPeriod::Days(period) => ("days", period),
                        domain::RetentionPeriod::Years(period) => ("years", period),
                        domain::RetentionPeriod::Seconds(period) => ("seconds", period),
                        domain::RetentionPeriod::UntilRelease => ("until_release", 0),
                    };
                    wire::RepositoryDefaultRetention {
                        mode: match retention.mode {
                            domain::RetentionMode::Governance => "governance",
                            domain::RetentionMode::Compliance => "compliance",
                            domain::RetentionMode::ProviderEnforced => "provider_enforced",
                        }
                        .into(),
                        period_unit: unit.into(),
                        period,
                    }
                });
            },
        }),
        lifecycle: observation(policy.lifecycle, |output, value| {
            output.lifecycle = Some(wire::RepositoryLifecyclePolicy {
                current_expiration: value.current_expiration,
                noncurrent_expiration: value.noncurrent_expiration,
                transition: value.transition,
                abandoned_upload_expiration: value.abandoned_upload_expiration,
            });
        }),
    }
}
fn observation<T>(
    value: domain::PolicyObservation<T>,
    project: impl FnOnce(&mut wire::RepositoryPolicyObservation, T),
) -> wire::RepositoryPolicyObservation {
    let mut output = wire::RepositoryPolicyObservation::default();
    match value {
        domain::PolicyObservation::Observed(value) => {
            output.state = "observed".into();
            project(&mut output, value);
        },
        domain::PolicyObservation::Unobservable => output.state = "unobservable".into(),
        domain::PolicyObservation::Unavailable(failure) => {
            output.state = "unavailable".into();
            output.failure = Some(
                match failure {
                    domain::RepositoryFailure::InvalidInput => "invalid_input",
                    domain::RepositoryFailure::IdentityMismatch => "identity_mismatch",
                    domain::RepositoryFailure::ForeignPrefix => "foreign_prefix",
                    domain::RepositoryFailure::PermissionDenied => "permission_denied",
                    domain::RepositoryFailure::NotFound => "not_found",
                    domain::RepositoryFailure::AlreadyExists => "already_exists",
                    domain::RepositoryFailure::PreconditionFailed => "precondition_failed",
                    domain::RepositoryFailure::Busy => "busy",
                    domain::RepositoryFailure::ChecksumMismatch => "checksum_mismatch",
                    domain::RepositoryFailure::CorruptState => "corrupt_state",
                    domain::RepositoryFailure::StorageUnavailable => "storage_unavailable",
                    domain::RepositoryFailure::OutcomeUnknown => "outcome_unknown",
                    domain::RepositoryFailure::LimitExceeded => "limit_exceeded",
                    domain::RepositoryFailure::Interrupted => "interrupted",
                    domain::RepositoryFailure::Throttled { retry_after_millis } => {
                        output.retry_after_millis = Some(retry_after_millis);
                        "throttled"
                    },
                }
                .into(),
            );
        },
    }
    output
}
