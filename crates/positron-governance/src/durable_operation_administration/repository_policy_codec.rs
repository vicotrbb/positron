//! Bounded policy observations in the existing terminal operation record.
use super::{
    DurableOperationFailure,
    codec::{take_array, take_byte},
};
use positron_domain::repository::*;
const MAGIC: &[u8; 8] = b"POSRPL01";
const MAX_LENGTH: usize = 96;
type Failure = DurableOperationFailure;
fn invalid() -> Failure {
    Failure::PersistenceUnavailable
}

/// Checked terminal value: encoding cannot discard a failed validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RepositoryPolicyReceipt {
    policy: RepositoryPolicy,
    bytes: [u8; MAX_LENGTH],
    length: u8,
}
impl RepositoryPolicyReceipt {
    pub(super) fn new(policy: RepositoryPolicy) -> Result<Self, Failure> {
        let encoded = encode(policy)?;
        let length = u8::try_from(encoded.len()).map_err(|_| invalid())?;
        if encoded.len() > MAX_LENGTH {
            return Err(invalid());
        }
        let mut bytes = [0; MAX_LENGTH];
        for (slot, value) in bytes.iter_mut().zip(encoded) {
            *slot = value;
        }
        Ok(Self {
            policy,
            bytes,
            length,
        })
    }
    pub(super) const fn policy(self) -> RepositoryPolicy {
        self.policy
    }
    pub(super) fn encoded_bytes(&self) -> impl Iterator<Item = u8> + '_ {
        self.bytes.iter().take(usize::from(self.length)).copied()
    }
}

pub(super) fn encode(policy: RepositoryPolicy) -> Result<Vec<u8>, Failure> {
    let mut bytes = Vec::with_capacity(MAX_LENGTH);
    bytes.extend_from_slice(MAGIC);
    observation(&mut bytes, policy.versioning, |bytes, value| {
        bytes.push(match value {
            VersioningPolicy::Disabled => 0,
            VersioningPolicy::Enabled => 1,
            VersioningPolicy::Suspended => 2,
        });
        Ok(())
    })?;
    observation(&mut bytes, policy.object_lock, |bytes, value| {
        match value {
            ObjectLockPolicy::Disabled => bytes.push(0),
            ObjectLockPolicy::Enabled {
                default_retention: None,
            } => bytes.push(1),
            ObjectLockPolicy::Enabled {
                default_retention: Some(retention),
            } => {
                bytes.push(2);
                bytes.push(match retention.mode {
                    RetentionMode::Governance => 0,
                    RetentionMode::Compliance => 1,
                    RetentionMode::ProviderEnforced => 2,
                });
                let (unit, amount) = match retention.period {
                    RetentionPeriod::Days(amount) => (0, amount),
                    RetentionPeriod::Years(amount) => (1, amount),
                    RetentionPeriod::Seconds(amount) => (2, amount),
                    RetentionPeriod::UntilRelease => return Err(invalid()),
                };
                if amount == 0 {
                    return Err(invalid());
                }
                bytes.push(unit);
                bytes.extend_from_slice(&amount.to_be_bytes());
            },
        }
        Ok(())
    })?;
    observation(&mut bytes, policy.lifecycle, |bytes, value| {
        bytes.push(
            u8::from(value.current_expiration)
                | (u8::from(value.noncurrent_expiration) << 1)
                | (u8::from(value.transition) << 2)
                | (u8::from(value.abandoned_upload_expiration) << 3),
        );
        Ok(())
    })?;
    if let Some(probe) = policy.doctor_probe {
        bytes.extend_from_slice(b"POSROP01");
        observation(&mut bytes, probe.retention, |bytes, value| {
            if value.retain_until_unix_seconds == 0 {
                return Err(invalid());
            }
            bytes.push(match value.mode {
                RetentionMode::Governance => 0,
                RetentionMode::Compliance => 1,
                RetentionMode::ProviderEnforced => 2,
            });
            bytes.extend_from_slice(&value.retain_until_unix_seconds.to_be_bytes());
            Ok(())
        })?;
        observation(&mut bytes, probe.legal_hold, |bytes, value| {
            bytes.push(u8::from(value));
            Ok(())
        })?;
        observation(&mut bytes, probe.event_hold, |bytes, value| {
            match value {
                None => bytes.push(0),
                Some(period) => {
                    let (unit, amount) = match period {
                        RetentionPeriod::Days(amount) => (1, amount),
                        RetentionPeriod::Years(amount) => (2, amount),
                        RetentionPeriod::Seconds(amount) => (3, amount),
                        RetentionPeriod::UntilRelease => (4, 0),
                    };
                    if amount == 0 && unit != 4 {
                        return Err(invalid());
                    }
                    bytes.push(unit);
                    bytes.extend_from_slice(&amount.to_be_bytes());
                },
            }
            Ok(())
        })?;
    }
    if let Some(soft_delete) = policy.soft_delete {
        bytes.extend_from_slice(b"POSRSD01");
        observation(&mut bytes, soft_delete, |bytes, seconds| {
            bytes.extend_from_slice(&seconds.to_be_bytes());
            Ok(())
        })?;
    }
    Ok(bytes)
}
fn observation<T>(
    bytes: &mut Vec<u8>,
    value: PolicyObservation<T>,
    encode: impl FnOnce(&mut Vec<u8>, T) -> Result<(), Failure>,
) -> Result<(), Failure> {
    match value {
        PolicyObservation::Observed(value) => {
            bytes.push(0);
            encode(bytes, value)?;
        },
        PolicyObservation::Unobservable => bytes.push(1),
        PolicyObservation::Unavailable(failure) => {
            bytes.push(2);
            encode_failure(bytes, failure)?;
        },
    }
    Ok(())
}
fn encode_failure(bytes: &mut Vec<u8>, failure: RepositoryFailure) -> Result<(), Failure> {
    let code = match failure {
        RepositoryFailure::InvalidInput => 0,
        RepositoryFailure::IdentityMismatch => 1,
        RepositoryFailure::ForeignPrefix => 2,
        RepositoryFailure::PermissionDenied => 3,
        RepositoryFailure::NotFound => 4,
        RepositoryFailure::AlreadyExists => 5,
        RepositoryFailure::PreconditionFailed => 6,
        RepositoryFailure::Busy => 7,
        RepositoryFailure::ChecksumMismatch => 8,
        RepositoryFailure::CorruptState => 9,
        RepositoryFailure::StorageUnavailable => 10,
        RepositoryFailure::OutcomeUnknown => 11,
        RepositoryFailure::LimitExceeded => 12,
        RepositoryFailure::Interrupted => 13,
        RepositoryFailure::Throttled { retry_after_millis } => {
            if !(100..=60_000).contains(&retry_after_millis) {
                return Err(invalid());
            }
            bytes.push(14);
            bytes.extend_from_slice(&retry_after_millis.to_be_bytes());
            return Ok(());
        },
    };
    bytes.push(code);
    Ok(())
}
pub(super) fn decode(bytes: &[u8]) -> Result<RepositoryPolicyReceipt, Failure> {
    if bytes.len() > MAX_LENGTH || !bytes.starts_with(MAGIC) {
        return Err(invalid());
    }
    let mut offset = MAGIC.len();
    let versioning = read_observation(bytes, &mut offset, |bytes, offset| {
        match take_byte(bytes, offset)? {
            0 => Ok(VersioningPolicy::Disabled),
            1 => Ok(VersioningPolicy::Enabled),
            2 => Ok(VersioningPolicy::Suspended),
            _ => Err(invalid()),
        }
    })?;
    let object_lock = read_observation(bytes, &mut offset, |bytes, offset| {
        match take_byte(bytes, offset)? {
            0 => Ok(ObjectLockPolicy::Disabled),
            1 => Ok(ObjectLockPolicy::Enabled {
                default_retention: None,
            }),
            2 => {
                let mode = match take_byte(bytes, offset)? {
                    0 => RetentionMode::Governance,
                    1 => RetentionMode::Compliance,
                    2 => RetentionMode::ProviderEnforced,
                    _ => return Err(invalid()),
                };
                let unit = take_byte(bytes, offset)?;
                let amount = u32::from_be_bytes(take_array(bytes, offset)?);
                if amount == 0 {
                    return Err(invalid());
                }
                let period = match unit {
                    0 => RetentionPeriod::Days(amount),
                    1 => RetentionPeriod::Years(amount),
                    2 => RetentionPeriod::Seconds(amount),
                    _ => return Err(invalid()),
                };
                Ok(ObjectLockPolicy::Enabled {
                    default_retention: Some(RetentionPolicy { mode, period }),
                })
            },
            _ => Err(invalid()),
        }
    })?;
    let lifecycle = read_observation(bytes, &mut offset, |bytes, offset| {
        let flags = take_byte(bytes, offset)?;
        if flags > 15 {
            return Err(invalid());
        }
        Ok(LifecyclePolicy {
            current_expiration: flags & 1 != 0,
            noncurrent_expiration: flags & 2 != 0,
            transition: flags & 4 != 0,
            abandoned_upload_expiration: flags & 8 != 0,
        })
    })?;
    let doctor_probe = if bytes.get(offset..offset + 8) != Some(b"POSROP01") {
        None
    } else {
        if take_array::<8>(bytes, &mut offset)? != *b"POSROP01" {
            return Err(invalid());
        }
        let retention = read_observation(bytes, &mut offset, |bytes, offset| {
            let mode = match take_byte(bytes, offset)? {
                0 => RetentionMode::Governance,
                1 => RetentionMode::Compliance,
                2 => RetentionMode::ProviderEnforced,
                _ => return Err(invalid()),
            };
            let retain_until_unix_seconds = u64::from_be_bytes(take_array(bytes, offset)?);
            if retain_until_unix_seconds == 0 {
                return Err(invalid());
            }
            Ok(ObjectRetention {
                mode,
                retain_until_unix_seconds,
            })
        })?;
        let legal_hold = read_observation(bytes, &mut offset, |bytes, offset| {
            match take_byte(bytes, offset)? {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(invalid()),
            }
        })?;
        let event_hold = read_observation(bytes, &mut offset, |bytes, offset| {
            let unit = take_byte(bytes, offset)?;
            if unit == 0 {
                return Ok(None);
            }
            let amount = u32::from_be_bytes(take_array(bytes, offset)?);
            if amount == 0 && unit != 4 {
                return Err(invalid());
            }
            match unit {
                1 => Ok(Some(RetentionPeriod::Days(amount))),
                2 => Ok(Some(RetentionPeriod::Years(amount))),
                3 => Ok(Some(RetentionPeriod::Seconds(amount))),
                4 if amount == 0 => Ok(Some(RetentionPeriod::UntilRelease)),
                _ => Err(invalid()),
            }
        })?;
        Some(ObjectProtection {
            retention,
            legal_hold,
            event_hold,
        })
    };
    let soft_delete = if offset == bytes.len() {
        None
    } else {
        if take_array::<8>(bytes, &mut offset)? != *b"POSRSD01" {
            return Err(invalid());
        }
        Some(read_observation(bytes, &mut offset, |bytes, offset| {
            Ok(u64::from_be_bytes(take_array(bytes, offset)?))
        })?)
    };
    if offset != bytes.len() {
        return Err(invalid());
    }
    RepositoryPolicyReceipt::new(RepositoryPolicy {
        soft_delete,
        versioning,
        object_lock,
        lifecycle,
        doctor_probe,
    })
}
fn read_observation<T>(
    bytes: &[u8],
    offset: &mut usize,
    decode: impl FnOnce(&[u8], &mut usize) -> Result<T, Failure>,
) -> Result<PolicyObservation<T>, Failure> {
    match take_byte(bytes, offset)? {
        0 => Ok(PolicyObservation::Observed(decode(bytes, offset)?)),
        1 => Ok(PolicyObservation::Unobservable),
        2 => Ok(PolicyObservation::Unavailable(decode_failure(
            bytes, offset,
        )?)),
        _ => Err(invalid()),
    }
}
fn decode_failure(bytes: &[u8], offset: &mut usize) -> Result<RepositoryFailure, Failure> {
    Ok(match take_byte(bytes, offset)? {
        0 => RepositoryFailure::InvalidInput,
        1 => RepositoryFailure::IdentityMismatch,
        2 => RepositoryFailure::ForeignPrefix,
        3 => RepositoryFailure::PermissionDenied,
        4 => RepositoryFailure::NotFound,
        5 => RepositoryFailure::AlreadyExists,
        6 => RepositoryFailure::PreconditionFailed,
        7 => RepositoryFailure::Busy,
        8 => RepositoryFailure::ChecksumMismatch,
        9 => RepositoryFailure::CorruptState,
        10 => RepositoryFailure::StorageUnavailable,
        11 => RepositoryFailure::OutcomeUnknown,
        12 => RepositoryFailure::LimitExceeded,
        13 => RepositoryFailure::Interrupted,
        14 => {
            let retry_after_millis = u32::from_be_bytes(take_array(bytes, offset)?);
            if !(100..=60_000).contains(&retry_after_millis) {
                return Err(invalid());
            }
            RepositoryFailure::Throttled { retry_after_millis }
        },
        _ => return Err(invalid()),
    })
}
