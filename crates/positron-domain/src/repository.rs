//! SDK-free Repository outcomes and native policy observations.
/// Safe closed failures. Provider errors and native credential values never
/// become diagnostic strings or control-flow inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryFailure {
    InvalidInput,
    IdentityMismatch,
    ForeignPrefix,
    PermissionDenied,
    NotFound,
    AlreadyExists,
    PreconditionFailed,
    Busy,
    ChecksumMismatch,
    CorruptState,
    StorageUnavailable,
    OutcomeUnknown,
    LimitExceeded,
    Interrupted,
    Throttled { retry_after_millis: u32 },
}
impl std::fmt::Display for RepositoryFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "repository failure: {self:?}")
    }
}
impl std::error::Error for RepositoryFailure {}

/// Native API observations distinguish denied/unavailable inspection from
/// controls the provider cannot expose. Neither is evidence of absence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyObservation<T> {
    Observed(T),
    Unobservable,
    Unavailable(RepositoryFailure),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersioningPolicy {
    Disabled,
    Enabled,
    Suspended,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionMode {
    Governance,
    Compliance,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionPeriod {
    Days(u32),
    Years(u32),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionPolicy {
    pub mode: RetentionMode,
    pub period: RetentionPeriod,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectLockPolicy {
    Disabled,
    Enabled {
        default_retention: Option<RetentionPolicy>,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecyclePolicy {
    pub current_expiration: bool,
    pub noncurrent_expiration: bool,
    pub transition: bool,
    pub abandoned_upload_expiration: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepositoryPolicy {
    pub versioning: PolicyObservation<VersioningPolicy>,
    pub object_lock: PolicyObservation<ObjectLockPolicy>,
    pub lifecycle: PolicyObservation<LifecyclePolicy>,
    /// Only the owned Doctor probe; never a claim about all stored objects.
    pub doctor_probe: Option<ObjectProtection>,
}
impl RepositoryPolicy {
    /// Native filesystem snapshots and out-of-band retention are not observable
    /// through this adapter. Successful probe deletion cannot qualify them.
    pub const fn local() -> Self {
        Self {
            versioning: PolicyObservation::Unobservable,
            object_lock: PolicyObservation::Unobservable,
            lifecycle: PolicyObservation::Unobservable,
            doctor_probe: None,
        }
    }
}

/// Protection observed on the same authoritative object response as its bytes.
/// Missing headers cannot prove absence of retention or legal hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectRetention {
    pub mode: RetentionMode,
    pub retain_until_unix_seconds: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectProtection {
    pub retention: PolicyObservation<ObjectRetention>,
    pub legal_hold: PolicyObservation<bool>,
    pub event_hold: PolicyObservation<Option<RetentionPeriod>>,
}
impl ObjectProtection {
    pub const fn unobservable() -> Self {
        Self {
            retention: PolicyObservation::Unobservable,
            legal_hold: PolicyObservation::Unobservable,
            event_hold: PolicyObservation::Unobservable,
        }
    }
}
