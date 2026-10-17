//! Declarative upgrades compose the existing Drain, Catalog and Backup owners.
mod artifact;
#[cfg(test)]
#[path = "../../positron-release/tests/support/upgrade_metadata.rs"]
pub(crate) mod fixture_metadata;
pub(crate) mod startup;
pub use startup::UpgradeStartupVerification;
mod offline;
pub use offline::OfflineUpgradeSession;
mod request;
#[cfg(test)]
pub(crate) use request::tests::{installed_trust, qualified_target as qualified_fixture_target};
pub use request::{UpgradeArtifactInput, UpgradeRequest};
mod release_plan;
pub use artifact::UpgradeArtifactIdentity;
pub use release_plan::UpgradeReleasePlan;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpgradeFailure {
    InvalidRequest,
    StaleGeneration,
    IdempotencyConflict,
    AuthenticationFailed,
    ArtifactUnavailable,
    ArtifactMismatch,
    CapacityUnavailable,
    UnsupportedTransition,
    UnsafeState,
    PersistenceUnavailable,
    DrainIncomplete,
    SnapshotUnavailable,
    VerificationFailed,
}
impl std::fmt::Display for UpgradeFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "upgrade rejected: {self:?}")
    }
}
impl std::error::Error for UpgradeFailure {}

/// Cooperate with the native request's existing absolute admission deadline.
pub(crate) fn check_admission_deadline(
    deadline: Option<std::time::Instant>,
) -> Result<(), UpgradeFailure> {
    if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
        return Err(UpgradeFailure::CapacityUnavailable);
    }
    Ok(())
}

/// Keep exclusive cold ownership while the trusted elapsed clock catches up.
/// Reopening instead would restart elapsed time at the same retained anchor.
pub(crate) fn await_lifecycle_time(
    instance: &crate::InitializedInstance,
    updated_at: u64,
    deadline: std::time::Instant,
) -> Result<(), UpgradeFailure> {
    loop {
        let observed = instance
            .retention_time
            .governance_now_seconds()
            .map_err(|_| UpgradeFailure::SnapshotUnavailable)?;
        if observed >= updated_at {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(UpgradeFailure::CapacityUnavailable);
        }
        std::thread::sleep(remaining.min(std::time::Duration::from_millis(10)));
    }
}

#[cfg(test)]
pub(crate) use request::tests::signed as signed_fixture_release;

mod installed;
pub use installed::{installed_upgrade_request, installed_upgrade_startup};
