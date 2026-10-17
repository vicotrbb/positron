//! Declarative upgrades compose the existing Drain, Catalog and Backup owners.
mod artifact;
pub(crate) mod startup;
pub use startup::UpgradeStartupVerification;
mod offline;
pub use offline::OfflineUpgradeSession;
mod request;
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

#[cfg(test)]
pub(crate) use request::tests::signed as signed_fixture_release;

mod installed;
pub use installed::{installed_upgrade_request, installed_upgrade_startup};
