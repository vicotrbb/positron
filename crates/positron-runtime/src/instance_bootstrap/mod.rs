mod codec;
mod operation;
mod resources;
mod storage;
#[cfg(any(test, fuzzing, feature = "test-support"))]
mod test_support;
mod types;

// Direct bootstrap callers have no configuration authority; preserve the shipped
// configuration default until the composition root supplies its resolved value.
const DEFAULT_MAX_REGISTERED_TENANTS: u16 = 2;

#[cfg(test)]
mod tests;

pub(crate) use operation::recover_initial_ledgers;
#[cfg(any(test, feature = "test-support"))]
pub use test_support::GovernanceTestFixture;
pub(crate) use types::TenantRetentionPreviewConfirmation;
pub use types::{
    BackupRepositoryInspection, BootstrapClaim, BootstrapFailure, BootstrapFailureCode,
    BootstrapPaths, BootstrapState, DoctorRuntimeFacts, InitializationPlan, InitializedInstance,
    TenantRetentionImpactPreview,
};

/// The sole Application Runtime authority for classifying and initializing an instance.
pub enum InstanceBootstrap {}

impl InstanceBootstrap {
    pub fn classify(paths: &BootstrapPaths) -> Result<BootstrapState, BootstrapFailure> {
        operation::classify(paths)
    }

    pub fn initialize(
        paths: &BootstrapPaths,
        plan: InitializationPlan,
    ) -> Result<InitializedInstance, BootstrapFailure> {
        Self::initialize_with_max_registered_tenants(paths, plan, DEFAULT_MAX_REGISTERED_TENANTS)
    }

    pub fn reopen(paths: &BootstrapPaths) -> Result<InitializedInstance, BootstrapFailure> {
        Self::reopen_with_max_registered_tenants(paths, DEFAULT_MAX_REGISTERED_TENANTS)
    }

    pub(crate) fn initialize_with_max_registered_tenants(
        paths: &BootstrapPaths,
        plan: InitializationPlan,
        max_registered_tenants: u16,
    ) -> Result<InitializedInstance, BootstrapFailure> {
        operation::initialize(paths, plan, max_registered_tenants)
    }

    pub(crate) fn reopen_with_max_registered_tenants(
        paths: &BootstrapPaths,
        max_registered_tenants: u16,
    ) -> Result<InitializedInstance, BootstrapFailure> {
        operation::reopen(paths, max_registered_tenants)
    }

    pub(crate) fn verify_offline_integrity(
        paths: &BootstrapPaths,
        max_registered_tenants: u16,
        selected_scope: Option<positron_kernel::SegmentScope>,
        resume: Option<crate::OfflineIntegrityContinuation>,
    ) -> Result<crate::OfflineIntegrityVerification, crate::OfflineIntegrityFailure> {
        let cancellation = positron_kernel::IntegrityCancellation::new();
        operation::verify_offline_integrity(
            paths,
            max_registered_tenants,
            selected_scope,
            resume,
            operation::offline_integrity_claim()?,
            &cancellation,
        )
    }

    #[cfg(test)]
    pub(crate) fn verify_offline_integrity_with_claim_for_test(
        paths: &BootstrapPaths,
        max_registered_tenants: u16,
        claim: positron_kernel::WorkClaim,
    ) -> Result<crate::OfflineIntegrityVerification, crate::OfflineIntegrityFailure> {
        let cancellation = positron_kernel::IntegrityCancellation::new();
        operation::verify_offline_integrity(
            paths,
            max_registered_tenants,
            None,
            None,
            claim,
            &cancellation,
        )
    }

    #[cfg(test)]
    pub(crate) fn verify_offline_integrity_with_claim_and_cancellation_for_test(
        paths: &BootstrapPaths,
        max_registered_tenants: u16,
        claim: positron_kernel::WorkClaim,
        cancellation: &positron_kernel::IntegrityCancellation,
    ) -> Result<crate::OfflineIntegrityVerification, crate::OfflineIntegrityFailure> {
        operation::verify_offline_integrity(
            paths,
            max_registered_tenants,
            None,
            None,
            claim,
            cancellation,
        )
    }

    /// Runs one caller-supplied, bounded diagnostic operation under the
    /// exclusive storage and system-only resource authority available when
    /// the local bootstrap key cannot be opened.
    pub fn with_offline_key_unavailable_diagnostics<T>(
        paths: &BootstrapPaths,
        max_registered_tenants: u16,
        claim: positron_kernel::WorkClaim,
        operation: impl FnOnce() -> T,
    ) -> Result<T, crate::OfflineIntegrityFailure> {
        operation::with_offline_key_unavailable_diagnostics(
            paths,
            max_registered_tenants,
            claim,
            operation,
        )
    }

    pub fn claim(paths: &BootstrapPaths) -> Result<BootstrapClaim, BootstrapFailure> {
        operation::claim(paths)
    }
}
