use super::*;
use crate::{BootstrapPaths, InstanceBootstrap};
use positron_kernel::SegmentScope;

/// Begins a bounded offline verification sequence without creating or
/// repairing bootstrap, Catalog, ledger, or quarantine state. Scope discovery
/// is bounded by the authenticated Catalog's 1,024-object limit; this
/// invocation processes one scope under the kernel's 128-segment, 16 MiB
/// scrub-pass budget and reports authenticated progress instead of continuing
/// internally.
pub fn verify_offline_integrity(
    paths: &BootstrapPaths,
    max_registered_tenants: u16,
) -> Result<OfflineIntegrityVerification, OfflineIntegrityFailure> {
    InstanceBootstrap::verify_offline_integrity(paths, max_registered_tenants, None, None)
}

/// Verifies one caller-selected offline scope without promoting it to an
/// aggregate verification claim.
pub fn verify_offline_integrity_scope(
    paths: &BootstrapPaths,
    max_registered_tenants: u16,
    scope: SegmentScope,
) -> Result<OfflineIntegrityVerification, OfflineIntegrityFailure> {
    InstanceBootstrap::verify_offline_integrity(paths, max_registered_tenants, Some(scope), None)
}

/// Resumes exactly one bounded offline scrub pass from an authenticated
/// cursor. The caller names the scope so the cursor never selects source
/// bytes outside its reported result.
pub fn resume_offline_integrity(
    paths: &BootstrapPaths,
    max_registered_tenants: u16,
    continuation: OfflineIntegrityContinuation,
) -> Result<OfflineIntegrityVerification, OfflineIntegrityFailure> {
    InstanceBootstrap::verify_offline_integrity(
        paths,
        max_registered_tenants,
        None,
        Some(continuation),
    )
}
