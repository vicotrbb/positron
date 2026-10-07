mod model;
mod offline;

pub use model::{
    OfflineDiskPressure, OfflineInspectionFacts, OfflineIntegrityAggregateOutcome,
    OfflineIntegrityContinuation, OfflineIntegrityEvidence, OfflineIntegrityFailure,
    OfflineIntegrityVerification,
};
pub use offline::{
    resume_offline_integrity, verify_offline_integrity, verify_offline_integrity_scope,
};

#[cfg(test)]
mod tests;
