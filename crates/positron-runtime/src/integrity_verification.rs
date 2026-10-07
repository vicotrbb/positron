mod model;
mod offline;

pub use model::{
    OfflineDiskPressure, OfflineEventRange, OfflineIngestRange, OfflineInspectionFacts,
    OfflineIntegrityAggregateOutcome, OfflineIntegrityContinuation, OfflineIntegrityEvidence,
    OfflineIntegrityFailure, OfflineIntegrityVerification, OfflineLocalizedObservation,
};
pub use offline::{
    resume_offline_integrity, verify_offline_integrity, verify_offline_integrity_scope,
};

#[cfg(test)]
mod tests;
