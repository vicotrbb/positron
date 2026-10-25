//! Bounded presentation of facts collected from the existing operational owners.
//! Labels and events are closed vocabulary; no tenant identity enters here.

mod events;
mod metrics;
mod telemetry;

pub(crate) use events::{BackupReadStage, OperationalEvent, RequestOutcome};
pub use events::{
    IntegrityScrubFailureStage, MaintenanceWorkerOperation, OperationalDiagnostic,
    OperationalReloadRejection, render_operational_diagnostic, write_operational_diagnostic,
};
pub(crate) use metrics::{MAINTENANCE_CLASSES, metrics};
pub(crate) use telemetry::OperationalTelemetry;

#[cfg(fuzzing)]
pub(crate) use telemetry::fuzz_state;

#[cfg(test)]
#[path = "operational/tests.rs"]
mod tests;
