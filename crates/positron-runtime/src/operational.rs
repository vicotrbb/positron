//! Bounded presentation of facts collected from the existing operational owners.
//! Labels and events are closed vocabulary; no tenant identity enters here.

mod events;
mod metrics;
mod telemetry;

pub use events::{
    IntegrityScrubFailureStage, MaintenanceWorkerOperation, OperationalDiagnostic,
    OperationalReloadRejection, render_operational_diagnostic, write_operational_diagnostic,
};
pub(crate) use events::{OperationalEvent, RequestOutcome};
pub(crate) use metrics::{MAINTENANCE_CLASSES, metrics};
pub(crate) use telemetry::OperationalTelemetry;

#[cfg(fuzzing)]
pub(crate) use telemetry::fuzz_state;
