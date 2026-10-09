use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::sync::{Arc, Barrier, Mutex, mpsc};
use std::time::Duration;

use positron_api::maintenance::{
    AuthenticatedTimeRangeDescriptor, IntegrityQuarantineDescriptor, MAX_INTEGRITY_FINDINGS,
    MAX_STATUS_PAGE_TASKS, MaintenanceExplainRequest, MaintenancePauseRequest,
    MaintenanceResourceReservations, MaintenanceResumeRequest, MaintenanceRunRequest,
    MaintenanceStatusRequest, MaintenanceStatusResponse, MaintenanceTaskStatus,
    MaintenanceWindowRequest, OnlineVerificationRequest,
};
use positron_api::tenant_aliases::TenantAliasBindRequest;
use positron_domain::{routing::SignalKind, time::UnixNanoseconds};
use positron_governance::GovernanceAuditEntry;
use positron_kernel::{
    ActiveSegmentLedger, CatalogPublicationFault, LifecycleClockFailure, LifecycleClockPolicy,
    LifecycleClockSource, MaintenancePreconditions, MaintenanceScope, MaintenanceTask,
    MaintenanceTaskClass, MaintenanceTaskId, MaintenanceTaskPhase, MaintenanceTrigger,
    ResourceAmounts, RetentionTimeAuthority, SegmentScope, with_catalog_publication_fault_after,
};
use positron_query::QueryBudget;
use prost::Message;

use super::super::tests::schema_maintenance::{Fixture, open_catalog, publish_unrelated, request};
use super::super::{OnlineVerificationTestHook, ServiceHandle};
use super::{
    MaintenanceServiceFailure, append_status_task_within_response_limit, hex,
    online_verification_task_identity, task_identity,
};
use crate::{
    ApplicationRuntime, HostInputs, InitializationMode, NativeBindings, NativeHost,
    ServeConfiguration, ShutdownTrigger,
};

struct MutableWallClock(Arc<Mutex<UnixNanoseconds>>);

impl LifecycleClockSource for MutableWallClock {
    fn read(&self) -> Result<UnixNanoseconds, LifecycleClockFailure> {
        self.0
            .lock()
            .map(|value| *value)
            .map_err(|_| LifecycleClockFailure::Unavailable)
    }
}

struct BlockingOnlineVerification {
    captured: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl OnlineVerificationTestHook for BlockingOnlineVerification {
    fn after_basis_capture(&self) {
        let _ = self.captured.send(());
        if let Ok(release) = self.release.lock() {
            let _ = release.recv();
        }
    }
}

struct BlockingOnlineVerificationAdmission {
    captured: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl OnlineVerificationTestHook for BlockingOnlineVerificationAdmission {
    fn after_admission(&self) {
        let _ = self.captured.send(());
        if let Ok(release) = self.release.lock() {
            let _ = release.recv();
        }
    }

    fn after_basis_capture(&self) {}
}

#[path = "maintenance_api_tests/control.rs"]
mod control;
#[path = "maintenance_api_tests/status.rs"]
mod status;
#[path = "maintenance_api_tests/verification.rs"]
mod verification;
#[path = "maintenance_api_tests/window.rs"]
mod window;

#[path = "maintenance_api_tests/abandonment.rs"]
mod abandonment;

#[cfg(unix)]
#[path = "maintenance_api_tests/fencing_causes.rs"]
mod fencing_causes;
