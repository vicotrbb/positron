//! Deterministic process-stop boundaries for cold Runtime recovery tests.
use super::*;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::services) enum StopPoint {
    RegistryPublished,
    BackupOverlayPublished,
    VerificationMetadataVerified,
    VerificationSemanticVerified,
    VerificationKeyRecovered,
    VerificationReportPublished,
    CaptureCleanupBatch,
    CancellationCommitted,
    ResourcesRequeued,
    ReservationRegistered,
    BeforeKeyUpload,
    KeyPreparationPersisted,
    RegistryCursorPersisted,
}
struct Stop {
    point: StopPoint,
    observed: Arc<AtomicBool>,
}
static STOP: Mutex<Option<Stop>> = Mutex::new(None);
pub(super) fn armed(point: StopPoint) -> Result<bool, ServiceFailure> {
    Ok(STOP
        .lock()
        .map_err(|_| ServiceFailure::Internal)?
        .as_ref()
        .is_some_and(|stop| stop.point == point))
}
pub(super) fn after_cleanup_error(
    cancellation: Option<&crate::TaskCancellation>,
) -> Result<(), ServiceFailure> {
    match hit(StopPoint::CaptureCleanupBatch, cancellation) {
        Err(ServiceFailure::Cancelled) => Ok(()),
        result => result,
    }
}
pub(in crate::services) struct StopGuard {
    observed: Arc<AtomicBool>,
}
impl StopGuard {
    pub(in crate::services) fn observed(&self) -> bool {
        self.observed.load(Ordering::Acquire)
    }
}
impl Drop for StopGuard {
    fn drop(&mut self) {
        if let Ok(mut stop) = STOP.lock() {
            *stop = None;
        }
    }
}
pub(in crate::services) fn stop_after(point: StopPoint) -> Result<StopGuard, ServiceFailure> {
    let mut stop = STOP.lock().map_err(|_| ServiceFailure::Internal)?;
    if stop.is_some() {
        return Err(ServiceFailure::Internal);
    }
    let observed = Arc::new(AtomicBool::new(false));
    *stop = Some(Stop {
        point,
        observed: Arc::clone(&observed),
    });
    Ok(StopGuard { observed })
}
pub(in crate::services) fn hit(
    point: StopPoint,
    cancellation: Option<&crate::TaskCancellation>,
) -> Result<(), ServiceFailure> {
    let mut stop = STOP.lock().map_err(|_| ServiceFailure::Internal)?;
    if stop.as_ref().is_some_and(|stop| stop.point == point) {
        let stop = stop.take().ok_or(ServiceFailure::Internal)?;
        stop.observed.store(true, Ordering::Release);
        if let Some(cancellation) = cancellation {
            cancellation.cancel();
        }
        return Err(ServiceFailure::Cancelled);
    }
    Ok(())
}
