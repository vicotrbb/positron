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
    VerificationNativeFileVerified,
    VerificationRemoteRangeVerified,
    VerificationRemoteCheckpointDue,
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
    instance: [u8; 16],
    operation: [u8; 16],
    point: StopPoint,
    observed: Arc<AtomicBool>,
}
static STOP: Mutex<Option<Stop>> = Mutex::new(None);
pub(super) fn armed(
    instance: [u8; 16],
    operation: [u8; 16],
    point: StopPoint,
) -> Result<bool, ServiceFailure> {
    Ok(STOP
        .lock()
        .map_err(|_| ServiceFailure::Internal)?
        .as_ref()
        .is_some_and(|stop| {
            stop.instance == instance && stop.operation == operation && stop.point == point
        }))
}
pub(super) fn after_cleanup_error(
    instance: [u8; 16],
    operation: [u8; 16],
    cancellation: Option<&crate::TaskCancellation>,
) -> Result<(), ServiceFailure> {
    match hit(
        instance,
        operation,
        StopPoint::CaptureCleanupBatch,
        cancellation,
    ) {
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
        if let Ok(mut stop) = STOP.lock()
            && stop
                .as_ref()
                .is_some_and(|registration| Arc::ptr_eq(&registration.observed, &self.observed))
        {
            *stop = None;
        }
    }
}
pub(in crate::services) fn stop_after(
    instance: [u8; 16],
    operation: [u8; 16],
    point: StopPoint,
) -> Result<StopGuard, ServiceFailure> {
    let mut stop = STOP.lock().map_err(|_| ServiceFailure::Internal)?;
    if stop.is_some() {
        return Err(ServiceFailure::Internal);
    }
    let observed = Arc::new(AtomicBool::new(false));
    *stop = Some(Stop {
        instance,
        operation,
        point,
        observed: Arc::clone(&observed),
    });
    Ok(StopGuard { observed })
}
pub(in crate::services) fn hit(
    instance: [u8; 16],
    operation: [u8; 16],
    point: StopPoint,
    cancellation: Option<&crate::TaskCancellation>,
) -> Result<(), ServiceFailure> {
    let mut stop = STOP.lock().map_err(|_| ServiceFailure::Internal)?;
    if stop.as_ref().is_some_and(|stop| {
        stop.instance == instance && stop.operation == operation && stop.point == point
    }) {
        let stop = stop.take().ok_or(ServiceFailure::Internal)?;
        stop.observed.store(true, Ordering::Release);
        if let Some(cancellation) = cancellation {
            cancellation.cancel();
        }
        return Err(ServiceFailure::Cancelled);
    }
    Ok(())
}

#[test]
fn stop_is_owned_by_its_instance_and_operation() -> Result<(), ServiceFailure> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let owner = stop_after([1; 16], [3; 16], StopPoint::ResourcesRequeued)?;
    assert!(armed([1; 16], [3; 16], StopPoint::ResourcesRequeued)?);
    assert!(!armed([2; 16], [3; 16], StopPoint::ResourcesRequeued)?);
    assert!(!armed([1; 16], [4; 16], StopPoint::ResourcesRequeued)?);
    let foreign = crate::TaskCancellation::new();
    assert_eq!(
        hit(
            [2; 16],
            [3; 16],
            StopPoint::ResourcesRequeued,
            Some(&foreign)
        ),
        Ok(())
    );
    assert!(!foreign.is_cancelled());
    assert!(!owner.observed());
    let other_task = crate::TaskCancellation::new();
    assert_eq!(
        hit(
            [1; 16],
            [4; 16],
            StopPoint::ResourcesRequeued,
            Some(&other_task)
        ),
        Ok(())
    );
    assert!(!other_task.is_cancelled());
    assert!(!owner.observed());
    let own = crate::TaskCancellation::new();
    assert_eq!(
        hit([1; 16], [3; 16], StopPoint::ResourcesRequeued, Some(&own)),
        Err(ServiceFailure::Cancelled)
    );
    assert!(own.is_cancelled());
    assert!(owner.observed());
    Ok(())
}

#[test]
fn consumed_guard_does_not_disarm_its_successor() -> Result<(), ServiceFailure> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let previous = stop_after([1; 16], [3; 16], StopPoint::ResourcesRequeued)?;
    assert_eq!(
        hit([1; 16], [3; 16], StopPoint::ResourcesRequeued, None),
        Err(ServiceFailure::Cancelled)
    );
    let successor = stop_after([1; 16], [3; 16], StopPoint::ResourcesRequeued)?;
    drop(previous);
    assert_eq!(
        hit([1; 16], [3; 16], StopPoint::ResourcesRequeued, None),
        Err(ServiceFailure::Cancelled)
    );
    assert!(successor.observed());
    Ok(())
}
