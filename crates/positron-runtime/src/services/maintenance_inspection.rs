use positron_api::maintenance::{MaintenanceResourceReservations, MaintenanceTaskStatus};
use positron_kernel::{
    MaintenanceCoordinator, MaintenanceFailure, MaintenanceReservationAuthority,
    MaintenanceTaskPhase, NO_DURABLE_PROGRESS_SLO_SECONDS, ResourceDimension,
};

use super::maintenance_api::{class_name, hex, phase_name, scope_name};

pub(super) fn task_status_for_coordinator(
    coordinator: &MaintenanceCoordinator,
    status: positron_kernel::MaintenanceTaskStatus,
    now: Option<u64>,
) -> Result<MaintenanceTaskStatus, MaintenanceFailure> {
    let active_window_until = now
        .map(|current| coordinator.active_window_until(status.task().identity(), current))
        .transpose()?
        .flatten();
    let window_until = (status.phase() == MaintenanceTaskPhase::Queued)
        .then_some(active_window_until)
        .flatten();
    Ok(task_status(status, now, window_until, active_window_until))
}

fn task_status(
    status: positron_kernel::MaintenanceTaskStatus,
    now: Option<u64>,
    window_until: Option<u64>,
    active_window_until: Option<u64>,
) -> MaintenanceTaskStatus {
    let task = status.task();
    let phase = status.phase();
    let paused = phase == MaintenanceTaskPhase::Deferred && status.pause_until().is_some();
    let reservations = task.reservations();
    let input_object_count = task.inputs().len() as u32;
    let output_object_count = task.outputs().len() as u32;
    let estimated_output_object_amplification_milli = (input_object_count != 0
        && output_object_count != 0)
        .then(|| {
            output_object_count
                .checked_mul(1_000)
                .and_then(|scaled| scaled.checked_div(input_object_count))
        })
        .flatten();
    let conflict_owner = status.conflict_owner();
    let blocked_precondition = if status.clock_uncertain_blocked() {
        Some("clock_uncertain_destructive_schedule".to_owned())
    } else if paused {
        Some("maintenance_pause_active".to_owned())
    } else if window_until.is_some() {
        Some("maintenance_window_active".to_owned())
    } else if conflict_owner.is_some() {
        Some("conflict_owner_active".to_owned())
    } else if phase == MaintenanceTaskPhase::Queued
        && now.is_some_and(|current| task.not_before() > current)
    {
        Some("scheduled_start_time".to_owned())
    } else {
        None
    };
    let reservation_view = MaintenanceResourceReservations {
        memory_bytes: reservations.get(ResourceDimension::MemoryBytes),
        queue_slots: reservations.get(ResourceDimension::QueueSlots),
        task_slots: reservations.get(ResourceDimension::TaskSlots),
        buffer_cache_bytes: reservations.get(ResourceDimension::BufferCacheBytes),
        batch_items: reservations.get(ResourceDimension::BatchItems),
        lease_slots: reservations.get(ResourceDimension::LeaseSlots),
        retry_slots: reservations.get(ResourceDimension::RetrySlots),
        io_permits: reservations.get(ResourceDimension::IoPermits),
        cpu_work_units: reservations.get(ResourceDimension::CpuWorkUnits),
        file_descriptors: reservations.get(ResourceDimension::FileDescriptors),
        disk_headroom_bytes: reservations.get(ResourceDimension::DiskHeadroomBytes),
    };
    let deferral_active = paused || active_window_until.is_some();
    let automatic_resume_at_unix_seconds = match (status.pause_until(), active_window_until) {
        (Some(pause_until), Some(window_until)) => Some(pause_until.max(window_until)),
        (Some(pause_until), None) => Some(pause_until),
        (None, Some(window_until)) => Some(window_until),
        (None, None) => None,
    };
    MaintenanceTaskStatus {
        identity: hex(task.identity().to_bytes()),
        class: class_name(task.class()).to_owned(),
        scope: scope_name(task.scope()),
        phase: phase_name(phase).to_owned(),
        submitted_at_unix_seconds: status.submitted_at(),
        checkpoint_sequence: status.checkpoint().map(|checkpoint| checkpoint.sequence()),
        last_progress_at_unix_seconds: status.last_progress_at(),
        no_durable_progress_slo_breached: status.no_durable_progress_slo_breached(),
        no_durable_progress_slo_seconds: (phase == MaintenanceTaskPhase::Running)
            .then_some(NO_DURABLE_PROGRESS_SLO_SECONDS),
        capacity_risk: (!matches!(
            phase,
            MaintenanceTaskPhase::Cancelled
                | MaintenanceTaskPhase::Succeeded
                | MaintenanceTaskPhase::Failed
        ))
        .then(|| match task.reservation_authority() {
            MaintenanceReservationAuthority::Foreground => "foreground_reservation".to_owned(),
            MaintenanceReservationAuthority::RecoveryReserve => "recovery_reserve".to_owned(),
        }),
        retention_impact: if status.clock_uncertain_blocked() {
            Some("eligibility_unknown".to_owned())
        } else if deferral_active {
            Some("unaffected".to_owned())
        } else {
            None
        },
        recovery_impact: deferral_active.then_some("unaffected".to_owned()),
        automatic_resume_at_unix_seconds,
        pause_until_unix_seconds: status.pause_until(),
        cancellation_requested: status.cancellation_requested(),
        resource_generation: Some(task.preconditions().resource_generation()),
        reservations: Some(reservation_view.clone()),
        expected_foreground_impact: Some(reservation_view),
        blocked_precondition,
        maintenance_window_until_unix_seconds: active_window_until,
        safe_actions: if paused {
            vec!["resume".to_owned()]
        } else if phase == MaintenanceTaskPhase::Queued && task.is_pause_deferrable() {
            vec!["pause".to_owned()]
        } else {
            Vec::new()
        },
        backlog_age_seconds: now.map(|current| current.saturating_sub(status.submitted_at())),
        conflict_owner: conflict_owner.map(|identity| hex(identity.to_bytes())),
        checkpoint_completed_inputs: status
            .checkpoint()
            .map(positron_kernel::MaintenanceCheckpoint::completed_inputs),
        input_object_count,
        output_object_count,
        estimated_output_object_amplification_milli,
        terminal_outcome: match phase {
            MaintenanceTaskPhase::Cancelled => Some("cancelled".to_owned()),
            MaintenanceTaskPhase::Succeeded => Some("succeeded".to_owned()),
            MaintenanceTaskPhase::Failed => Some("failed".to_owned()),
            MaintenanceTaskPhase::Queued
            | MaintenanceTaskPhase::Running
            | MaintenanceTaskPhase::Deferred => None,
        },
        terminal_failure_class: status.terminal_failure().map(terminal_failure_class),
    }
}

fn terminal_failure_class(failure: positron_kernel::MaintenanceTerminalFailure) -> String {
    match failure {
        positron_kernel::MaintenanceTerminalFailure::IdentityMismatch => {
            "identity_mismatch".to_owned()
        },
        positron_kernel::MaintenanceTerminalFailure::StaleGeneration => {
            "stale_generation".to_owned()
        },
        positron_kernel::MaintenanceTerminalFailure::Unclassified => "unclassified".to_owned(),
    }
}
