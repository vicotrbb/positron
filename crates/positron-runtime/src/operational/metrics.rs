//! Closed metric families rendered directly from canonical owner snapshots.

use crate::health::OperationsStatus;
use crate::{HealthState, Liveness, ProcessPhase, Readiness};

pub(crate) const MAINTENANCE_CLASSES: [(positron_kernel::MaintenanceTaskClass, &str); 22] = [
    (
        positron_kernel::MaintenanceTaskClass::ActiveSegmentRoll,
        "active_segment_roll",
    ),
    (
        positron_kernel::MaintenanceTaskClass::Compaction,
        "compaction",
    ),
    (
        positron_kernel::MaintenanceTaskClass::RetentionPublication,
        "retention_publication",
    ),
    (
        positron_kernel::MaintenanceTaskClass::RetentionReclamation,
        "retention_reclamation",
    ),
    (
        positron_kernel::MaintenanceTaskClass::CatalogReclamation,
        "catalog_reclamation",
    ),
    (
        positron_kernel::MaintenanceTaskClass::OrphanReclamation,
        "orphan_reclamation",
    ),
    (
        positron_kernel::MaintenanceTaskClass::IntegrityScrub,
        "integrity_scrub",
    ),
    (
        positron_kernel::MaintenanceTaskClass::QuarantineFollowUp,
        "quarantine_follow_up",
    ),
    (
        positron_kernel::MaintenanceTaskClass::SchemaStatistics,
        "schema_statistics",
    ),
    (
        positron_kernel::MaintenanceTaskClass::SchemaPromotion,
        "schema_promotion",
    ),
    (
        positron_kernel::MaintenanceTaskClass::SchemaDemotion,
        "schema_demotion",
    ),
    (
        positron_kernel::MaintenanceTaskClass::GovernanceAuditCheckpoint,
        "governance_audit_checkpoint",
    ),
    (
        positron_kernel::MaintenanceTaskClass::KeyRewrap,
        "key_rewrap",
    ),
    (
        positron_kernel::MaintenanceTaskClass::EnvelopeVerification,
        "envelope_verification",
    ),
    (
        positron_kernel::MaintenanceTaskClass::Migration,
        "migration",
    ),
    (
        positron_kernel::MaintenanceTaskClass::RepositoryVerification,
        "repository_verification",
    ),
    (
        positron_kernel::MaintenanceTaskClass::RepositoryCleanup,
        "repository_cleanup",
    ),
    (
        positron_kernel::MaintenanceTaskClass::BackupSnapshot,
        "backup_snapshot",
    ),
    (
        positron_kernel::MaintenanceTaskClass::DurableExport,
        "durable_export",
    ),
    (
        positron_kernel::MaintenanceTaskClass::SnapshotLeaseExpiry,
        "snapshot_lease_expiry",
    ),
    (
        positron_kernel::MaintenanceTaskClass::CompletedOperationExpiry,
        "completed_operation_expiry",
    ),
    (
        positron_kernel::MaintenanceTaskClass::TenantPurge,
        "tenant_purge",
    ),
];

pub(crate) fn metrics(
    health: &HealthState,
    status: Option<&OperationsStatus>,
    openmetrics: bool,
) -> String {
    let mut output = String::with_capacity(8192);
    gauge(
        &mut output,
        "process_live",
        u64::from(health.liveness() == Liveness::Live),
    );
    gauge(
        &mut output,
        "process_ready",
        u64::from(health.readiness() == Readiness::Ready),
    );
    gauge(
        &mut output,
        "integrity_degraded",
        u64::from(health.integrity_degraded()),
    );
    output.push_str("# TYPE positron_process_phase gauge\n");
    let observed_phase = health.phase();
    for (phase, label) in [
        (ProcessPhase::Starting, "starting"),
        (ProcessPhase::Recovering, "recovering"),
        (ProcessPhase::Serving, "serving"),
        (ProcessPhase::Draining, "draining"),
        (ProcessPhase::Fenced, "fenced"),
        (ProcessPhase::Stopping, "stopping"),
        (ProcessPhase::Stopped, "stopped"),
    ] {
        output.push_str(&format!(
            "positron_process_phase{{phase=\"{label}\"}} {}\n",
            u8::from(observed_phase == phase)
        ));
    }
    output.push_str("# TYPE positron_security_warning gauge\n");
    let warnings = health.security_warnings();
    for label in [
        "control_plaintext",
        "operations_plaintext",
        "public_plaintext_api",
        "otlp_grpc_plaintext",
        "otlp_http_plaintext",
        "loki_push_plaintext",
    ] {
        output.push_str(&format!(
            "positron_security_warning{{warning=\"{label}\"}} {}\n",
            u8::from(warnings.iter().any(|warning| warning.label() == label))
        ));
    }
    gauge(
        &mut output,
        "operational_owner_available",
        u64::from(status.is_some()),
    );
    let Some(status) = status else {
        health
            .operational_telemetry()
            .metrics(&mut output, openmetrics);
        return output;
    };
    let resources = status.resources;
    let dimensions = [
        (
            positron_kernel::ResourceDimension::MemoryBytes,
            "memory_bytes",
        ),
        (
            positron_kernel::ResourceDimension::QueueSlots,
            "queue_slots",
        ),
        (positron_kernel::ResourceDimension::TaskSlots, "task_slots"),
        (
            positron_kernel::ResourceDimension::BufferCacheBytes,
            "buffer_cache_bytes",
        ),
        (
            positron_kernel::ResourceDimension::BatchItems,
            "batch_items",
        ),
        (
            positron_kernel::ResourceDimension::LeaseSlots,
            "lease_slots",
        ),
        (
            positron_kernel::ResourceDimension::RetrySlots,
            "retry_slots",
        ),
        (positron_kernel::ResourceDimension::IoPermits, "io_permits"),
        (
            positron_kernel::ResourceDimension::CpuWorkUnits,
            "cpu_work_units",
        ),
        (
            positron_kernel::ResourceDimension::FileDescriptors,
            "file_descriptors",
        ),
        (
            positron_kernel::ResourceDimension::DiskHeadroomBytes,
            "disk_headroom_bytes",
        ),
    ];
    for metric in ["usage", "capacity", "ordinary_capacity", "recovery_reserve"] {
        output.push_str(&format!("# TYPE positron_resource_{metric} gauge\n"));
        for (dimension, label) in dimensions {
            let value = match metric {
                "usage" => resources.usage(dimension),
                "capacity" => resources.effective_capacity(dimension),
                "ordinary_capacity" => resources.ordinary_capacity(dimension),
                _ => resources.recovery_reserve_capacity(dimension),
            };
            output.push_str(&format!(
                "positron_resource_{metric}{{dimension=\"{label}\"}} {value}\n"
            ));
        }
    }
    output.push_str("# TYPE positron_disk_pressure gauge\n");
    for (pressure, label) in [
        (positron_kernel::DiskPressureState::Healthy, "healthy"),
        (positron_kernel::DiskPressureState::SoftPressure, "soft"),
        (positron_kernel::DiskPressureState::HardPressure, "hard"),
    ] {
        output.push_str(&format!(
            "positron_disk_pressure{{state=\"{label}\"}} {}\n",
            u8::from(resources.disk_pressure() == pressure)
        ));
    }
    gauge(
        &mut output,
        "disk_usable_bytes",
        resources.usable_disk_bytes(),
    );
    for (name, value) in [
        ("resource_rejections_total", resources.rejection_count()),
        (
            "disk_pressure_transitions_total",
            resources.pressure_transition_count(),
        ),
    ] {
        counter_type(&mut output, name, openmetrics);
        output.push_str(&format!("positron_{name} {value}\n"));
    }
    let m = status.maintenance;
    output.push_str("# TYPE positron_maintenance_tasks_by_class gauge\n");
    for ((_, class), counts) in MAINTENANCE_CLASSES.iter().zip(m.by_class.iter()) {
        for (phase, count) in [
            "queued",
            "running",
            "deferred",
            "cancelled",
            "succeeded",
            "failed",
        ]
        .iter()
        .zip(counts.iter())
        {
            output.push_str(&format!("positron_maintenance_tasks_by_class{{class=\"{class}\",phase=\"{phase}\"}} {count}\n"));
        }
    }

    output.push_str("# TYPE positron_maintenance_tasks gauge\n");
    for (phase, count) in [
        ("queued", m.queued()),
        ("running", m.running()),
        ("deferred", m.deferred()),
        ("terminal", m.terminal()),
        ("failed", m.failed()),
    ] {
        output.push_str(&format!(
            "positron_maintenance_tasks{{phase=\"{phase}\"}} {count}\n"
        ));
    }
    for (name, value) in [
        ("clock_uncertain", u64::from(m.clock_uncertain())),
        (
            "maintenance_oldest_queued_age_known",
            u64::from(m.oldest_queued_age_seconds().is_some()),
        ),
        (
            "maintenance_queue_delay_breaches",
            u64::from(m.lower_class_queue_delay_breaches()),
        ),
        (
            "maintenance_progress_slo_breaches",
            u64::from(m.running_no_durable_progress_slo_breaches()),
        ),
        (
            "maintenance_progress_slo_unknown",
            u64::from(m.running_no_durable_progress_slo_unknown()),
        ),
        (
            "maintenance_checkpointed_tasks",
            u64::from(m.checkpointed_tasks()),
        ),
        ("maintenance_paused_tasks", u64::from(m.paused_tasks())),
        (
            "maintenance_conflicted_tasks",
            u64::from(m.conflicted_tasks()),
        ),
        (
            "maintenance_completed_inputs",
            u64::from(m.completed_inputs()),
        ),
        ("maintenance_input_objects", u64::from(m.input_objects())),
        (
            "resource_reservations",
            u64::from(m.outstanding_reservations()),
        ),
        (
            "resource_reservation_limit",
            u64::from(m.maximum_outstanding_reservations()),
        ),
        (
            "resource_maintenance_reservations",
            u64::from(m.outstanding_maintenance_reservations()),
        ),
        (
            "resource_recovery_reserve_memory_bytes",
            m.recovery_reserve_memory_bytes(),
        ),
        (
            "key_custody_verified",
            u64::from(status.doctor.key_custody_verified()),
        ),
        (
            "catalog_verified",
            u64::from(status.doctor.catalog_bootstrap_verified()),
        ),
        ("catalog_generation", status.doctor.catalog_generation()),
        (
            "catalog_manifest_objects",
            u64::from(status.doctor.catalog_manifest_objects()),
        ),
        (
            "catalog_reachable_ledger_scopes",
            u64::from(status.doctor.catalog_reachable_ledger_scopes()),
        ),
        (
            "integrity_quarantine_findings",
            u64::from(status.doctor.catalog_quarantine_findings()),
        ),
        (
            "integrity_scrub_tasks",
            u64::from(status.doctor.integrity_scrub_tasks()),
        ),
        (
            "integrity_scrub_checkpoints",
            u64::from(status.doctor.integrity_scrub_checkpoints()),
        ),
        (
            "durable_operations",
            u64::from(status.doctor.durable_operations()),
        ),
        (
            "active_durable_operations",
            u64::from(status.doctor.active_durable_operations()),
        ),
        (
            "snapshot_leases",
            u64::from(status.doctor.snapshot_leases()),
        ),
    ] {
        gauge(&mut output, name, value);
    }
    if let Some(age) = m.oldest_queued_age_seconds() {
        gauge(&mut output, "maintenance_oldest_queued_age_seconds", age);
    }
    output.push_str("# TYPE positron_resource_reservations_by_class gauge\n");
    for (class, count) in [
        ("durability_recovery", m.durability_recovery_reservations()),
        ("security_lifecycle", m.security_lifecycle_reservations()),
        ("ingest", m.ingest_reservations()),
        (
            "interactive_query_tail",
            m.interactive_query_tail_reservations(),
        ),
        (
            "ordinary_maintenance_backup",
            m.ordinary_maintenance_backup_reservations(),
        ),
    ] {
        output.push_str(&format!(
            "positron_resource_reservations_by_class{{class=\"{class}\"}} {count}\n"
        ));
    }
    if let Some(configuration) = &status.configuration {
        gauge(
            &mut output,
            "configuration_generation",
            configuration.generation(),
        );
        gauge(
            &mut output,
            "configuration_pending_restart",
            u64::from(configuration.pending_restart().is_some()),
        );
    }
    health
        .operational_telemetry()
        .metrics(&mut output, openmetrics);
    output
}

pub(super) fn counter_type(output: &mut String, name: &str, openmetrics: bool) {
    let family = if openmetrics {
        name.strip_suffix("_total").unwrap_or(name)
    } else {
        name
    };
    output.push_str(&format!("# TYPE positron_{family} counter\n"));
}

pub(super) fn gauge(output: &mut String, name: &'static str, value: u64) {
    output.push_str(&format!(
        "# TYPE positron_{name} gauge\npositron_{name} {value}\n"
    ));
}
