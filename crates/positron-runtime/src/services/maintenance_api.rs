use std::fmt::Write;

use sha2::{Digest, Sha256};

use positron_api::maintenance::{
    MaintenanceControlResponse, MaintenanceExplainRequest, MaintenanceExplainResponse,
    MaintenancePauseRequest, MaintenanceResourceReservations, MaintenanceResumeRequest,
    MaintenanceRunRequest, MaintenanceRunResponse, MaintenanceStatusRequest,
    MaintenanceStatusResponse, MaintenanceTaskStatus, MaintenanceWindowRequest,
    MaintenanceWindowResponse,
};
use positron_domain::{
    identity::{PrincipalId, TenantId},
    routing::{SignalKind, VirtualShardId},
};
use positron_governance::{
    AdministrativeIdempotencyKey, AuthorizedContext, CompatibilityHints, GovernanceAuditEntry,
    Identity, PresentedCredential, RequestedIntent, maintenance_control_audit_intent,
    maintenance_window_audit_intent,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, LedgerFailure, LedgerFailureCode, LifecycleClockState,
    MaintenanceCoordinator, MaintenanceFailure, MaintenanceScope, MaintenanceTaskClass,
    MaintenanceTaskId, MaintenanceTaskPhase, ResourceDimension, SegmentScope,
};

use crate::ServiceHandle;

impl ServiceHandle {
    /// Authenticates a system administrator before decoding the bounded
    /// inspection request. The response is derived solely from the runtime's
    /// one coordinator and contains no credentials or immutable input bytes.
    pub(crate) fn maintenance_status(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<MaintenanceStatusResponse, (u16, &'static str)> {
        let _catalog_operation = self
            .catalog_operation()
            .map_err(|_| (503, "administration_unavailable"))?;
        self.authorize_system_administration(bearer)?;
        let request =
            MaintenanceStatusRequest::decode(body).map_err(|_| (400, "invalid_request"))?;
        let cursor = match request.cursor() {
            Some(value) => Some(task_identity(value).ok_or((400, "invalid_request"))?),
            None => None,
        };
        let (clock_uncertain, now) = self.maintenance_inspection_clock()?;
        let statuses = self
            .instance
            .maintenance_coordinator()
            .statuses_with_clock_uncertainty(clock_uncertain)
            .map_err(|_| (503, "administration_unavailable"))?;
        let mut response = MaintenanceStatusResponse {
            tasks: Vec::with_capacity(request.page_limit()),
            returned: 0,
            total: u32::try_from(statuses.len())
                .map_err(|_| (503, "administration_unavailable"))?,
            next_cursor: None,
            queued: 0,
            running: 0,
            deferred: 0,
            terminal: 0,
        };
        for status in &statuses {
            match status.phase() {
                MaintenanceTaskPhase::Queued => response.queued += 1,
                MaintenanceTaskPhase::Running => response.running += 1,
                MaintenanceTaskPhase::Deferred => response.deferred += 1,
                MaintenanceTaskPhase::Cancelled
                | MaintenanceTaskPhase::Succeeded
                | MaintenanceTaskPhase::Failed => response.terminal += 1,
            }
        }
        let page_start = cursor.map_or(0, |cursor| {
            statuses.partition_point(|status| status.task().identity() <= cursor)
        });
        let remaining = statuses.len().saturating_sub(page_start);
        let page_len = remaining.min(request.page_limit());
        let has_more = remaining > page_len;
        let coordinator = self.instance.maintenance_coordinator();
        for status in statuses.into_iter().skip(page_start).take(page_len) {
            response.tasks.push(
                task_status_for_coordinator(coordinator, status, now)
                    .map_err(|_| (503, "administration_unavailable"))?,
            );
        }
        response.returned =
            u32::try_from(response.tasks.len()).map_err(|_| (503, "administration_unavailable"))?;
        if has_more {
            response.next_cursor = response.tasks.last().map(|task| task.identity.clone());
        }
        response
            .validate()
            .map_err(|_| (503, "administration_unavailable"))?;
        Ok(response)
    }

    pub(crate) fn explain_maintenance_task(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<MaintenanceExplainResponse, (u16, &'static str)> {
        let _catalog_operation = self
            .catalog_operation()
            .map_err(|_| (503, "administration_unavailable"))?;
        self.authorize_system_administration(bearer)?;
        let request =
            MaintenanceExplainRequest::decode(body).map_err(|_| (400, "invalid_request"))?;
        let identity = task_identity(&request.identity).ok_or((400, "invalid_request"))?;
        let (clock_uncertain, now) = self.maintenance_inspection_clock()?;
        let status = self
            .instance
            .maintenance_coordinator()
            .status_with_clock_uncertainty(identity, clock_uncertain)
            .map_err(|_| (404, "task_unavailable"))?;
        Ok(MaintenanceExplainResponse {
            task: task_status_for_coordinator(self.instance.maintenance_coordinator(), status, now)
                .map_err(|_| (503, "administration_unavailable"))?,
        })
    }

    /// Submits only the kernel-produced Compaction descriptor for one explicit
    /// sealed signal scope. Callers provide no source objects, retention
    /// bounds, reservations, preconditions, or task descriptor fields.
    pub(crate) fn run_maintenance(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<MaintenanceRunResponse, (u16, &'static str)> {
        let _catalog_operation = self
            .catalog_operation()
            .map_err(|_| (503, "administration_unavailable"))?;
        let actor = self.authorize_system_administration(bearer)?;
        let request = MaintenanceRunRequest::decode(body).map_err(|_| (400, "invalid_request"))?;
        let tenant =
            TenantId::parse_canonical(request.tenant()).map_err(|_| (400, "invalid_request"))?;
        let signal = signal(request.signal()).ok_or((400, "invalid_request"))?;
        let shard = VirtualShardId::new(request.shard()).map_err(|_| (400, "invalid_request"))?;
        let idempotency = PrincipalId::parse_canonical(request.idempotency_key())
            .map_err(|_| (400, "invalid_request"))?;
        let task_identity = maintenance_task_id(actor.principal_id(), idempotency)?;
        let now = self.maintenance_status_now()?;
        let instance = &self.instance;
        let catalog = Catalog::open(
            &instance._authority,
            instance.instance,
            instance
                .key
                .catalog_secret(instance.instance)
                .map_err(|_| (503, "administration_unavailable"))?,
        )
        .map_err(|_| (503, "administration_unavailable"))?;
        let snapshot = catalog
            .pin()
            .map_err(|_| (503, "administration_unavailable"))?;
        let identity =
            Identity::open(&snapshot).map_err(|_| (503, "administration_unavailable"))?;
        let scope = SegmentScope::new(tenant, signal, shard);
        let expected_scope = MaintenanceScope::segment(tenant, signal, shard);
        if !snapshot
            .reachable_ledger_scopes(tenant, signal)
            .map_err(|_| (503, "administration_unavailable"))?
            .into_iter()
            .any(|candidate| candidate == scope)
        {
            return Err((404, "source_unavailable"));
        }
        let coordinator = instance.maintenance_coordinator();
        match coordinator.status(task_identity) {
            Ok(status)
                if status.task().class() == MaintenanceTaskClass::Compaction
                    && status.task().scope() == expected_scope =>
            {
                return Ok(MaintenanceRunResponse {
                    task: task_status_for_coordinator(
                        self.instance.maintenance_coordinator(),
                        status,
                        Some(now),
                    )
                    .map_err(|_| (503, "administration_unavailable"))?,
                });
            },
            Ok(_) => return Err((409, "idempotency_conflict")),
            Err(positron_kernel::MaintenanceFailure::UnknownTask) => {},
            Err(_) => return Err((503, "administration_unavailable")),
        }
        let key = super::tenant_segment_key(instance, &identity, scope)
            .map_err(|_| (503, "administration_unavailable"))?;
        let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
            &instance._authority,
            &instance.retention_time,
            &catalog,
            scope,
            key,
        )
        .map_err(|_| (503, "administration_unavailable"))?;
        let bucket = ledger.sealed_compaction_bucket().map_err(source_failure)?;
        let task = ledger
            .prepare_compaction_task(bucket, task_identity)
            .map_err(|_| (503, "administration_unavailable"))?;
        let submitted = task
            .submit_and_persist(coordinator, &catalog, now)
            .map_err(|_| (503, "administration_unavailable"))?;
        let status = coordinator
            .status(submitted.identity())
            .map_err(|_| (503, "administration_unavailable"))?;
        drop(ledger);
        drop(catalog);
        drop(_catalog_operation);
        self.notify_maintenance_worker();
        Ok(MaintenanceRunResponse {
            task: task_status_for_coordinator(
                self.instance.maintenance_coordinator(),
                status,
                Some(now),
            )
            .map_err(|_| (503, "administration_unavailable"))?,
        })
    }

    pub(crate) fn pause_maintenance(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<MaintenanceControlResponse, (u16, &'static str)> {
        let _catalog_operation = self
            .catalog_operation()
            .map_err(|_| (503, "administration_unavailable"))?;
        let actor = self.authorize_system_administration(bearer)?;
        let request =
            MaintenancePauseRequest::decode(body).map_err(|_| (400, "invalid_request"))?;
        let identity = task_identity(request.identity()).ok_or((400, "invalid_request"))?;
        let idempotency = PrincipalId::parse_canonical(request.idempotency_key())
            .map_err(|_| (400, "invalid_request"))?;
        let catalog = self.open_maintenance_catalog()?;
        let now = self.maintenance_status_now()?;
        if let Some(audit_position) = maintenance_control_replay(
            &catalog,
            actor.principal_id(),
            idempotency,
            identity,
            true,
            request.resource_generation(),
            request.duration_seconds(),
        )? {
            let status = self
                .instance
                .maintenance_coordinator()
                .status(identity)
                .map_err(control_failure)?;
            return Ok(MaintenanceControlResponse {
                task: task_status_for_coordinator(
                    self.instance.maintenance_coordinator(),
                    status,
                    Some(now),
                )
                .map_err(|_| (503, "administration_unavailable"))?,
                audit_position,
            });
        }
        let until = now
            .checked_add(request.duration_seconds())
            .ok_or((400, "invalid_request"))?;
        let audit = maintenance_control_audit_intent(
            actor.principal_id(),
            administrative_key(idempotency)?,
            identity,
            true,
            request.resource_generation(),
            request.duration_seconds(),
            Some(until),
        )
        .map_err(|_| (503, "administration_unavailable"))?;
        let coordinator = self.instance.maintenance_coordinator();
        coordinator
            .pause_and_persist_audited(
                &catalog,
                identity,
                request.resource_generation(),
                until,
                now,
                audit,
            )
            .map_err(control_failure)?;
        let status = coordinator.status(identity).map_err(control_failure)?;
        let audit_position = latest_control_audit_position(&catalog)?;
        drop(catalog);
        drop(_catalog_operation);
        self.notify_maintenance_worker();
        Ok(MaintenanceControlResponse {
            task: task_status_for_coordinator(
                self.instance.maintenance_coordinator(),
                status,
                Some(now),
            )
            .map_err(|_| (503, "administration_unavailable"))?,
            audit_position,
        })
    }

    pub(crate) fn resume_maintenance(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<MaintenanceControlResponse, (u16, &'static str)> {
        let _catalog_operation = self
            .catalog_operation()
            .map_err(|_| (503, "administration_unavailable"))?;
        let actor = self.authorize_system_administration(bearer)?;
        let request =
            MaintenanceResumeRequest::decode(body).map_err(|_| (400, "invalid_request"))?;
        let identity = task_identity(request.identity()).ok_or((400, "invalid_request"))?;
        let idempotency = PrincipalId::parse_canonical(request.idempotency_key())
            .map_err(|_| (400, "invalid_request"))?;
        let catalog = self.open_maintenance_catalog()?;
        let now = self.maintenance_status_now()?;
        if let Some(audit_position) = maintenance_control_replay(
            &catalog,
            actor.principal_id(),
            idempotency,
            identity,
            false,
            0,
            0,
        )? {
            let status = self
                .instance
                .maintenance_coordinator()
                .status(identity)
                .map_err(control_failure)?;
            return Ok(MaintenanceControlResponse {
                task: task_status_for_coordinator(
                    self.instance.maintenance_coordinator(),
                    status,
                    Some(now),
                )
                .map_err(|_| (503, "administration_unavailable"))?,
                audit_position,
            });
        }
        let audit = maintenance_control_audit_intent(
            actor.principal_id(),
            administrative_key(idempotency)?,
            identity,
            false,
            0,
            0,
            None,
        )
        .map_err(|_| (503, "administration_unavailable"))?;
        let coordinator = self.instance.maintenance_coordinator();
        coordinator
            .resume_and_persist_audited(&catalog, identity, audit)
            .map_err(control_failure)?;
        let status = coordinator.status(identity).map_err(control_failure)?;
        let audit_position = latest_control_audit_position(&catalog)?;
        drop(catalog);
        drop(_catalog_operation);
        self.notify_maintenance_worker();
        Ok(MaintenanceControlResponse {
            task: task_status_for_coordinator(
                self.instance.maintenance_coordinator(),
                status,
                Some(now),
            )
            .map_err(|_| (503, "administration_unavailable"))?,
            audit_position,
        })
    }

    /// Authenticates before decoding a bounded whole-coordinator Maintenance
    /// Window. The durable Catalog generation precondition prevents a stale
    /// operator request from replacing a later window.
    pub(crate) fn set_maintenance_window(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<MaintenanceWindowResponse, (u16, &'static str)> {
        let _catalog_operation = self
            .catalog_operation()
            .map_err(|_| (503, "administration_unavailable"))?;
        let actor = self.authorize_system_administration(bearer)?;
        let request =
            MaintenanceWindowRequest::decode(body).map_err(|_| (400, "invalid_request"))?;
        let mut deferred = request
            .deferred_classes()
            .iter()
            .map(|class| window_class(class).ok_or((400, "invalid_request")))
            .collect::<Result<Vec<_>, _>>()?;
        deferred.sort_unstable();
        let deferred_classes = window_class_names(&deferred);
        let idempotency = PrincipalId::parse_canonical(request.idempotency_key())
            .map_err(|_| (400, "invalid_request"))?;
        let catalog = self.open_maintenance_catalog()?;
        if let Some(response) = maintenance_window_replay(
            &catalog,
            actor.principal_id(),
            idempotency,
            request.expected_catalog_generation(),
            &deferred,
            request.duration_seconds(),
        )? {
            return Ok(response);
        }
        let now = self.maintenance_status_now()?;
        let until = now
            .checked_add(request.duration_seconds())
            .ok_or((400, "invalid_request"))?;
        let audit = maintenance_window_audit_intent(
            actor.principal_id(),
            administrative_key(idempotency)?,
            request.expected_catalog_generation(),
            &deferred,
            request.duration_seconds(),
            until,
        )
        .map_err(|_| (503, "administration_unavailable"))?;
        let catalog_generation = self
            .instance
            .maintenance_coordinator()
            .set_window_and_persist_audited(
                &catalog,
                deferred,
                request.expected_catalog_generation(),
                until,
                now,
                audit,
            )
            .map_err(control_failure)?;
        let audit_position = latest_control_audit_position(&catalog)?;
        drop(catalog);
        drop(_catalog_operation);
        self.notify_maintenance_worker();
        Ok(MaintenanceWindowResponse {
            deferred_classes,
            until_unix_seconds: until,
            catalog_generation,
            audit_position,
        })
    }

    fn open_maintenance_catalog(&self) -> Result<Catalog<'_>, (u16, &'static str)> {
        let instance = &self.instance;
        Catalog::open(
            &instance._authority,
            instance.instance,
            instance
                .key
                .catalog_secret(instance.instance)
                .map_err(|_| (503, "administration_unavailable"))?,
        )
        .map_err(|_| (503, "administration_unavailable"))
    }

    fn maintenance_status_now(&self) -> Result<u64, (u16, &'static str)> {
        self.instance
            .retention_time
            .governance_now_seconds()
            .map_err(|_| (503, "administration_unavailable"))
    }

    /// Inspection exposes exact scheduler blockers even while lifecycle time
    /// cannot safely derive an age or deadline.
    fn maintenance_inspection_clock(&self) -> Result<(bool, Option<u64>), (u16, &'static str)> {
        if self.instance.retention_time.status().state() == LifecycleClockState::ClockUncertain {
            return Ok((true, None));
        }
        self.maintenance_status_now().map(|now| (false, Some(now)))
    }

    fn authorize_system_administration(
        &self,
        bearer: &str,
    ) -> Result<AuthorizedContext, (u16, &'static str)> {
        self.instance
            .attribute(
                PresentedCredential::parse(bearer).map_err(|_| (401, "authentication_rejected"))?,
                RequestedIntent::SystemAdministration,
                CompatibilityHints::none(),
            )
            .map_err(|_| (401, "authentication_rejected"))
    }
}

fn signal(value: &str) -> Option<SignalKind> {
    match value {
        "logs" => Some(SignalKind::Logs),
        "traces" => Some(SignalKind::Traces),
        _ => None,
    }
}

fn source_failure(failure: LedgerFailure) -> (u16, &'static str) {
    match failure.code() {
        LedgerFailureCode::InvalidInput | LedgerFailureCode::PhysicalScopeMismatch => {
            (404, "source_unavailable")
        },
        _ => (503, "administration_unavailable"),
    }
}

fn maintenance_task_id(
    principal: PrincipalId,
    idempotency: PrincipalId,
) -> Result<MaintenanceTaskId, (u16, &'static str)> {
    let mut digest = Sha256::new();
    digest.update(b"positron-maintenance-run-v1");
    digest.update(principal.to_bytes());
    digest.update(idempotency.to_bytes());
    let digest: [u8; 32] = digest.finalize().into();
    let mut identity = [0_u8; 16];
    identity.copy_from_slice(
        digest
            .get(..16)
            .ok_or((503, "administration_unavailable"))?,
    );
    MaintenanceTaskId::new(identity).map_err(|_| (503, "administration_unavailable"))
}

fn administrative_key(
    idempotency: PrincipalId,
) -> Result<AdministrativeIdempotencyKey, (u16, &'static str)> {
    AdministrativeIdempotencyKey::new(idempotency.to_bytes()).map_err(|_| (400, "invalid_request"))
}

fn maintenance_control_replay(
    catalog: &Catalog<'_>,
    actor: PrincipalId,
    idempotency: PrincipalId,
    identity: MaintenanceTaskId,
    pause: bool,
    resource_generation: u64,
    duration_seconds: u64,
) -> Result<Option<u64>, (u16, &'static str)> {
    let records = catalog
        .governance_audit_records()
        .map_err(|_| (503, "administration_unavailable"))?;
    for record in records {
        let entry = GovernanceAuditEntry::decode(&record)
            .map_err(|_| (503, "administration_unavailable"))?;
        let GovernanceAuditEntry::MaintenanceControl(candidate) = entry else {
            continue;
        };
        if candidate.idempotency_key().to_bytes() != idempotency.to_bytes()
            || candidate.actor() != actor
        {
            continue;
        }
        if candidate.task() != identity
            || candidate.is_pause() != pause
            || candidate.resource_generation() != resource_generation
            || candidate.duration_seconds() != duration_seconds
        {
            return Err((409, "idempotency_conflict"));
        }
        return Ok(Some(candidate.position()));
    }
    Ok(None)
}

fn maintenance_window_replay(
    catalog: &Catalog<'_>,
    actor: PrincipalId,
    idempotency: PrincipalId,
    expected_catalog_generation: u64,
    deferred: &[MaintenanceTaskClass],
    duration_seconds: u64,
) -> Result<Option<MaintenanceWindowResponse>, (u16, &'static str)> {
    let records = catalog
        .governance_audit_records()
        .map_err(|_| (503, "administration_unavailable"))?;
    for record in records {
        let entry = GovernanceAuditEntry::decode(&record)
            .map_err(|_| (503, "administration_unavailable"))?;
        let GovernanceAuditEntry::MaintenanceWindow(candidate) = entry else {
            continue;
        };
        if candidate.idempotency_key().to_bytes() != idempotency.to_bytes()
            || candidate.actor() != actor
        {
            continue;
        }
        if candidate.expected_catalog_generation() != expected_catalog_generation
            || candidate.deferred() != deferred
            || candidate.duration_seconds() != duration_seconds
        {
            return Err((409, "idempotency_conflict"));
        }
        return Ok(Some(MaintenanceWindowResponse {
            deferred_classes: window_class_names(deferred),
            until_unix_seconds: candidate.until_unix_seconds(),
            catalog_generation: expected_catalog_generation
                .checked_add(1)
                .ok_or((503, "administration_unavailable"))?,
            audit_position: candidate.position(),
        }));
    }
    Ok(None)
}

fn window_class(value: &str) -> Option<MaintenanceTaskClass> {
    match value {
        "compaction" => Some(MaintenanceTaskClass::Compaction),
        "schema_promotion" => Some(MaintenanceTaskClass::SchemaPromotion),
        "schema_demotion" => Some(MaintenanceTaskClass::SchemaDemotion),
        "repository_verification" => Some(MaintenanceTaskClass::RepositoryVerification),
        "backup_snapshot" => Some(MaintenanceTaskClass::BackupSnapshot),
        "durable_export" => Some(MaintenanceTaskClass::DurableExport),
        _ => None,
    }
}

const fn window_class_name(class: &MaintenanceTaskClass) -> &'static str {
    match class {
        MaintenanceTaskClass::Compaction => "compaction",
        MaintenanceTaskClass::SchemaPromotion => "schema_promotion",
        MaintenanceTaskClass::SchemaDemotion => "schema_demotion",
        MaintenanceTaskClass::RepositoryVerification => "repository_verification",
        MaintenanceTaskClass::BackupSnapshot => "backup_snapshot",
        MaintenanceTaskClass::DurableExport => "durable_export",
        _ => "",
    }
}

fn window_class_names(deferred: &[MaintenanceTaskClass]) -> Vec<String> {
    let mut names = deferred
        .iter()
        .map(window_class_name)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    names.sort_unstable();
    names
}

fn latest_control_audit_position(catalog: &Catalog<'_>) -> Result<u64, (u16, &'static str)> {
    catalog
        .governance_audit_records()
        .map_err(|_| (503, "administration_unavailable"))?
        .last()
        .map(positron_kernel::GovernanceAuditRecord::position)
        .ok_or((503, "administration_unavailable"))
}

fn control_failure(failure: MaintenanceFailure) -> (u16, &'static str) {
    match failure {
        MaintenanceFailure::UnknownTask => (404, "task_unavailable"),
        MaintenanceFailure::PreconditionFailed
        | MaintenanceFailure::InvalidTransition
        | MaintenanceFailure::InvalidInput => (409, "precondition_failed"),
        _ => (503, "administration_unavailable"),
    }
}

fn task_status_for_coordinator(
    coordinator: &MaintenanceCoordinator,
    status: positron_kernel::MaintenanceTaskStatus,
    now: Option<u64>,
) -> Result<MaintenanceTaskStatus, MaintenanceFailure> {
    let window_until = now
        .map(|current| coordinator.window_blocking_until(status.task().identity(), current))
        .transpose()?
        .flatten();
    Ok(task_status(status, now, window_until))
}

fn task_status(
    status: positron_kernel::MaintenanceTaskStatus,
    now: Option<u64>,
    window_until: Option<u64>,
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
    MaintenanceTaskStatus {
        identity: hex(task.identity().to_bytes()),
        class: class_name(task.class()).to_owned(),
        scope: scope_name(task.scope()),
        phase: phase_name(phase).to_owned(),
        submitted_at_unix_seconds: status.submitted_at(),
        checkpoint_sequence: status.checkpoint().map(|checkpoint| checkpoint.sequence()),
        pause_until_unix_seconds: status.pause_until(),
        cancellation_requested: status.cancellation_requested(),
        resource_generation: Some(task.preconditions().resource_generation()),
        reservations: Some(reservation_view.clone()),
        expected_foreground_impact: Some(reservation_view),
        blocked_precondition,
        maintenance_window_until_unix_seconds: window_until,
        safe_actions: if paused {
            vec!["resume".to_owned()]
        } else if phase == MaintenanceTaskPhase::Queued && task.class().is_deferrable() {
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
        positron_kernel::MaintenanceTerminalFailure::Unclassified => "unclassified".to_owned(),
    }
}

fn task_identity(value: &str) -> Option<positron_kernel::MaintenanceTaskId> {
    let mut bytes = [0_u8; 16];
    for (slot, pair) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let high = hex_value(*pair.first()?)?;
        let low = hex_value(*pair.get(1)?)?;
        *slot = (high << 4) | low;
    }
    positron_kernel::MaintenanceTaskId::new(bytes).ok()
}

const fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn hex(bytes: [u8; 16]) -> String {
    let mut rendered = String::with_capacity(32);
    for byte in bytes {
        let _ = write!(rendered, "{byte:02x}");
    }
    rendered
}

fn scope_name(scope: MaintenanceScope) -> String {
    match scope {
        MaintenanceScope::System => "system".to_owned(),
        MaintenanceScope::Tenant(tenant) => format!("tenant:{}", tenant.to_canonical_text()),
        MaintenanceScope::Segment {
            tenant,
            signal,
            shard,
        } => format!(
            "segment:{}:{}:{}",
            tenant.to_canonical_text(),
            signal.as_str(),
            shard.value()
        ),
    }
}

const fn phase_name(phase: MaintenanceTaskPhase) -> &'static str {
    match phase {
        MaintenanceTaskPhase::Queued => "queued",
        MaintenanceTaskPhase::Running => "running",
        MaintenanceTaskPhase::Deferred => "deferred",
        MaintenanceTaskPhase::Cancelled => "cancelled",
        MaintenanceTaskPhase::Succeeded => "succeeded",
        MaintenanceTaskPhase::Failed => "failed",
    }
}

const fn class_name(class: MaintenanceTaskClass) -> &'static str {
    match class {
        MaintenanceTaskClass::ActiveSegmentRoll => "active_segment_roll",
        MaintenanceTaskClass::Compaction => "compaction",
        MaintenanceTaskClass::RetentionPublication => "retention_publication",
        MaintenanceTaskClass::RetentionReclamation => "retention_reclamation",
        MaintenanceTaskClass::CatalogReclamation => "catalog_reclamation",
        MaintenanceTaskClass::OrphanReclamation => "orphan_reclamation",
        MaintenanceTaskClass::IntegrityScrub => "integrity_scrub",
        MaintenanceTaskClass::QuarantineFollowUp => "quarantine_follow_up",
        MaintenanceTaskClass::SchemaStatistics => "schema_statistics",
        MaintenanceTaskClass::SchemaPromotion => "schema_promotion",
        MaintenanceTaskClass::SchemaDemotion => "schema_demotion",
        MaintenanceTaskClass::GovernanceAuditCheckpoint => "governance_audit_checkpoint",
        MaintenanceTaskClass::KeyRewrap => "key_rewrap",
        MaintenanceTaskClass::EnvelopeVerification => "envelope_verification",
        MaintenanceTaskClass::Migration => "migration",
        MaintenanceTaskClass::RepositoryVerification => "repository_verification",
        MaintenanceTaskClass::RepositoryCleanup => "repository_cleanup",
        MaintenanceTaskClass::BackupSnapshot => "backup_snapshot",
        MaintenanceTaskClass::DurableExport => "durable_export",
        MaintenanceTaskClass::SnapshotLeaseExpiry => "snapshot_lease_expiry",
        MaintenanceTaskClass::CompletedOperationExpiry => "completed_operation_expiry",
        MaintenanceTaskClass::TenantPurge => "tenant_purge",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier, Mutex, mpsc};
    use std::time::Duration;

    use positron_api::maintenance::{
        MaintenanceExplainRequest, MaintenancePauseRequest, MaintenanceResumeRequest,
        MaintenanceRunRequest, MaintenanceStatusRequest, MaintenanceWindowRequest,
    };
    use positron_domain::{routing::SignalKind, time::UnixNanoseconds};
    use positron_kernel::{
        ActiveSegmentLedger, LifecycleClockFailure, LifecycleClockPolicy, LifecycleClockSource,
        MaintenancePreconditions, MaintenanceScope, MaintenanceTask, MaintenanceTaskClass,
        MaintenanceTaskId, MaintenanceTaskPhase, MaintenanceTrigger, ResourceAmounts,
        RetentionTimeAuthority, SegmentScope,
    };
    use prost::Message;

    use super::super::ServiceHandle;
    use super::super::tests::schema_maintenance::{Fixture, open_catalog, request};

    struct MutableWallClock(Arc<Mutex<UnixNanoseconds>>);

    impl LifecycleClockSource for MutableWallClock {
        fn read(&self) -> Result<UnixNanoseconds, LifecycleClockFailure> {
            self.0
                .lock()
                .map(|value| *value)
                .map_err(|_| LifecycleClockFailure::Unavailable)
        }
    }

    #[test]
    fn authenticated_maintenance_status_waits_for_catalog_ownership_before_attribution()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
        let services = Arc::new(ServiceHandle::new(initialized)?);
        let catalog_operation = services.catalog_operation()?;
        let barrier = Arc::new(Barrier::new(2));
        let (sender, receiver) = mpsc::sync_channel(1);
        let request_services = Arc::clone(&services);
        let request_barrier = Arc::clone(&barrier);
        let request = std::thread::spawn(move || {
            request_barrier.wait();
            let result = request_services
                .maintenance_status(&administrator, br"{}")
                .map(|_| ());
            let _ = sender.send(result);
        });
        barrier.wait();
        assert!(
            receiver.recv_timeout(Duration::from_millis(100)).is_err(),
            "maintenance attribution bypassed the catalog-operation gate"
        );
        drop(catalog_operation);
        assert_eq!(
            receiver
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| "maintenance request did not resume")?,
            Ok(())
        );
        request
            .join()
            .map_err(|_| "maintenance request thread panicked")?;
        Ok(())
    }

    #[test]
    fn authenticated_status_and_explain_report_a_durable_terminal_failure_class()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
        let mut initialized = Arc::try_unwrap(initialized)
            .map_err(|_| "maintenance fixture retains the initialized instance")?;
        let task = initialized.queue_governance_audit_checkpoint_for_test()?;
        initialized.rotate_governance_audit_fingerprint_for_test([0xa5; 32])?;
        let failure = initialized
            .complete_queued_governance_audit_checkpoint_for_test(task)
            .expect_err("retired identity binding must terminalize");
        assert_eq!(
            failure.code(),
            crate::BootstrapFailureCode::IdentityMismatch
        );
        let initialized = Arc::new(initialized);
        let services = ServiceHandle::new(initialized)?;
        let identity = super::hex(task.to_bytes());
        let status = services
            .maintenance_status(&administrator, br"{}")
            .map_err(|failure| format!("status: {failure:?}"))?;
        let observed = status
            .tasks
            .into_iter()
            .find(|candidate| candidate.identity == identity)
            .ok_or("failed task missing from status")?;
        assert_eq!(observed.phase, "failed");
        assert_eq!(
            observed.terminal_failure_class.as_deref(),
            Some("identity_mismatch")
        );
        let explained = services
            .explain_maintenance_task(
                &administrator,
                &serde_json::to_vec(&MaintenanceExplainRequest { identity })?,
            )
            .map_err(|failure| format!("explain: {failure:?}"))?;
        assert_eq!(
            explained.task.terminal_failure_class.as_deref(),
            Some("identity_mismatch")
        );
        Ok(())
    }

    #[test]
    fn authenticated_status_and_explain_report_clock_uncertain_destructive_blocking()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
        let mut initialized = Arc::try_unwrap(initialized)
            .map_err(|_| "maintenance fixture retains the initialized instance")?;
        let wall = Arc::new(Mutex::new(UnixNanoseconds::new(1_000)));
        initialized.install_retention_time_for_test(
            RetentionTimeAuthority::establish_with_source(
                MutableWallClock(Arc::clone(&wall)),
                LifecycleClockPolicy::new(10)?,
            )?,
        )?;
        *wall.lock().map_err(|_| "maintenance test wall clock")? = UnixNanoseconds::new(500);
        let scope = SegmentScope::new(
            initialized.default_tenant_id(),
            SignalKind::Logs,
            positron_domain::routing::VirtualShardId::new(1)?,
        );
        initialized.retention_time.governance_time_seconds(scope)?;
        let task = MaintenanceTask::with_contract(
            MaintenanceTaskId::new([0x44; 16])
                .map_err(|failure| format!("maintenance identity: {failure:?}"))?,
            MaintenanceTaskClass::RepositoryCleanup,
            MaintenanceScope::System,
            MaintenanceTrigger::Scheduled,
            MaintenancePreconditions::new(1, 1)
                .map_err(|failure| format!("maintenance preconditions: {failure:?}"))?,
            Vec::new(),
            Vec::new(),
            ResourceAmounts::new([64, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0]),
        )
        .map_err(|failure| format!("scheduled destructive task: {failure:?}"))?;
        let initialized = Arc::new(initialized);
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        initialized
            .maintenance_coordinator()
            .submit_at(task, 1)
            .map_err(|failure| format!("queue destructive task: {failure:?}"))?;

        let status = services
            .maintenance_status(&administrator, br"{}")
            .map_err(|failure| format!("uncertain maintenance status: {failure:?}"))?;
        let observed = status.tasks.first().ok_or("uncertain task status")?;
        assert_eq!(
            observed.blocked_precondition.as_deref(),
            Some("clock_uncertain_destructive_schedule")
        );
        assert_eq!(
            observed.backlog_age_seconds, None,
            "inspection must not invent an age from an uncertain lifecycle clock"
        );
        let explain = services
            .explain_maintenance_task(
                &administrator,
                &serde_json::to_vec(&MaintenanceExplainRequest {
                    identity: observed.identity.clone(),
                })?,
            )
            .map_err(|failure| format!("uncertain maintenance explain: {failure:?}"))?;
        assert_eq!(
            explain.task.blocked_precondition.as_deref(),
            Some("clock_uncertain_destructive_schedule")
        );
        assert_eq!(explain.task.backlog_age_seconds, None);
        Ok(())
    }

    #[test]
    fn authenticated_status_and_explain_report_an_active_maintenance_window()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        let task = MaintenanceTask::new(
            MaintenanceTaskId::new([0x51; 16])
                .map_err(|failure| format!("window identity: {failure:?}"))?,
            MaintenanceTaskClass::Compaction,
        );
        let identity = super::hex(task.identity().to_bytes());
        let now = services
            .maintenance_status_now()
            .map_err(|failure| format!("window clock: {failure:?}"))?;
        initialized
            .maintenance_coordinator()
            .submit_at(task, now)
            .map_err(|failure| format!("queue window task: {failure:?}"))?;
        let expected_catalog_generation = open_catalog(&initialized)?.pin()?.number();
        let window = services
            .set_maintenance_window(
                &administrator,
                &MaintenanceWindowRequest::new(
                    vec!["compaction".to_owned()],
                    expected_catalog_generation,
                    60,
                    "00000000-0000-0000-0000-000000000031".to_owned(),
                )
                .encode()?,
            )
            .map_err(|failure| format!("set window: {failure:?}"))?;
        assert!(window.until_unix_seconds >= now);

        let status = services
            .maintenance_status(&administrator, br"{}")
            .map_err(|failure| format!("window status: {failure:?}"))?;
        let observed = status
            .tasks
            .into_iter()
            .find(|candidate| candidate.identity == identity)
            .ok_or("window task missing from status")?;
        assert_eq!(
            observed.blocked_precondition.as_deref(),
            Some("maintenance_window_active")
        );
        assert_eq!(
            observed.maintenance_window_until_unix_seconds,
            Some(window.until_unix_seconds)
        );

        let explain = services
            .explain_maintenance_task(
                &administrator,
                &serde_json::to_vec(&MaintenanceExplainRequest { identity })?,
            )
            .map_err(|failure| format!("window explain: {failure:?}"))?;
        assert_eq!(
            explain.task.blocked_precondition.as_deref(),
            Some("maintenance_window_active")
        );
        assert_eq!(
            explain.task.maintenance_window_until_unix_seconds,
            Some(window.until_unix_seconds)
        );
        Ok(())
    }

    #[test]
    fn authenticated_maintenance_status_pages_the_full_registry_without_hiding_queued_work()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        for value in 1_u8..=33 {
            initialized
                .maintenance_coordinator()
                .submit_at(
                    MaintenanceTask::new(
                        MaintenanceTaskId::new([value; 16])
                            .map_err(|failure| format!("task identity: {failure:?}"))?,
                        MaintenanceTaskClass::SchemaStatistics,
                    ),
                    u64::from(value),
                )
                .map_err(|failure| format!("queued task: {failure:?}"))?;
        }

        let first = services
            .maintenance_status(&administrator, br"{}")
            .map_err(|failure| format!("first page: {failure:?}"))?;
        assert_eq!(first.total, 33);
        assert_eq!(first.queued, 33);
        assert_eq!(first.returned, 32);
        let cursor = first.next_cursor.clone().ok_or("first page continuation")?;
        assert_eq!(first.tasks.len(), 32);
        let second_body = serde_json::to_vec(&MaintenanceStatusRequest::page_after(cursor, 32))?;
        let second = services
            .maintenance_status(&administrator, &second_body)
            .map_err(|failure| format!("second page: {failure:?}"))?;
        assert_eq!(second.total, 33);
        assert_eq!(second.queued, 33);
        assert_eq!(second.returned, 1);
        assert_eq!(second.next_cursor, None);
        assert_eq!(second.tasks.len(), 1);
        let second_task = second.tasks.first().ok_or("second page task")?;
        assert!(
            first
                .tasks
                .iter()
                .all(|first_task| first_task.identity != second_task.identity),
            "the continuation must expose the queued task omitted from the first bounded page"
        );
        Ok(())
    }

    #[test]
    fn authenticated_run_prepares_one_sealed_compaction_task_and_replays_after_reopen()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        services.ingest_otlp_logs(&ingest, request("run-api-sealed-source").encode_to_vec())?;
        let catalog = open_catalog(&initialized)?;
        let scope = catalog
            .pin()?
            .reachable_ledger_scopes(initialized.default_tenant_id(), SignalKind::Logs)?
            .into_iter()
            .next()
            .ok_or("log scope")?;
        ActiveSegmentLedger::open_for_maintenance_with_retention_time(
            &initialized._authority,
            &initialized.retention_time,
            &catalog,
            scope,
            initialized.tenant_segment_key_for_test(scope)?,
        )?
        .seal()?;
        drop(catalog);
        let request = MaintenanceRunRequest::new(
            "compaction".to_owned(),
            initialized.default_tenant_id().to_canonical_text(),
            "logs".to_owned(),
            scope.shard_id().value(),
            "00000000-0000-0000-0000-000000000001".to_owned(),
        );
        let body = request.encode()?;
        let first = services
            .run_maintenance(&administrator, &body)
            .map_err(|failure| format!("first run: {failure:?}"))?;
        assert_eq!(first.task.class, "compaction");
        assert_eq!(first.task.phase, "queued");
        let replay = services
            .run_maintenance(&administrator, &body)
            .map_err(|failure| format!("replayed run: {failure:?}"))?;
        assert_eq!(replay, first, "retry attaches to the durable task");
        let identity = super::task_identity(&first.task.identity).ok_or("task identity")?;
        drop(services);
        drop(initialized);

        let reopened = fixture.reopen()?;
        let _restored_services = ServiceHandle::new(Arc::clone(&reopened))?;
        assert_eq!(
            reopened
                .maintenance_coordinator()
                .status(identity)
                .map_err(|failure| format!("restored task: {failure:?}"))?
                .phase(),
            MaintenanceTaskPhase::Queued,
            "the acknowledged run remains durably queued after reopen"
        );
        Ok(())
    }

    #[test]
    fn maintenance_run_rejects_unauthenticated_requests_before_decoding()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let (initialized, _, _, _) = fixture.initialized_with_admin()?;
        let services = ServiceHandle::new(initialized)?;
        assert_eq!(
            services.run_maintenance("not-a-credential", br#"{\"unknown\":true}"#),
            Err((401, "authentication_rejected")),
            "authentication precedes decoding"
        );
        Ok(())
    }

    #[test]
    fn maintenance_window_authenticates_before_decode_and_replays_its_atomic_publication()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        assert_eq!(
            services.set_maintenance_window("not-a-credential", br#"{\"unexpected\":true}"#),
            Err((401, "authentication_rejected")),
            "authentication must precede untrusted window decoding"
        );
        let expected = open_catalog(&initialized)?.pin()?.number();
        let request = MaintenanceWindowRequest::new(
            vec!["backup_snapshot".to_owned(), "compaction".to_owned()],
            expected,
            60,
            "00000000-0000-0000-0000-000000000021".to_owned(),
        );
        let first = services
            .set_maintenance_window(&administrator, &request.encode()?)
            .map_err(|failure| format!("window publication: {failure:?}"))?;
        assert_eq!(first.catalog_generation, expected + 1);
        assert!(first.until_unix_seconds >= 60);
        assert_ne!(first.audit_position, 0);
        assert_eq!(
            services
                .set_maintenance_window(&administrator, &request.encode()?)
                .map_err(|failure| format!("window replay: {failure:?}"))?,
            first,
            "exact retries return the same acknowledged publication"
        );
        let conflict = MaintenanceWindowRequest::new(
            vec!["compaction".to_owned()],
            expected,
            60,
            "00000000-0000-0000-0000-000000000021".to_owned(),
        );
        assert_eq!(
            services.set_maintenance_window(&administrator, &conflict.encode()?),
            Err((409, "idempotency_conflict"))
        );
        let stale = MaintenanceWindowRequest::new(
            vec!["compaction".to_owned()],
            expected,
            60,
            "00000000-0000-0000-0000-000000000022".to_owned(),
        );
        assert_eq!(
            services.set_maintenance_window(&administrator, &stale.encode()?),
            Err((409, "precondition_failed")),
            "the actual committed Catalog generation fences the global window"
        );
        Ok(())
    }

    #[test]
    fn authenticated_pause_and_resume_replay_durably_after_reopen()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        services.ingest_otlp_logs(&ingest, request("pause-api-sealed-source").encode_to_vec())?;
        let catalog = open_catalog(&initialized)?;
        let scope = catalog
            .pin()?
            .reachable_ledger_scopes(initialized.default_tenant_id(), SignalKind::Logs)?
            .into_iter()
            .next()
            .ok_or("log scope")?;
        ActiveSegmentLedger::open_for_maintenance_with_retention_time(
            &initialized._authority,
            &initialized.retention_time,
            &catalog,
            scope,
            initialized.tenant_segment_key_for_test(scope)?,
        )?
        .seal()?;
        drop(catalog);
        let run = MaintenanceRunRequest::new(
            "compaction".to_owned(),
            initialized.default_tenant_id().to_canonical_text(),
            "logs".to_owned(),
            scope.shard_id().value(),
            "00000000-0000-0000-0000-000000000011".to_owned(),
        );
        let task = services
            .run_maintenance(&administrator, &run.encode()?)
            .map_err(|failure| format!("run task: {failure:?}"))?
            .task;
        let pause = MaintenancePauseRequest::new(
            task.identity.clone(),
            1,
            60,
            "00000000-0000-0000-0000-000000000012".to_owned(),
        );
        let paused = services
            .pause_maintenance(&administrator, &pause.encode()?)
            .map_err(|failure| format!("pause task: {failure:?}"))?;
        assert_eq!(paused.task.phase, "deferred");
        assert!(paused.task.pause_until_unix_seconds.is_some());
        assert_ne!(paused.audit_position, 0);
        let status = services
            .maintenance_status(&administrator, br"{}")
            .map_err(|failure| format!("paused status: {failure:?}"))?;
        assert_eq!(status.returned, 1);
        assert_eq!(status.total, 1);
        assert_eq!(status.next_cursor, None);
        assert_eq!(status.queued, 0);
        assert_eq!(status.running, 0);
        assert_eq!(status.deferred, 1);
        assert_eq!(status.terminal, 0);
        let observed = status
            .tasks
            .iter()
            .find(|candidate| candidate.identity == task.identity)
            .ok_or("paused task status")?;
        assert_eq!(
            observed.blocked_precondition.as_deref(),
            Some("maintenance_pause_active"),
            "status reports the durable scheduling precondition"
        );
        assert_eq!(observed.resource_generation, Some(1));
        assert_eq!(
            observed
                .reservations
                .as_ref()
                .ok_or("task reservation profile")?
                .task_slots,
            1
        );
        assert_eq!(
            observed
                .expected_foreground_impact
                .as_ref()
                .ok_or("foreground impact")?
                .task_slots,
            1,
            "the declared task reservation is the exact foreground-impact estimate"
        );
        assert_eq!(observed.safe_actions, ["resume"]);
        assert!(observed.backlog_age_seconds.is_some());
        assert_eq!(observed.conflict_owner, None);
        assert_eq!(observed.checkpoint_completed_inputs, Some(0));
        assert_eq!(observed.input_object_count, 1);
        assert_eq!(observed.output_object_count, 0);
        assert_eq!(observed.estimated_output_object_amplification_milli, None);
        assert_eq!(observed.terminal_outcome, None);
        assert_eq!(
            services
                .pause_maintenance(&administrator, &pause.encode()?)
                .map_err(|failure| format!("replay pause: {failure:?}"))?,
            paused,
            "an exact operator retry replays its acknowledged durable pause"
        );
        let conflicting_pause = MaintenancePauseRequest::new(
            task.identity.clone(),
            1,
            61,
            "00000000-0000-0000-0000-000000000012".to_owned(),
        );
        assert_eq!(
            services.pause_maintenance(&administrator, &conflicting_pause.encode()?),
            Err((409, "idempotency_conflict"))
        );
        let identity = super::task_identity(&task.identity).ok_or("task identity")?;
        drop(services);
        drop(initialized);

        let reopened = fixture.reopen()?;
        let services = ServiceHandle::new(Arc::clone(&reopened))?;
        let reopened_phase = {
            let coordinator_handle = reopened.maintenance_coordinator();
            let coordinator = coordinator_handle;
            coordinator
                .status(identity)
                .map_err(|failure| format!("reopened task: {failure:?}"))?
                .phase()
        };
        assert_eq!(reopened_phase, MaintenanceTaskPhase::Deferred);
        let resume = MaintenanceResumeRequest::new(
            task.identity,
            "00000000-0000-0000-0000-000000000013".to_owned(),
        );
        let resumed = services
            .resume_maintenance(&administrator, &resume.encode()?)
            .map_err(|failure| format!("resume task: {failure:?}"))?;
        assert_eq!(resumed.task.phase, "queued");
        assert_eq!(resumed.task.pause_until_unix_seconds, None);
        assert_eq!(
            services
                .resume_maintenance(&administrator, &resume.encode()?)
                .map_err(|failure| format!("replay resume: {failure:?}"))?,
            resumed,
            "an exact operator retry replays its acknowledged durable resume"
        );
        Ok(())
    }
}
