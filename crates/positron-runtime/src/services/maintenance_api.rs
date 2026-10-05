use sha2::{Digest, Sha256};

use positron_api::maintenance::{
    AuthenticatedTimeRangeDescriptor, IntegrityQuarantineDescriptor, MaintenanceControlResponse,
    MaintenanceExplainRequest, MaintenanceExplainResponse, MaintenancePauseRequest,
    MaintenanceResourceReservations, MaintenanceResumeRequest, MaintenanceRunRequest,
    MaintenanceRunResponse, MaintenanceStatusRequest, MaintenanceStatusResponse,
    MaintenanceTaskAcknowledgement, MaintenanceTaskStatus, MaintenanceWindowRequest,
    MaintenanceWindowResponse,
};
use positron_domain::{
    identity::{PrincipalId, TenantId},
    routing::{SignalKind, VirtualShardId},
};
use positron_governance::{
    AdministrativeIdempotencyKey, AuthorizedContext, CompatibilityHints, GovernanceAuditEntry,
    Identity, MaintenanceControlAuditEntry, MaintenanceRunAuditEntry, MaintenanceRunAuditRequest,
    PresentedCredential, RequestedIntent, maintenance_control_audit_intent,
    maintenance_run_audit_intent, maintenance_window_audit_intent,
};
use positron_kernel::{
    ActiveSegmentLedger, AuthenticatedEventRange, AuthenticatedIngestRange, Catalog, LedgerFailure,
    LedgerFailureCode, LifecycleClockState, MaintenanceCoordinator, MaintenanceFailure,
    MaintenanceReservationAuthority, MaintenanceScope, MaintenanceTaskClass, MaintenanceTaskId,
    MaintenanceTaskPhase, NO_DURABLE_PROGRESS_SLO_SECONDS, ResourceDimension, SegmentScope,
    integrity_quarantine_findings,
};

use crate::ServiceHandle;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MaintenanceServiceFailure {
    InvalidRequest,
    AuthenticationRejected,
    TaskUnavailable,
    SourceUnavailable,
    IdempotencyConflict,
    PreconditionFailed,
    AdministrationUnavailable,
}

impl ServiceHandle {
    /// Authenticates a system administrator before decoding the bounded
    /// inspection request. The response is derived solely from the runtime's
    /// one coordinator and contains no credentials or immutable input bytes.
    pub(crate) fn maintenance_status(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<MaintenanceStatusResponse, MaintenanceServiceFailure> {
        let _catalog_operation = self
            .catalog_operation()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        self.authorize_system_administration(bearer)?;
        let request = MaintenanceStatusRequest::decode(body)
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let cursor = match request.cursor() {
            Some(value) => {
                Some(task_identity(value).ok_or(MaintenanceServiceFailure::InvalidRequest)?)
            },
            None => None,
        };
        let (clock_uncertain, now) = self.maintenance_inspection_clock()?;
        let statuses = self
            .instance
            .maintenance_coordinator()
            .statuses_with_progress_slo(now, clock_uncertain)
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let mut response = MaintenanceStatusResponse {
            tasks: Vec::with_capacity(request.page_limit()),
            returned: 0,
            total: u32::try_from(statuses.len())
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?,
            next_cursor: None,
            queued: 0,
            running: 0,
            deferred: 0,
            terminal: 0,
            integrity_findings: integrity_findings(self)?,
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
                    .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?,
            );
        }
        response.returned = u32::try_from(response.tasks.len())
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        if has_more {
            response.next_cursor = response.tasks.last().map(|task| task.identity.clone());
        }
        response
            .validate()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        Ok(response)
    }

    pub(crate) fn explain_maintenance_task(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<MaintenanceExplainResponse, MaintenanceServiceFailure> {
        let _catalog_operation = self
            .catalog_operation()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        self.authorize_system_administration(bearer)?;
        let request = MaintenanceExplainRequest::decode(body)
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let identity =
            task_identity(&request.identity).ok_or(MaintenanceServiceFailure::InvalidRequest)?;
        let (clock_uncertain, now) = self.maintenance_inspection_clock()?;
        let status = self
            .instance
            .maintenance_coordinator()
            .status_with_progress_slo(identity, now, clock_uncertain)
            .map_err(|_| MaintenanceServiceFailure::TaskUnavailable)?;
        Ok(MaintenanceExplainResponse {
            task: task_status_for_coordinator(self.instance.maintenance_coordinator(), status, now)
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?,
        })
    }

    /// Submits only the kernel-produced Compaction descriptor for one explicit
    /// sealed signal scope. Callers provide no source objects, retention
    /// bounds, reservations, preconditions, or task descriptor fields.
    pub(crate) fn run_maintenance(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<MaintenanceRunResponse, MaintenanceServiceFailure> {
        let _catalog_operation = self
            .catalog_operation()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let actor = self.authorize_system_administration(bearer)?;
        let request = MaintenanceRunRequest::decode(body)
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let tenant = TenantId::parse_canonical(request.tenant())
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let signal = signal(request.signal()).ok_or(MaintenanceServiceFailure::InvalidRequest)?;
        let shard = VirtualShardId::new(request.shard())
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let idempotency = administrative_key(request.idempotency_key())
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let task_identity = maintenance_task_id(actor.principal_id(), idempotency)?;
        let now = self.maintenance_status_now()?;
        let instance = &self.instance;
        let catalog = Catalog::open(
            &instance._authority,
            instance.instance,
            instance
                .key
                .catalog_secret(instance.instance)
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?,
        )
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        if let Some(response) = maintenance_run_replay(
            &catalog,
            actor.principal_id(),
            idempotency,
            task_identity,
            tenant,
            signal,
            shard,
        )? {
            return Ok(response);
        }
        let snapshot = catalog
            .pin()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let identity = Identity::open(&snapshot)
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let scope = SegmentScope::new(tenant, signal, shard);
        let expected_scope = MaintenanceScope::segment(tenant, signal, shard);
        if !snapshot
            .reachable_ledger_scopes(tenant, signal)
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
            .into_iter()
            .any(|candidate| candidate == scope)
        {
            return Err(MaintenanceServiceFailure::SourceUnavailable);
        }
        let coordinator = instance.maintenance_coordinator();
        match coordinator.status(task_identity) {
            Ok(status)
                if status.task().class() == MaintenanceTaskClass::Compaction
                    && status.task().scope() == expected_scope =>
            {
                return Ok(MaintenanceRunResponse {
                    resource_generation: status.task().preconditions().resource_generation(),
                    task: task_acknowledgement(status),
                });
            },
            Ok(_) => return Err(MaintenanceServiceFailure::IdempotencyConflict),
            Err(positron_kernel::MaintenanceFailure::UnknownTask) => {},
            Err(_) => return Err(MaintenanceServiceFailure::AdministrationUnavailable),
        }
        let key = super::tenant_segment_key(instance, &identity, scope)
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
            &instance._authority,
            &instance.retention_time,
            &catalog,
            scope,
            key,
        )
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let bucket = ledger.sealed_compaction_bucket().map_err(source_failure)?;
        let task = ledger
            .prepare_compaction_task(bucket, task_identity)
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let audit = maintenance_run_audit_intent(MaintenanceRunAuditRequest {
            actor: actor.principal_id(),
            idempotency_key: idempotency,
            task: task_identity,
            tenant,
            signal,
            shard: shard.value(),
            resource_generation: task.task().preconditions().resource_generation(),
            submitted_at_unix_seconds: now,
        })
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let submitted = task
            .submit_and_persist_audited(coordinator, &catalog, now, audit)
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let status = coordinator
            .status(submitted.identity())
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        drop(ledger);
        drop(catalog);
        drop(_catalog_operation);
        self.notify_maintenance_worker();
        Ok(MaintenanceRunResponse {
            resource_generation: status.task().preconditions().resource_generation(),
            task: task_acknowledgement(status),
        })
    }

    pub(crate) fn pause_maintenance(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<MaintenanceControlResponse, MaintenanceServiceFailure> {
        let _catalog_operation = self
            .catalog_operation()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let actor = self.authorize_system_administration(bearer)?;
        let request = MaintenancePauseRequest::decode(body)
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let identity =
            task_identity(request.identity()).ok_or(MaintenanceServiceFailure::InvalidRequest)?;
        let idempotency = administrative_key(request.idempotency_key())
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let catalog = self.open_maintenance_catalog()?;
        let now = self.maintenance_status_now()?;
        if let Some(audit) = maintenance_control_replay(
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
            return Ok(control_acknowledgement(status, &audit));
        }
        let until = now
            .checked_add(request.duration_seconds())
            .ok_or(MaintenanceServiceFailure::InvalidRequest)?;
        let audit = maintenance_control_audit_intent(
            actor.principal_id(),
            idempotency,
            identity,
            true,
            request.resource_generation(),
            request.duration_seconds(),
            Some(until),
        )
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
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
        let audit = maintenance_control_replay(
            &catalog,
            actor.principal_id(),
            idempotency,
            identity,
            true,
            request.resource_generation(),
            request.duration_seconds(),
        )?
        .ok_or(MaintenanceServiceFailure::AdministrationUnavailable)?;
        drop(catalog);
        drop(_catalog_operation);
        self.notify_maintenance_worker();
        Ok(control_acknowledgement(status, &audit))
    }

    pub(crate) fn resume_maintenance(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<MaintenanceControlResponse, MaintenanceServiceFailure> {
        let _catalog_operation = self
            .catalog_operation()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let actor = self.authorize_system_administration(bearer)?;
        let request = MaintenanceResumeRequest::decode(body)
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let identity =
            task_identity(request.identity()).ok_or(MaintenanceServiceFailure::InvalidRequest)?;
        let idempotency = administrative_key(request.idempotency_key())
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let catalog = self.open_maintenance_catalog()?;
        if let Some(audit) = maintenance_control_replay(
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
            return Ok(control_acknowledgement(status, &audit));
        }
        let audit = maintenance_control_audit_intent(
            actor.principal_id(),
            idempotency,
            identity,
            false,
            0,
            0,
            None,
        )
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let coordinator = self.instance.maintenance_coordinator();
        coordinator
            .resume_and_persist_audited(&catalog, identity, audit)
            .map_err(control_failure)?;
        let status = coordinator.status(identity).map_err(control_failure)?;
        let audit = maintenance_control_replay(
            &catalog,
            actor.principal_id(),
            idempotency,
            identity,
            false,
            0,
            0,
        )?
        .ok_or(MaintenanceServiceFailure::AdministrationUnavailable)?;
        drop(catalog);
        drop(_catalog_operation);
        self.notify_maintenance_worker();
        Ok(control_acknowledgement(status, &audit))
    }

    /// Authenticates before decoding a bounded whole-coordinator Maintenance
    /// Window. The durable Catalog generation precondition prevents a stale
    /// operator request from replacing a later window.
    pub(crate) fn set_maintenance_window(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<MaintenanceWindowResponse, MaintenanceServiceFailure> {
        let _catalog_operation = self
            .catalog_operation()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let actor = self.authorize_system_administration(bearer)?;
        let request = MaintenanceWindowRequest::decode(body)
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let mut deferred = request
            .deferred_classes()
            .iter()
            .map(|class| window_class(class).ok_or(MaintenanceServiceFailure::InvalidRequest))
            .collect::<Result<Vec<_>, _>>()?;
        deferred.sort_unstable();
        let deferred_classes = window_class_names(&deferred);
        let idempotency = administrative_key(request.idempotency_key())
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
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
            .ok_or(MaintenanceServiceFailure::InvalidRequest)?;
        let audit = maintenance_window_audit_intent(
            actor.principal_id(),
            idempotency,
            request.expected_catalog_generation(),
            &deferred,
            request.duration_seconds(),
            until,
        )
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
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
        let audit_position = latest_governance_audit_position(&catalog)?;
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

    fn open_maintenance_catalog(&self) -> Result<Catalog<'_>, MaintenanceServiceFailure> {
        let instance = &self.instance;
        Catalog::open(
            &instance._authority,
            instance.instance,
            instance
                .key
                .catalog_secret(instance.instance)
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?,
        )
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)
    }

    fn maintenance_status_now(&self) -> Result<u64, MaintenanceServiceFailure> {
        self.instance
            .retention_time
            .governance_now_seconds()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)
    }

    /// Inspection exposes exact scheduler blockers even while lifecycle time
    /// cannot safely derive an age or deadline.
    fn maintenance_inspection_clock(
        &self,
    ) -> Result<(bool, Option<u64>), MaintenanceServiceFailure> {
        if self.instance.retention_time.status().state() == LifecycleClockState::ClockUncertain {
            return Ok((true, None));
        }
        self.maintenance_status_now().map(|now| (false, Some(now)))
    }

    fn authorize_system_administration(
        &self,
        bearer: &str,
    ) -> Result<AuthorizedContext, MaintenanceServiceFailure> {
        self.instance
            .attribute(
                PresentedCredential::parse(bearer)
                    .map_err(|_| MaintenanceServiceFailure::AuthenticationRejected)?,
                RequestedIntent::SystemAdministration,
                CompatibilityHints::none(),
            )
            .map_err(|_| MaintenanceServiceFailure::AuthenticationRejected)
    }
}

fn integrity_findings(
    services: &ServiceHandle,
) -> Result<Vec<IntegrityQuarantineDescriptor>, MaintenanceServiceFailure> {
    let catalog = services.open_maintenance_catalog()?;
    let snapshot = catalog
        .pin()
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
    let findings = integrity_quarantine_findings(&snapshot)
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
    let mut projected = Vec::new();
    projected
        .try_reserve(findings.len())
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
    for finding in findings {
        projected.push(IntegrityQuarantineDescriptor {
            tenant: finding.scope().tenant_id().to_canonical_text(),
            signal: match finding.scope().signal_kind() {
                SignalKind::Logs => "logs".to_owned(),
                SignalKind::Traces => "traces".to_owned(),
            },
            shard: finding.scope().shard_id().value(),
            segment: hex_bytes(&finding.segment().to_bytes()),
            base_position: finding.base_position(),
            event_range: event_range(finding.event_range()),
            ingest_range: ingest_range(finding.ingest_range()),
        });
    }
    Ok(projected)
}

fn event_range(range: AuthenticatedEventRange) -> AuthenticatedTimeRangeDescriptor {
    match range {
        AuthenticatedEventRange::Known { earliest, latest } => {
            known_range(earliest.value(), latest.value())
        },
        AuthenticatedEventRange::Unavailable(reason) => unavailable_range(match reason {
            positron_kernel::EventRangeUnavailable::MissingSourceTime => "missing_source_time",
            positron_kernel::EventRangeUnavailable::InvalidSourceTime => "invalid_source_time",
            positron_kernel::EventRangeUnavailable::LegacyFormat => "legacy_format",
        }),
    }
}

fn ingest_range(range: AuthenticatedIngestRange) -> AuthenticatedTimeRangeDescriptor {
    match range {
        AuthenticatedIngestRange::Known { earliest, latest } => {
            known_range(earliest.value(), latest.value())
        },
        AuthenticatedIngestRange::Unavailable => unavailable_range("unavailable"),
    }
}

fn known_range(earliest: i64, latest: i64) -> AuthenticatedTimeRangeDescriptor {
    AuthenticatedTimeRangeDescriptor {
        provenance: "known".to_owned(),
        earliest_unix_nanos: Some(earliest),
        latest_unix_nanos: Some(latest),
    }
}

fn unavailable_range(provenance: &str) -> AuthenticatedTimeRangeDescriptor {
    AuthenticatedTimeRangeDescriptor {
        provenance: provenance.to_owned(),
        earliest_unix_nanos: None,
        latest_unix_nanos: None,
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

fn signal(value: &str) -> Option<SignalKind> {
    match value {
        "logs" => Some(SignalKind::Logs),
        "traces" => Some(SignalKind::Traces),
        _ => None,
    }
}

fn source_failure(failure: LedgerFailure) -> MaintenanceServiceFailure {
    match failure.code() {
        LedgerFailureCode::InvalidInput | LedgerFailureCode::PhysicalScopeMismatch => {
            MaintenanceServiceFailure::SourceUnavailable
        },
        _ => MaintenanceServiceFailure::AdministrationUnavailable,
    }
}

fn maintenance_task_id(
    principal: PrincipalId,
    idempotency: AdministrativeIdempotencyKey,
) -> Result<MaintenanceTaskId, MaintenanceServiceFailure> {
    let mut digest = Sha256::new();
    digest.update(b"positron-maintenance-run-v1");
    digest.update(principal.to_bytes());
    digest.update(idempotency.to_bytes());
    let digest: [u8; 32] = digest.finalize().into();
    let mut identity = [0_u8; 16];
    identity.copy_from_slice(
        digest
            .get(..16)
            .ok_or(MaintenanceServiceFailure::AdministrationUnavailable)?,
    );
    MaintenanceTaskId::new(identity)
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)
}

/// Decodes the wire format solely to construct the administrative key at the
/// maintenance boundary. No principal identity crosses that boundary.
fn administrative_key(
    value: &str,
) -> Result<AdministrativeIdempotencyKey, MaintenanceServiceFailure> {
    let principal = PrincipalId::parse_canonical(value)
        .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
    AdministrativeIdempotencyKey::new(principal.to_bytes())
        .map_err(|_| MaintenanceServiceFailure::InvalidRequest)
}

fn maintenance_control_replay(
    catalog: &Catalog<'_>,
    actor: PrincipalId,
    idempotency: AdministrativeIdempotencyKey,
    identity: MaintenanceTaskId,
    pause: bool,
    resource_generation: u64,
    duration_seconds: u64,
) -> Result<Option<MaintenanceControlAuditEntry>, MaintenanceServiceFailure> {
    let records = catalog
        .governance_audit_records()
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
    for record in records {
        let entry = GovernanceAuditEntry::decode(&record)
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
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
            return Err(MaintenanceServiceFailure::IdempotencyConflict);
        }
        return Ok(Some(candidate));
    }
    Ok(None)
}

fn maintenance_run_replay(
    catalog: &Catalog<'_>,
    actor: PrincipalId,
    idempotency: AdministrativeIdempotencyKey,
    task: MaintenanceTaskId,
    tenant: TenantId,
    signal: SignalKind,
    shard: VirtualShardId,
) -> Result<Option<MaintenanceRunResponse>, MaintenanceServiceFailure> {
    for record in catalog
        .governance_audit_records()
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
    {
        let entry = GovernanceAuditEntry::decode(&record)
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let GovernanceAuditEntry::MaintenanceRun(candidate) = entry else {
            continue;
        };
        if candidate.actor() != actor
            || candidate.idempotency_key().to_bytes() != idempotency.to_bytes()
        {
            continue;
        }
        if candidate.task() != task
            || candidate.tenant() != tenant
            || candidate.signal() != signal
            || candidate.shard() != shard.value()
        {
            return Err(MaintenanceServiceFailure::IdempotencyConflict);
        }
        return Ok(Some(run_acknowledgement(&candidate)?));
    }
    Ok(None)
}

fn run_acknowledgement(
    audit: &MaintenanceRunAuditEntry,
) -> Result<MaintenanceRunResponse, MaintenanceServiceFailure> {
    let shard = VirtualShardId::new(audit.shard())
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
    Ok(MaintenanceRunResponse {
        resource_generation: audit.resource_generation(),
        task: MaintenanceTaskAcknowledgement {
            identity: hex(audit.task().to_bytes()),
            class: "compaction".to_owned(),
            scope: scope_name(MaintenanceScope::segment(
                audit.tenant(),
                audit.signal(),
                shard,
            )),
            submitted_at_unix_seconds: audit.submitted_at_unix_seconds(),
        },
    })
}

fn maintenance_window_replay(
    catalog: &Catalog<'_>,
    actor: PrincipalId,
    idempotency: AdministrativeIdempotencyKey,
    expected_catalog_generation: u64,
    deferred: &[MaintenanceTaskClass],
    duration_seconds: u64,
) -> Result<Option<MaintenanceWindowResponse>, MaintenanceServiceFailure> {
    let records = catalog
        .governance_audit_records()
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
    for record in records {
        let entry = GovernanceAuditEntry::decode(&record)
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
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
            return Err(MaintenanceServiceFailure::IdempotencyConflict);
        }
        return Ok(Some(MaintenanceWindowResponse {
            deferred_classes: window_class_names(deferred),
            until_unix_seconds: candidate.until_unix_seconds(),
            catalog_generation: expected_catalog_generation
                .checked_add(1)
                .ok_or(MaintenanceServiceFailure::AdministrationUnavailable)?,
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

fn control_failure(failure: MaintenanceFailure) -> MaintenanceServiceFailure {
    match failure {
        MaintenanceFailure::UnknownTask => MaintenanceServiceFailure::TaskUnavailable,
        MaintenanceFailure::PreconditionFailed
        | MaintenanceFailure::InvalidTransition
        | MaintenanceFailure::InvalidInput => MaintenanceServiceFailure::PreconditionFailed,
        _ => MaintenanceServiceFailure::AdministrationUnavailable,
    }
}

fn latest_governance_audit_position(
    catalog: &Catalog<'_>,
) -> Result<u64, MaintenanceServiceFailure> {
    catalog
        .governance_audit_records()
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
        .last()
        .map(positron_kernel::GovernanceAuditRecord::position)
        .ok_or(MaintenanceServiceFailure::AdministrationUnavailable)
}

fn task_acknowledgement(
    status: positron_kernel::MaintenanceTaskStatus,
) -> MaintenanceTaskAcknowledgement {
    let task = status.task();
    MaintenanceTaskAcknowledgement {
        identity: hex(task.identity().to_bytes()),
        class: class_name(task.class()).to_owned(),
        scope: scope_name(task.scope()),
        submitted_at_unix_seconds: status.submitted_at(),
    }
}

fn control_acknowledgement(
    status: positron_kernel::MaintenanceTaskStatus,
    audit: &MaintenanceControlAuditEntry,
) -> MaintenanceControlResponse {
    MaintenanceControlResponse {
        task: task_acknowledgement(status),
        action: if audit.is_pause() {
            "pause".to_owned()
        } else {
            "resume".to_owned()
        },
        resource_generation: audit.is_pause().then_some(audit.resource_generation()),
        pause_until_unix_seconds: audit.is_pause().then_some(audit.pause_until_unix_seconds()),
        audit_position: audit.position(),
    }
}

fn task_status_for_coordinator(
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
        rendered.push(hex_digit(byte >> 4));
        rendered.push(hex_digit(byte & 0x0f));
    }
    rendered
}

const fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'a' + (value - 10)) as char,
    }
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
        ActiveSegmentLedger, CatalogPublicationFault, LifecycleClockFailure, LifecycleClockPolicy,
        LifecycleClockSource, MaintenancePreconditions, MaintenanceScope, MaintenanceTask,
        MaintenanceTaskClass, MaintenanceTaskId, MaintenanceTaskPhase, MaintenanceTrigger,
        ResourceAmounts, RetentionTimeAuthority, SegmentScope,
        with_catalog_publication_fault_after,
    };
    use prost::Message;

    use super::super::ServiceHandle;
    use super::super::tests::schema_maintenance::{Fixture, open_catalog, request};
    use super::MaintenanceServiceFailure;

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
    fn authenticated_status_and_explain_report_the_durable_progress_deadline_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
        let mut initialized = Arc::try_unwrap(initialized)
            .map_err(|_| "maintenance fixture retains the initialized instance")?;
        let (retention_time, elapsed) = RetentionTimeAuthority::establish_with_manual_elapsed(
            UnixNanoseconds::new(1_000_000_000),
        );
        initialized.install_retention_time_for_test(retention_time)?;
        let initialized = Arc::new(initialized);
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        let operations = crate::health::ProcessState::starting();
        operations.set_inspection_authority(Arc::clone(&initialized))?;
        operations.set_catalog_operation(services.catalog_operation_gate())?;
        let identity = initialized.queue_governance_audit_checkpoint_for_test()?;
        let catalog = open_catalog(&initialized)?;
        let execution = initialized
            .maintenance_coordinator()
            .start_task_with_reservation_and_persist(
                &catalog,
                &initialized._authority,
                1,
                false,
                identity,
            )
            .map_err(|failure| format!("durably start task: {failure:?}"))?
            .ok_or("running task was not selected")?;
        drop(execution);
        drop(catalog);
        let rendered_identity = super::hex(identity.to_bytes());

        elapsed.advance(59_000_000_000)?;
        let status = services
            .maintenance_status(&administrator, br"{}")
            .map_err(|failure| format!("pre-deadline status: {failure:?}"))?;
        let observed = status
            .tasks
            .into_iter()
            .find(|candidate| candidate.identity == rendered_identity)
            .ok_or("running task missing before deadline")?;
        assert_eq!(observed.phase, "running");
        assert_eq!(observed.last_progress_at_unix_seconds, Some(1));
        assert_eq!(observed.no_durable_progress_slo_seconds, Some(60));
        assert_eq!(observed.no_durable_progress_slo_breached, Some(false));
        let explain = services
            .explain_maintenance_task(
                &administrator,
                &serde_json::to_vec(&MaintenanceExplainRequest {
                    identity: rendered_identity.clone(),
                })?,
            )
            .map_err(|failure| format!("pre-deadline explain: {failure:?}"))?;
        assert_eq!(explain.task.no_durable_progress_slo_seconds, Some(60));
        assert_eq!(explain.task.no_durable_progress_slo_breached, Some(false));
        let health = operations
            .health()
            .authorized_configuration_status(&administrator)
            .map_err(|failure| format!("pre-deadline operations health: {failure:?}"))?
            .maintenance;
        assert_eq!(health.running(), 1);
        assert_eq!(health.running_no_durable_progress_slo_breaches(), 0);
        assert_eq!(health.running_no_durable_progress_slo_unknown(), 0);

        elapsed.advance(1_000_000_000)?;
        let status = services
            .maintenance_status(&administrator, br"{}")
            .map_err(|failure| format!("deadline status: {failure:?}"))?;
        let observed = status
            .tasks
            .into_iter()
            .find(|candidate| candidate.identity == rendered_identity)
            .ok_or("running task missing at deadline")?;
        assert_eq!(observed.no_durable_progress_slo_breached, Some(true));
        let explain = services
            .explain_maintenance_task(
                &administrator,
                &serde_json::to_vec(&MaintenanceExplainRequest {
                    identity: rendered_identity,
                })?,
            )
            .map_err(|failure| format!("deadline explain: {failure:?}"))?;
        assert_eq!(explain.task.no_durable_progress_slo_breached, Some(true));
        let health = operations
            .health()
            .authorized_configuration_status(&administrator)
            .map_err(|failure| format!("deadline operations health: {failure:?}"))?
            .maintenance;
        assert_eq!(health.running_no_durable_progress_slo_breaches(), 1);
        assert_eq!(health.running_no_durable_progress_slo_unknown(), 0);
        Ok(())
    }

    #[test]
    fn authenticated_running_status_and_explain_report_progress_unknown_when_clock_is_uncertain()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
        let mut initialized = Arc::try_unwrap(initialized)
            .map_err(|_| "maintenance fixture retains the initialized instance")?;
        let wall = Arc::new(Mutex::new(UnixNanoseconds::new(10_000_000_000)));
        initialized.install_retention_time_for_test(
            RetentionTimeAuthority::establish_with_source(
                MutableWallClock(Arc::clone(&wall)),
                LifecycleClockPolicy::new(10)?,
            )?,
        )?;
        let scope = SegmentScope::new(
            initialized.default_tenant_id(),
            SignalKind::Logs,
            positron_domain::routing::VirtualShardId::new(1)?,
        );
        let now = initialized.retention_time.governance_time_seconds(scope)?;
        let initialized = Arc::new(initialized);
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        let operations = crate::health::ProcessState::starting();
        operations.set_inspection_authority(Arc::clone(&initialized))?;
        operations.set_catalog_operation(services.catalog_operation_gate())?;
        let identity = initialized.queue_governance_audit_checkpoint_for_test()?;
        let catalog = open_catalog(&initialized)?;
        let execution = initialized
            .maintenance_coordinator()
            .start_task_with_reservation_and_persist(
                &catalog,
                &initialized._authority,
                now,
                false,
                identity,
            )
            .map_err(|failure| format!("durably start task: {failure:?}"))?
            .ok_or("running task was not selected")?;
        drop(execution);
        drop(catalog);
        *wall.lock().map_err(|_| "maintenance test wall clock")? = UnixNanoseconds::new(500);
        initialized.retention_time.governance_time_seconds(scope)?;
        let rendered_identity = super::hex(identity.to_bytes());

        let status = services
            .maintenance_status(&administrator, br"{}")
            .map_err(|failure| format!("uncertain running status: {failure:?}"))?;
        let observed = status
            .tasks
            .into_iter()
            .find(|candidate| candidate.identity == rendered_identity)
            .ok_or("running uncertain task missing from status")?;
        assert_eq!(observed.phase, "running");
        assert_eq!(observed.no_durable_progress_slo_seconds, Some(60));
        assert_eq!(observed.no_durable_progress_slo_breached, None);
        assert_eq!(observed.backlog_age_seconds, None);
        let explain = services
            .explain_maintenance_task(
                &administrator,
                &serde_json::to_vec(&MaintenanceExplainRequest {
                    identity: rendered_identity,
                })?,
            )
            .map_err(|failure| format!("uncertain running explain: {failure:?}"))?;
        assert_eq!(explain.task.no_durable_progress_slo_seconds, Some(60));
        assert_eq!(explain.task.no_durable_progress_slo_breached, None);
        assert_eq!(explain.task.backlog_age_seconds, None);
        let health = operations
            .health()
            .authorized_configuration_status(&administrator)
            .map_err(|failure| format!("uncertain operations health: {failure:?}"))?
            .maintenance;
        assert!(health.clock_uncertain());
        assert_eq!(health.running(), 1);
        assert_eq!(health.running_no_durable_progress_slo_breaches(), 0);
        assert_eq!(health.running_no_durable_progress_slo_unknown(), 1);
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
        assert_eq!(
            observed.retention_impact.as_deref(),
            Some("eligibility_unknown")
        );
        assert_eq!(observed.automatic_resume_at_unix_seconds, None);
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
        assert_eq!(
            observed.capacity_risk.as_deref(),
            Some("foreground_reservation")
        );
        assert_eq!(observed.retention_impact.as_deref(), Some("unaffected"));
        assert_eq!(observed.recovery_impact.as_deref(), Some("unaffected"));
        assert_eq!(
            observed.automatic_resume_at_unix_seconds,
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
        assert_eq!(
            explain.task.automatic_resume_at_unix_seconds,
            Some(window.until_unix_seconds)
        );
        assert_eq!(
            explain.task.capacity_risk.as_deref(),
            Some("foreground_reservation")
        );
        assert_eq!(explain.task.retention_impact.as_deref(), Some("unaffected"));
        assert_eq!(explain.task.recovery_impact.as_deref(), Some("unaffected"));
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
        assert_eq!(first.resource_generation, 1);
        assert!(
            open_catalog(&initialized)?
                .governance_audit_records()?
                .into_iter()
                .map(|record| positron_governance::GovernanceAuditEntry::decode(&record))
                .collect::<Result<Vec<_>, _>>()?
                .iter()
                .any(|entry| entry.action() == "maintenance.run"),
            "the first durable task submission must atomically leave immutable governance evidence"
        );
        let replay = services
            .run_maintenance(&administrator, &body)
            .map_err(|failure| format!("replayed run: {failure:?}"))?;
        assert_eq!(replay, first, "retry attaches to the durable task");
        let identity = super::task_identity(&first.task.identity).ok_or("task identity")?;
        let catalog = open_catalog(&initialized)?;
        initialized
            .maintenance_coordinator()
            .cancel_and_persist(&catalog, identity)
            .map_err(|failure| format!("terminal successor: {failure:?}"))?;
        for raw in 1..=128_u8 {
            let filler = MaintenanceTask::new(
                MaintenanceTaskId::new([raw; 16])
                    .map_err(|failure| format!("filler identity: {failure:?}"))?,
                MaintenanceTaskClass::SchemaPromotion,
            );
            initialized
                .maintenance_coordinator()
                .submit_and_persist(&catalog, filler.clone(), 2)
                .map_err(|failure| format!("fill retained task capacity: {failure:?}"))?;
            initialized
                .maintenance_coordinator()
                .cancel_and_persist(&catalog, filler.identity())
                .map_err(|failure| format!("terminal filler task: {failure:?}"))?;
        }
        assert!(matches!(
            initialized.maintenance_coordinator().status(identity),
            Err(positron_kernel::MaintenanceFailure::UnknownTask)
        ));
        drop(catalog);
        assert_eq!(
            services
                .run_maintenance(&administrator, &body)
                .map_err(|failure| format!("terminal replay: {failure:?}"))?,
            first,
            "a terminal successor cannot change the durable run acknowledgement"
        );
        let conflicting = MaintenanceRunRequest::new(
            "compaction".to_owned(),
            initialized.default_tenant_id().to_canonical_text(),
            "traces".to_owned(),
            scope.shard_id().value(),
            "00000000-0000-0000-0000-000000000001".to_owned(),
        )
        .encode()?;
        assert_eq!(
            services.run_maintenance(&administrator, &conflicting),
            Err(MaintenanceServiceFailure::IdempotencyConflict),
            "a retained immutable receipt rejects a different request before source lookup"
        );
        drop(services);
        drop(initialized);

        let reopened = fixture.reopen()?;
        let restored_services = ServiceHandle::new(Arc::clone(&reopened))?;
        assert_eq!(
            restored_services
                .run_maintenance(&administrator, &body)
                .map_err(|failure| format!("reopened terminal replay: {failure:?}"))?,
            first,
            "a reopened terminal successor cannot change the durable run acknowledgement"
        );
        assert!(
            matches!(
                reopened.maintenance_coordinator().status(identity),
                Err(positron_kernel::MaintenanceFailure::UnknownTask)
            ),
            "terminal retention reclamation removes the mutable task record while the audit receipt remains replayable after reopen"
        );
        Ok(())
    }

    #[test]
    fn authenticated_run_terminalizes_a_one_segment_log_compaction()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        services.ingest_otlp_logs(&ingest, request("run-api-one-segment").encode_to_vec())?;
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

        let body = MaintenanceRunRequest::new(
            "compaction".to_owned(),
            initialized.default_tenant_id().to_canonical_text(),
            "logs".to_owned(),
            scope.shard_id().value(),
            "00000000-0000-0000-0000-000000000021".to_owned(),
        )
        .encode()?;
        let response = services
            .run_maintenance(&administrator, &body)
            .map_err(|failure| format!("one-segment run: {failure:?}"))?;
        let identity = super::task_identity(&response.task.identity).ok_or("task identity")?;

        assert!(
            services.wake_maintenance_worker()?,
            "the public Run task dispatches through the bounded worker"
        );
        assert_eq!(
            initialized
                .maintenance_coordinator()
                .status(identity)
                .map_err(|failure| format!("one-segment status: {failure:?}"))?
                .phase(),
            MaintenanceTaskPhase::Succeeded,
            "a selected sealed source with one segment has no compaction work but still terminalizes"
        );
        Ok(())
    }

    #[test]
    fn authenticated_run_keeps_audit_and_task_publication_atomic_across_faults()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        services.ingest_otlp_logs(&ingest, request("run-fault-sealed-source").encode_to_vec())?;
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
            "00000000-0000-0000-0000-000000000031".to_owned(),
        );
        let body = request.encode()?;
        let rejected = with_catalog_publication_fault_after(
            CatalogPublicationFault::SynchronizeCommit,
            0,
            || services.run_maintenance(&administrator, &body),
        );
        assert_eq!(
            rejected,
            Err(MaintenanceServiceFailure::AdministrationUnavailable)
        );
        assert!(
            initialized
                .maintenance_coordinator()
                .statuses()
                .map_err(|failure| format!("coordinator status: {failure:?}"))?
                .is_empty(),
            "the in-memory coordinator cannot expose a descriptor whose catalog publication failed"
        );
        assert!(
            open_catalog(&initialized)?
                .governance_audit_records()?
                .into_iter()
                .map(|record| positron_governance::GovernanceAuditEntry::decode(&record))
                .collect::<Result<Vec<_>, _>>()?
                .iter()
                .all(|entry| entry.action() != "maintenance.run"),
            "a failed pre-publication commit leaves neither a Run receipt nor a task descriptor"
        );
        let first = services
            .run_maintenance(&administrator, &body)
            .map_err(|failure| format!("retry after rejected publication: {failure:?}"))?;
        assert_eq!(
            initialized
                .maintenance_coordinator()
                .durable_records()
                .map_err(|failure| format!("coordinator records: {failure:?}"))?
                .len(),
            1,
            "the retry publishes one descriptor only after the rejected transaction left no durable state"
        );
        assert_eq!(
            services
                .run_maintenance(&administrator, &body)
                .map_err(|failure| format!("retry acknowledgement: {failure:?}"))?,
            first
        );
        Ok(())
    }

    #[test]
    fn authenticated_run_reconciles_a_lost_publication_acknowledgement_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        services.ingest_otlp_logs(&ingest, request("run-lost-ack-source").encode_to_vec())?;
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
        let body = MaintenanceRunRequest::new(
            "compaction".to_owned(),
            initialized.default_tenant_id().to_canonical_text(),
            "logs".to_owned(),
            scope.shard_id().value(),
            "00000000-0000-0000-0000-000000000032".to_owned(),
        )
        .encode()?;
        let acknowledged = with_catalog_publication_fault_after(
            CatalogPublicationFault::SynchronizeGenerationDirectory,
            0,
            || services.run_maintenance(&administrator, &body),
        )
        .map_err(|failure| format!("reconcile lost acknowledgement: {failure:?}"))?;
        let replay = services
            .run_maintenance(&administrator, &body)
            .map_err(|failure| format!("replay reconciled acknowledgement: {failure:?}"))?;
        assert_eq!(
            replay, acknowledged,
            "a post-marker fault reconciles the same immutable acknowledgement before responding"
        );
        assert_eq!(
            services
                .run_maintenance(&administrator, &body)
                .map_err(|failure| format!("repeat reconciled acknowledgement: {failure:?}"))?,
            replay,
            "identical retries expose one immutable acknowledgement"
        );
        let status = services
            .maintenance_status(&administrator, br"{}")
            .map_err(|failure| format!("reconciled status: {failure:?}"))?;
        assert_eq!(status.total, 1);
        assert_eq!(status.tasks.len(), 1);
        assert_eq!(status.tasks[0].identity, replay.task.identity);
        let runs = open_catalog(&initialized)?
            .governance_audit_records()?
            .into_iter()
            .map(|record| positron_governance::GovernanceAuditEntry::decode(&record))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|entry| entry.action() == "maintenance.run")
            .count();
        assert_eq!(runs, 1, "the lost acknowledgement retains one audit intent");
        assert_eq!(
            initialized
                .maintenance_coordinator()
                .durable_records()
                .map_err(|failure| format!("reconciled records: {failure:?}"))?
                .len(),
            1,
            "the audit receipt and coordinator registry retain one task identity"
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
            Err(MaintenanceServiceFailure::AuthenticationRejected),
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
            Err(MaintenanceServiceFailure::AuthenticationRejected),
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
            Err(MaintenanceServiceFailure::IdempotencyConflict)
        );
        let stale = MaintenanceWindowRequest::new(
            vec!["compaction".to_owned()],
            expected,
            60,
            "00000000-0000-0000-0000-000000000022".to_owned(),
        );
        assert_eq!(
            services.set_maintenance_window(&administrator, &stale.encode()?),
            Err(MaintenanceServiceFailure::PreconditionFailed),
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
        assert_eq!(paused.action, "pause");
        assert_eq!(paused.resource_generation, Some(1));
        assert!(paused.pause_until_unix_seconds.is_some());
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
        assert_eq!(
            observed.capacity_risk.as_deref(),
            Some("foreground_reservation"),
            "the current reservation truthfully identifies foreground capacity contention"
        );
        assert_eq!(observed.retention_impact.as_deref(), Some("unaffected"));
        assert_eq!(observed.recovery_impact.as_deref(), Some("unaffected"));
        assert_eq!(
            observed.automatic_resume_at_unix_seconds, observed.pause_until_unix_seconds,
            "a finite pause exposes its authoritative automatic-resume time"
        );
        assert_eq!(observed.safe_actions, ["resume"]);
        assert!(observed.backlog_age_seconds.is_some());
        assert_eq!(observed.conflict_owner, None);
        assert_eq!(observed.checkpoint_completed_inputs, Some(0));
        assert_eq!(observed.input_object_count, 1);
        assert_eq!(observed.output_object_count, 0);
        assert_eq!(observed.estimated_output_object_amplification_milli, None);
        assert_eq!(observed.terminal_outcome, None);
        let expected_window_generation = open_catalog(&initialized)?.pin()?.number();
        let window_request = MaintenanceWindowRequest::new(
            vec!["compaction".to_owned()],
            expected_window_generation,
            120,
            "00000000-0000-0000-0000-000000000014".to_owned(),
        );
        let window = services
            .set_maintenance_window(&administrator, &window_request.encode()?)
            .map_err(|failure| format!("overlapping window: {failure:?}"))?;
        let overlapping_status = services
            .maintenance_status(&administrator, br"{}")
            .map_err(|failure| format!("overlapping status: {failure:?}"))?;
        let overlapping = overlapping_status
            .tasks
            .iter()
            .find(|candidate| candidate.identity == task.identity)
            .ok_or("overlapping task status")?;
        assert_eq!(
            overlapping.blocked_precondition.as_deref(),
            Some("maintenance_pause_active"),
            "the task-specific pause remains the immediate scheduler blocker"
        );
        assert_eq!(
            overlapping.maintenance_window_until_unix_seconds,
            Some(window.until_unix_seconds),
            "status retains the concurrent global window rather than hiding it behind the pause"
        );
        assert_eq!(
            overlapping.automatic_resume_at_unix_seconds,
            Some(window.until_unix_seconds),
            "automatic resume means the earliest execution time after every finite deferral"
        );
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
            Err(MaintenanceServiceFailure::IdempotencyConflict)
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
        assert_eq!(resumed.action, "resume");
        assert_eq!(resumed.resource_generation, None);
        assert_eq!(resumed.pause_until_unix_seconds, None);
        assert_eq!(
            resumed.task, paused.task,
            "both controls identify the same immutable task descriptor"
        );
        assert_eq!(
            services
                .resume_maintenance(&administrator, &resume.encode()?)
                .map_err(|failure| format!("replay resume: {failure:?}"))?,
            resumed,
            "an exact operator retry replays its acknowledged durable resume"
        );
        assert_eq!(
            services
                .pause_maintenance(&administrator, &pause.encode()?)
                .map_err(|failure| format!("pause replay after successor: {failure:?}"))?,
            paused,
            "a later resume cannot change the acknowledged pause receipt"
        );
        Ok(())
    }

    #[test]
    fn authenticated_status_reports_protected_recovery_reserve_capacity()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        let task = MaintenanceTask::new(
            MaintenanceTaskId::new([0x82; 16]).map_err(|_| "task identity")?,
            MaintenanceTaskClass::CatalogReclamation,
        );
        let identity = task.identity();
        let catalog = open_catalog(&initialized)?;
        initialized
            .maintenance_coordinator()
            .submit_and_persist(&catalog, task, 1)
            .map_err(|failure| format!("submit recovery task: {failure:?}"))?;
        drop(catalog);
        let status = services
            .maintenance_status(&administrator, br"{}")
            .map_err(|failure| format!("status recovery task: {failure:?}"))?;
        let observed = status
            .tasks
            .iter()
            .find(|candidate| candidate.identity == super::hex(identity.to_bytes()))
            .ok_or("recovery task status")?;
        assert_eq!(
            observed.capacity_risk.as_deref(),
            Some("recovery_reserve"),
            "catalog reclamation is admitted through the protected Recovery Reserve"
        );
        assert_eq!(observed.retention_impact, None);
        assert_eq!(observed.recovery_impact, None);
        Ok(())
    }

    #[test]
    fn authenticated_pause_rejects_emergency_compaction_without_audit_or_transition()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        let task = MaintenanceTask::new(
            MaintenanceTaskId::new([0x83; 16]).map_err(|_| "task identity")?,
            MaintenanceTaskClass::Compaction,
        )
        .emergency_compaction_for_test()
        .map_err(|_| "emergency compaction")?;
        let identity = task.identity();
        let audit_count = open_catalog(&initialized)?
            .governance_audit_records()?
            .len();
        initialized
            .maintenance_coordinator()
            .submit(task)
            .map_err(|failure| format!("submit emergency task: {failure:?}"))?;
        let pause = MaintenancePauseRequest::new(
            super::hex(identity.to_bytes()),
            1,
            60,
            "00000000-0000-0000-0000-000000000083".to_owned(),
        );
        assert_eq!(
            services.pause_maintenance(&administrator, &pause.encode()?),
            Err(MaintenanceServiceFailure::PreconditionFailed),
            "ADR-0071 forbids an authenticated expiring pause from deferring emergency work"
        );
        assert_eq!(
            initialized
                .maintenance_coordinator()
                .status(identity)
                .map_err(|failure| format!("emergency task status: {failure:?}"))?
                .phase(),
            MaintenanceTaskPhase::Queued,
            "rejected pause must not change the durable scheduler phase"
        );
        assert_eq!(
            open_catalog(&initialized)?
                .governance_audit_records()?
                .len(),
            audit_count,
            "rejected pause must not publish an immutable control receipt"
        );
        Ok(())
    }
}
