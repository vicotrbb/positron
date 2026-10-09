use sha2::{Digest, Sha256};

use positron_api::maintenance::{
    MaintenanceControlResponse, MaintenanceRunResponse, MaintenanceStatusResponse,
    MaintenanceTaskAcknowledgement, MaintenanceTaskStatus, MaintenanceWindowResponse,
};
use positron_domain::{
    identity::{PrincipalId, TenantId},
    routing::{SignalKind, VirtualShardId},
};
use positron_governance::{
    AdministrativeIdempotencyKey, AuthorizedContext, CompatibilityHints, GovernanceAuditEntry,
    MaintenanceControlAuditEntry, MaintenanceRunAuditEntry, PresentedCredential, RequestedIntent,
};
use positron_kernel::{
    Catalog, LedgerFailure, LedgerFailureCode, LifecycleClockState, MaintenanceFailure,
    MaintenanceScope, MaintenanceTaskClass, MaintenanceTaskId, MaintenanceTaskPhase,
};

use crate::ServiceHandle;

#[cfg(test)]
pub(super) use super::maintenance_verification::online_verification_task_identity;

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
    pub(super) fn open_maintenance_catalog(
        &self,
    ) -> Result<Catalog<'_>, MaintenanceServiceFailure> {
        let instance = &self.instance;
        Catalog::open(
            &instance._authority,
            instance.instance,
            instance
                .key
                .catalog_secret(instance.instance)
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?,
        )
        .map_err(|failure| {
            if matches!(
                failure.code(),
                positron_kernel::CatalogFailureCode::IntegrityCorruption
                    | positron_kernel::CatalogFailureCode::AuthenticationFailed
                    | positron_kernel::CatalogFailureCode::UnsupportedFormat
            ) {
                self.request_integrity_fence();
            }
            MaintenanceServiceFailure::AdministrationUnavailable
        })
    }

    pub(super) fn maintenance_status_now(&self) -> Result<u64, MaintenanceServiceFailure> {
        self.instance
            .retention_time
            .governance_now_seconds()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)
    }

    /// Inspection exposes exact scheduler blockers even while lifecycle time
    /// cannot safely derive an age or deadline.
    pub(super) fn maintenance_inspection_clock(
        &self,
    ) -> Result<(bool, Option<u64>), MaintenanceServiceFailure> {
        if self.instance.retention_time.status().state() == LifecycleClockState::ClockUncertain {
            return Ok((true, None));
        }
        self.maintenance_status_now().map(|now| (false, Some(now)))
    }

    pub(super) fn authorize_system_administration(
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

/// Adds one task only if the actual canonical response still fits its fixed
/// transport envelope. The task cursor always points at a returned task, so a
/// response can never repeat an empty first page while claiming progress.
pub(super) fn append_status_task_within_response_limit(
    response: &mut MaintenanceStatusResponse,
    task: MaintenanceTaskStatus,
    remaining: usize,
) -> Result<bool, MaintenanceServiceFailure> {
    response.tasks.push(task);
    response.returned = u32::try_from(response.tasks.len())
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
    let returned = response.tasks.len();
    response.next_cursor = (remaining > returned)
        .then(|| response.tasks.last().map(|task| task.identity.clone()))
        .flatten();
    if response.encode().is_ok() {
        return Ok(true);
    }
    response.tasks.pop();
    response.returned = u32::try_from(response.tasks.len())
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
    if response.tasks.is_empty() {
        return Err(MaintenanceServiceFailure::AdministrationUnavailable);
    }
    response.next_cursor = response.tasks.last().map(|task| task.identity.clone());
    Ok(false)
}

pub(super) fn signal(value: &str) -> Option<SignalKind> {
    match value {
        "logs" => Some(SignalKind::Logs),
        "traces" => Some(SignalKind::Traces),
        _ => None,
    }
}

pub(super) fn source_failure(failure: LedgerFailure) -> MaintenanceServiceFailure {
    match failure.code() {
        LedgerFailureCode::InvalidInput | LedgerFailureCode::PhysicalScopeMismatch => {
            MaintenanceServiceFailure::SourceUnavailable
        },
        _ => MaintenanceServiceFailure::AdministrationUnavailable,
    }
}

pub(super) fn maintenance_task_id(
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
pub(super) fn administrative_key(
    value: &str,
) -> Result<AdministrativeIdempotencyKey, MaintenanceServiceFailure> {
    let principal = PrincipalId::parse_canonical(value)
        .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
    AdministrativeIdempotencyKey::new(principal.to_bytes())
        .map_err(|_| MaintenanceServiceFailure::InvalidRequest)
}

pub(super) fn maintenance_control_replay(
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

pub(super) fn maintenance_run_replay(
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

pub(super) fn run_acknowledgement(
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

pub(super) fn maintenance_window_replay(
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

pub(super) fn window_class(value: &str) -> Option<MaintenanceTaskClass> {
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

pub(super) fn window_class_names(deferred: &[MaintenanceTaskClass]) -> Vec<String> {
    let mut names = deferred
        .iter()
        .map(window_class_name)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    names.sort_unstable();
    names
}

pub(super) fn control_failure(failure: MaintenanceFailure) -> MaintenanceServiceFailure {
    match failure {
        MaintenanceFailure::UnknownTask => MaintenanceServiceFailure::TaskUnavailable,
        MaintenanceFailure::PreconditionFailed
        | MaintenanceFailure::InvalidTransition
        | MaintenanceFailure::InvalidInput => MaintenanceServiceFailure::PreconditionFailed,
        _ => MaintenanceServiceFailure::AdministrationUnavailable,
    }
}

pub(super) fn latest_governance_audit_position(
    catalog: &Catalog<'_>,
) -> Result<u64, MaintenanceServiceFailure> {
    catalog
        .governance_audit_records()
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
        .last()
        .map(positron_kernel::GovernanceAuditRecord::position)
        .ok_or(MaintenanceServiceFailure::AdministrationUnavailable)
}

pub(super) fn task_acknowledgement(
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

pub(super) fn control_acknowledgement(
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

pub(super) fn task_identity(value: &str) -> Option<positron_kernel::MaintenanceTaskId> {
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

pub(super) fn hex(bytes: [u8; 16]) -> String {
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

pub(super) fn scope_name(scope: MaintenanceScope) -> String {
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

pub(super) const fn phase_name(phase: MaintenanceTaskPhase) -> &'static str {
    match phase {
        MaintenanceTaskPhase::Queued => "queued",
        MaintenanceTaskPhase::Running => "running",
        MaintenanceTaskPhase::Deferred => "deferred",
        MaintenanceTaskPhase::Cancelled => "cancelled",
        MaintenanceTaskPhase::Succeeded => "succeeded",
        MaintenanceTaskPhase::Failed => "failed",
    }
}

pub(super) const fn class_name(class: MaintenanceTaskClass) -> &'static str {
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
#[path = "maintenance_api_tests.rs"]
mod tests;
