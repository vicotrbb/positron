use sha2::{Digest, Sha256};

use positron_api::maintenance::{
    AuthenticatedTimeRangeDescriptor, IntegrityQuarantineDescriptor, OnlineVerificationReport,
    OnlineVerificationRequest,
};
use positron_domain::{
    identity::TenantId,
    routing::{SignalKind, VirtualShardId},
};
use positron_governance::{
    Identity, IntegrityQuarantineAuditRequest, integrity_quarantine_audit_intent,
};
use positron_kernel::{
    ActiveSegmentLedger, AuthenticatedEventRange, AuthenticatedIngestRange, Catalog,
    IntegrityCancellation, IntegrityVerificationOutcome, LifecycleClockState,
    MaintenanceCoordinator, MaintenancePreconditions, MaintenanceScope, MaintenanceTask,
    MaintenanceTaskId, MaintenanceTrigger, SegmentScope, TransactionId,
    integrity_quarantine_findings,
};

use crate::ServiceHandle;

use super::{
    maintenance_api::{MaintenanceServiceFailure, signal},
    tenant_segment_key,
};

impl ServiceHandle {
    /// Authenticates before parsing one bounded online verification request.
    /// The request pins exactly one Catalog generation for key derivation,
    /// source selection, verification, findings, and any authorized PQUAR
    /// publication. It never repairs or rewrites source bytes.
    pub(crate) fn verify_online_integrity(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<OnlineVerificationReport, MaintenanceServiceFailure> {
        self.authorize_system_administration(bearer)?;
        let request = OnlineVerificationRequest::decode(body)
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let tenant = TenantId::parse_canonical(request.tenant())
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let signal = signal(request.signal()).ok_or(MaintenanceServiceFailure::InvalidRequest)?;
        let shard = VirtualShardId::new(request.shard())
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let scope = SegmentScope::new(tenant, signal, shard);
        let continuation = request
            .continuation()
            .map(decode_continuation)
            .transpose()?;
        // Capture an authenticated immutable basis without the sole Catalog
        // writer lease. The bounded scan below therefore cannot block safe
        // foreground reads. A local finding reacquires the writer only for an
        // exact-G0 quarantine compare-and-swap.
        let snapshot = Catalog::read_current_snapshot(
            &self.instance._authority,
            self.instance.instance,
            self.instance
                .key
                .catalog_secret(self.instance.instance)
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?,
        )
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        if !snapshot
            .reachable_ledger_scopes(tenant, signal)
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
            .into_iter()
            .any(|candidate| candidate == scope)
        {
            return Err(MaintenanceServiceFailure::SourceUnavailable);
        }
        if continuation.is_none()
            && request
                .expected_catalog_generation()
                .is_some_and(|expected| expected != snapshot.number())
        {
            return Ok(stale_online_report(scope, snapshot.number()));
        }
        let task_identity = online_verification_task_identity(
            scope,
            snapshot.identity().to_bytes(),
            request.continuation(),
        )?;
        let source_manifest = snapshot
            .integrity_scope_source_identity(scope)
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let now = self.maintenance_status_now()?;
        let coordinator = self.instance.maintenance_coordinator();
        let execution = {
            let _catalog_operation = self
                .catalog_operation()
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
            let catalog = self.open_maintenance_catalog()?;
            let task = MaintenanceTask::integrity_scrub(
                task_identity,
                MaintenanceScope::segment(tenant, signal, shard),
                MaintenanceTrigger::Event,
                MaintenancePreconditions::new(snapshot.number(), 1)
                    .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?,
                source_manifest,
                0,
            )
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
            coordinator
                .submit_and_persist(&catalog, task, now)
                .map_err(|_| MaintenanceServiceFailure::TaskUnavailable)?;
            coordinator
                .start_integrity_scrub_task_with_reservation_and_persist(
                    &catalog,
                    &self.instance._authority,
                    now,
                    self.instance.retention_time.status().state()
                        == LifecycleClockState::ClockUncertain,
                    task_identity,
                )
                .map_err(|_| MaintenanceServiceFailure::TaskUnavailable)?
                .ok_or(MaintenanceServiceFailure::TaskUnavailable)?
        };
        let result = (|| {
            #[cfg(test)]
            self.await_online_verification_admission_test_hook()
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
            #[cfg(test)]
            self.await_online_verification_test_hook()
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
            let identity = Identity::open(&snapshot)
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
            let protection = tenant_segment_key(&self.instance, &identity, scope)
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
            let transaction =
                online_verification_transaction(scope, snapshot.identity().to_bytes())?;
            let report = ActiveSegmentLedger::verify_online_snapshot_integrity(
                &self.instance._authority,
                &snapshot,
                self.instance.instance,
                scope,
                protection,
                self.maintenance_integrity_scrub_budget()
                    .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?,
                &IntegrityCancellation::new(),
                transaction,
                continuation,
            )
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
            let current = Catalog::read_current_snapshot(
                &self.instance._authority,
                self.instance.instance,
                self.instance
                    .key
                    .catalog_secret(self.instance.instance)
                    .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?,
            )
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
            if !snapshot
                .same_except_maintenance_task(&current, task_identity)
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
            {
                let _catalog_operation = self
                    .catalog_operation()
                    .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
                let catalog = self.open_maintenance_catalog()?;
                execution
                    .complete_and_persist(coordinator, &catalog, false)
                    .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
                let terminal = catalog
                    .pin()
                    .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
                return Ok(stale_online_report(scope, terminal.number()));
            }
            let response_snapshot = {
                let _catalog_operation = self
                    .catalog_operation()
                    .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
                let catalog = self.open_maintenance_catalog()?;
                let current = catalog
                    .pin()
                    .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
                if !snapshot
                    .same_except_maintenance_task(&current, task_identity)
                    .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
                {
                    execution
                        .complete_and_persist(coordinator, &catalog, false)
                        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
                    let terminal = catalog
                        .pin()
                        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
                    return Ok(stale_online_report(scope, terminal.number()));
                }
                if report.outcome() == IntegrityVerificationOutcome::Quarantined {
                    let segment = report
                        .quarantined_segment()
                        .ok_or(MaintenanceServiceFailure::AdministrationUnavailable)?;
                    let audit =
                        integrity_quarantine_audit_intent(IntegrityQuarantineAuditRequest {
                            tenant,
                            signal,
                            shard: shard.value(),
                            segment: Some(segment.to_bytes()),
                        })
                        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
                    ActiveSegmentLedger::publish_online_quarantine(
                        &self.instance._authority,
                        &catalog,
                        &snapshot,
                        &current,
                        report,
                        transaction,
                        task_identity,
                        audit,
                    )
                    .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
                    self.mark_integrity_degraded();
                } else if report.outcome() == IntegrityVerificationOutcome::Fenced {
                    self.mark_integrity_fenced();
                }
                execution
                    .complete_and_persist(coordinator, &catalog, report.is_success())
                    .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
                catalog
                    .pin()
                    .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
            };
            // The maintenance task's admission and completion publications
            // advance the Catalog, but they were not part of the immutable
            // source selected and scanned above. The report generation is G0;
            // the current response snapshot supplies only the authorized
            // quarantine evidence that the scan just published.
            online_report(report, &snapshot, &response_snapshot)
        })();
        if let Err(failure) = result {
            // Admission published a durable Running record. Every later
            // failure must make that exact task terminal or recovery-queued
            // before its reservation is dropped.
            self.fail_admitted_online_verification(&execution, coordinator)?;
            return Err(failure);
        }
        result
    }

    fn fail_admitted_online_verification(
        &self,
        execution: &positron_kernel::MaintenanceExecution<'_>,
        coordinator: &MaintenanceCoordinator,
    ) -> Result<(), MaintenanceServiceFailure> {
        let terminalized = (|| {
            let _catalog_operation = self
                .catalog_operation()
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
            let catalog = self.open_maintenance_catalog()?;
            if execution
                .fail_and_persist(
                    coordinator,
                    &catalog,
                    positron_kernel::MaintenanceTerminalFailure::Unclassified,
                )
                .is_ok()
            {
                return Ok(());
            }
            execution
                .requeue_and_persist(coordinator, &catalog)
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)
        })();
        match terminalized {
            Ok(()) => Ok(()),
            Err(_) => execution
                .release_for_same_process_recovery(coordinator)
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable),
        }
    }
}

pub(super) fn integrity_findings(
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
        projected.push(integrity_finding_descriptor(finding));
    }
    Ok(projected)
}

fn online_report(
    report: positron_kernel::IntegrityVerificationReport,
    scanned_snapshot: &positron_kernel::CatalogSnapshot,
    response_snapshot: &positron_kernel::CatalogSnapshot,
) -> Result<OnlineVerificationReport, MaintenanceServiceFailure> {
    let outcome = match report.outcome() {
        IntegrityVerificationOutcome::Verified => "verified",
        IntegrityVerificationOutcome::Incomplete => "incomplete",
        IntegrityVerificationOutcome::Stale => "stale",
        IntegrityVerificationOutcome::Quarantined => "quarantined",
        IntegrityVerificationOutcome::Fenced => "fenced",
    };
    let findings = integrity_findings_for_scope(response_snapshot, report.scope())?;
    let mut online = OnlineVerificationReport {
        report_version: 1,
        tenant: report.scope().tenant_id().to_canonical_text(),
        signal: match report.scope().signal_kind() {
            SignalKind::Logs => "logs".to_owned(),
            SignalKind::Traces => "traces".to_owned(),
        },
        shard: report.scope().shard_id().value(),
        catalog_generation: scanned_snapshot.number(),
        examined_segments: u32::try_from(report.examined_segments())
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?,
        examined_bytes: report.examined_bytes(),
        omitted_segments: u32::try_from(report.omitted_segments())
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?,
        outcome: outcome.to_owned(),
        verification_complete: report.outcome() == IntegrityVerificationOutcome::Verified,
        report_checksum: String::new(),
        continuation: report
            .continuation()
            .map(|cursor| hex_bytes(&cursor.encode())),
        findings,
    };
    online.report_checksum = online.checksum();
    Ok(online)
}

fn stale_online_report(scope: SegmentScope, catalog_generation: u64) -> OnlineVerificationReport {
    let mut online = OnlineVerificationReport {
        report_version: 1,
        tenant: scope.tenant_id().to_canonical_text(),
        signal: match scope.signal_kind() {
            SignalKind::Logs => "logs".to_owned(),
            SignalKind::Traces => "traces".to_owned(),
        },
        shard: scope.shard_id().value(),
        catalog_generation,
        examined_segments: 0,
        examined_bytes: 0,
        omitted_segments: 0,
        outcome: "stale".to_owned(),
        verification_complete: false,
        report_checksum: String::new(),
        continuation: None,
        findings: Vec::new(),
    };
    online.report_checksum = online.checksum();
    online
}

fn integrity_findings_for_scope(
    snapshot: &positron_kernel::CatalogSnapshot,
    scope: SegmentScope,
) -> Result<Vec<IntegrityQuarantineDescriptor>, MaintenanceServiceFailure> {
    let findings = integrity_quarantine_findings(snapshot)
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
    let mut projected = Vec::new();
    for finding in findings
        .into_iter()
        .filter(|finding| finding.scope() == scope)
    {
        projected
            .try_reserve(1)
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        projected.push(integrity_finding_descriptor(finding));
    }
    Ok(projected)
}

fn integrity_finding_descriptor(
    finding: positron_kernel::IntegrityQuarantineFinding,
) -> IntegrityQuarantineDescriptor {
    IntegrityQuarantineDescriptor {
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
    }
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

fn decode_continuation(
    value: &str,
) -> Result<positron_kernel::IntegrityScrubContinuation, MaintenanceServiceFailure> {
    let bytes = decode_fixed_hex::<56>(value).ok_or(MaintenanceServiceFailure::InvalidRequest)?;
    positron_kernel::IntegrityScrubContinuation::decode(&bytes)
        .map_err(|_| MaintenanceServiceFailure::InvalidRequest)
}

fn online_verification_transaction(
    scope: SegmentScope,
    catalog_identity: [u8; 32],
) -> Result<TransactionId, MaintenanceServiceFailure> {
    let mut digest = Sha256::new();
    digest.update(b"positron/online-verification/v1");
    digest.update(catalog_identity);
    digest.update(scope.tenant_id().to_bytes());
    digest.update([match scope.signal_kind() {
        SignalKind::Logs => 1,
        SignalKind::Traces => 2,
    }]);
    digest.update(scope.shard_id().value().to_be_bytes());
    let bytes: [u8; 32] = digest.finalize().into();
    TransactionId::new(
        bytes
            .get(..16)
            .and_then(|prefix| prefix.try_into().ok())
            .ok_or(MaintenanceServiceFailure::AdministrationUnavailable)?,
    )
    .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)
}

pub(super) fn online_verification_task_identity(
    scope: SegmentScope,
    catalog_identity: [u8; 32],
    continuation: Option<&str>,
) -> Result<MaintenanceTaskId, MaintenanceServiceFailure> {
    let mut digest = Sha256::new();
    digest.update(b"positron/online-verification-task/v1");
    digest.update(catalog_identity);
    digest.update(scope.tenant_id().to_bytes());
    digest.update([match scope.signal_kind() {
        SignalKind::Logs => 1,
        SignalKind::Traces => 2,
    }]);
    digest.update(scope.shard_id().value().to_be_bytes());
    match continuation {
        Some(value) => {
            digest.update([1]);
            digest.update(value.as_bytes());
        },
        None => digest.update([0]),
    }
    let bytes: [u8; 32] = digest.finalize().into();
    let identity = bytes
        .get(..16)
        .and_then(|prefix| prefix.try_into().ok())
        .ok_or(MaintenanceServiceFailure::AdministrationUnavailable)?;
    MaintenanceTaskId::new(identity)
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)
}

fn decode_fixed_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N.checked_mul(2)? {
        return None;
    }
    let mut bytes = [0_u8; N];
    for (slot, pair) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *slot = (hex_value(*pair.first()?)? << 4) | hex_value(*pair.get(1)?)?;
    }
    Some(bytes)
}

const fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
