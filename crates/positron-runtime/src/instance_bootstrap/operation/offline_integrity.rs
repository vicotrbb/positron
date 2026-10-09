use positron_governance::{Identity, TenantAdministration};
use positron_kernel::{BootstrapArtifact, BootstrapObjectPurpose, Catalog};

use super::super::{BootstrapPaths, BootstrapState, resources, storage};
use super::support::{decode_record, require_key_identity};

mod continuation;

use continuation::{
    MAX_OFFLINE_AGGREGATE_EVIDENCE, OfflineIntegrityContinuationMode,
    OfflineIntegrityContinuationState, decode_offline_integrity_continuation,
    encode_offline_integrity_continuation,
};

pub(in super::super) fn verify(
    paths: &BootstrapPaths,
    max_registered_tenants: u16,
    selected_scope: Option<positron_kernel::SegmentScope>,
    resume: Option<crate::OfflineIntegrityContinuation>,
    claim: positron_kernel::WorkClaim,
    cancellation: &positron_kernel::IntegrityCancellation,
) -> Result<crate::OfflineIntegrityVerification, crate::OfflineIntegrityFailure> {
    use positron_domain::routing::SignalKind;
    use positron_kernel::{
        ActiveSegmentLedger, IntegrityScrubBudget, IntegrityVerificationRequest, TransactionId,
    };

    let (volume, access) = paths.storage.acquire().map_err(|failure| match failure {
        positron_kernel::BootstrapStorageFailure::OwnershipLocked => {
            crate::OfflineIntegrityFailure::OwnershipLocked
        },
        _ => crate::OfflineIntegrityFailure::BootstrapUnavailable,
    })?;
    let state = storage::classify_with(&access)
        .map_err(|_| crate::OfflineIntegrityFailure::BootstrapUnavailable)?;
    if state != BootstrapState::Initialized {
        if state == BootstrapState::Inconsistent && access.open_key().is_err() {
            return Err(crate::OfflineIntegrityFailure::KeyUnavailable);
        }
        if state == BootstrapState::Inconsistent {
            return Err(crate::OfflineIntegrityFailure::CorruptState);
        }
        return Err(crate::OfflineIntegrityFailure::BootstrapUnavailable);
    }
    let key = access
        .open_key()
        .map_err(|_| crate::OfflineIntegrityFailure::KeyUnavailable)?;
    let encoded = storage::read(&access, BootstrapArtifact::Initialized)
        .map_err(|_| crate::OfflineIntegrityFailure::BootstrapUnavailable)?;
    let record = decode_record(&key, BootstrapObjectPurpose::Initialized, &encoded)
        .map_err(|_| crate::OfflineIntegrityFailure::CorruptState)?;
    require_key_identity(&record, key.identity())
        .map_err(|_| crate::OfflineIntegrityFailure::CorruptState)?;
    let authority = resources::establish_system_diagnostics(volume, max_registered_tenants)
        .map_err(|_| crate::OfflineIntegrityFailure::StorageUnavailable)?;
    let inspection =
        Catalog::reserve_offline_integrity_inspection(&authority, claim).map_err(|failure| {
            match failure.code() {
                positron_kernel::CatalogFailureCode::ResourceAdmissionRefused
                | positron_kernel::CatalogFailureCode::LimitExceeded => {
                    crate::OfflineIntegrityFailure::CapacityUnavailable
                },
                _ => crate::OfflineIntegrityFailure::StorageUnavailable,
            }
        })?;
    let resource_snapshot = inspection
        .authority()
        .governor()
        .inspect()
        .map_err(|_| crate::OfflineIntegrityFailure::StorageUnavailable)?;
    let snapshot = inspection
        .read_current_snapshot(
            record.instance,
            key.catalog_secret(record.instance)
                .map_err(|_| crate::OfflineIntegrityFailure::KeyUnavailable)?,
        )
        .map_err(|failure| match failure.code() {
            positron_kernel::CatalogFailureCode::StorageUnavailable => {
                crate::OfflineIntegrityFailure::StorageUnavailable
            },
            positron_kernel::CatalogFailureCode::ConcurrentWriter => {
                crate::OfflineIntegrityFailure::CatalogUnavailable
            },
            positron_kernel::CatalogFailureCode::LimitExceeded
            | positron_kernel::CatalogFailureCode::ResourceAdmissionRefused => {
                crate::OfflineIntegrityFailure::CapacityUnavailable
            },
            _ => crate::OfflineIntegrityFailure::CorruptState,
        })?;
    if snapshot.number() == 0 {
        return Err(crate::OfflineIntegrityFailure::CorruptState);
    }
    let findings = positron_kernel::integrity_quarantine_findings(&snapshot).map_err(
        |failure| match failure.code() {
            positron_kernel::IntegrityFailureCode::FindingCapacity => {
                crate::OfflineIntegrityFailure::CapacityUnavailable
            },
            _ => crate::OfflineIntegrityFailure::CorruptState,
        },
    )?;
    let backup_repository =
        crate::BackupRepositoryInspection::from_authenticated_catalog(&snapshot)
            .map_err(|_| crate::OfflineIntegrityFailure::CorruptState)?;
    let identity =
        Identity::open(&snapshot).map_err(|_| crate::OfflineIntegrityFailure::CorruptState)?;
    let tenants = TenantAdministration::registered_tenant_ids(&snapshot)
        .map_err(|_| crate::OfflineIntegrityFailure::CorruptState)?;
    let mut verified_envelope_count = 0_usize;
    for tenant in &tenants {
        let envelope = identity
            .tenant_key_envelope(*tenant)
            .map_err(|_| crate::OfflineIntegrityFailure::KeyUnavailable)?;
        // This custody check derives an opaque key from each persisted tenant
        // envelope. Every ledger-specific binding is verified below.
        let shard = positron_domain::routing::VirtualShardId::new(1)
            .map_err(|_| crate::OfflineIntegrityFailure::CorruptState)?;
        let scope = positron_kernel::SegmentScope::new(*tenant, SignalKind::Logs, shard);
        let _ = key
            .segment_key_from_tenant_envelope(record.instance, scope, envelope)
            .map_err(|_| crate::OfflineIntegrityFailure::KeyUnavailable)?;
        verified_envelope_count = verified_envelope_count
            .checked_add(1)
            .ok_or(crate::OfflineIntegrityFailure::CapacityUnavailable)?;
    }
    let mut scopes = Vec::new();
    for tenant in &tenants {
        for signal in [SignalKind::Logs, SignalKind::Traces] {
            let found = snapshot
                .reachable_ledger_scopes(*tenant, signal)
                .map_err(|_| crate::OfflineIntegrityFailure::CorruptState)?;
            scopes
                .try_reserve(found.len())
                .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?;
            scopes.extend(found);
        }
    }
    let resuming = resume.is_some();
    if selected_scope.is_some() && resuming {
        return Err(crate::OfflineIntegrityFailure::CorruptState);
    }
    let reachable_scope_count = scopes.len();
    let OfflineIntegrityContinuationState {
        mode,
        mut scope_index,
        covered: mut covered_scope_count,
        verified: mut verified_scope_count,
        fenced: mut fenced_scope_count,
        mut all_verified,
        mut examined_segments,
        mut examined_bytes,
        mut omitted_segments,
        mut aggregate_evidence,
        cursor: mut resume_cursor,
    } = if let Some(token) = resume {
        let decoded = key
            .open_object(
                record.instance,
                BootstrapObjectPurpose::Initialized,
                token.encoded(),
            )
            .map_err(|_| crate::OfflineIntegrityFailure::CorruptState)?;
        decode_offline_integrity_continuation(&decoded, snapshot.number())?
    } else {
        OfflineIntegrityContinuationState {
            mode: selected_scope.map_or(OfflineIntegrityContinuationMode::Aggregate, |scope| {
                OfflineIntegrityContinuationMode::Scope(scope)
            }),
            scope_index: 0,
            covered: 0,
            verified: 0,
            fenced: 0,
            all_verified: true,
            examined_segments: 0,
            examined_bytes: 0,
            omitted_segments: 0,
            aggregate_evidence: Vec::new(),
            cursor: None,
        }
    };
    let report_scope = match mode {
        OfflineIntegrityContinuationMode::Aggregate => {
            crate::OfflineIntegrityReportScope::AllReachable
        },
        OfflineIntegrityContinuationMode::Scope(_) => {
            crate::OfflineIntegrityReportScope::SelectedScope
        },
    };
    let aggregate = matches!(mode, OfflineIntegrityContinuationMode::Aggregate);
    if aggregate && (scope_index > scopes.len() || covered_scope_count > scopes.len()) {
        return Err(crate::OfflineIntegrityFailure::CorruptState);
    }
    if let OfflineIntegrityContinuationMode::Scope(scope) = mode {
        if !scopes.contains(&scope) {
            return Err(crate::OfflineIntegrityFailure::CorruptState);
        }
        let target_index = scopes
            .iter()
            .position(|candidate| *candidate == scope)
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
        if resuming {
            if scope_index != target_index || covered_scope_count > 1 || verified_scope_count > 1 {
                return Err(crate::OfflineIntegrityFailure::CorruptState);
            }
        } else {
            scope_index = target_index;
            covered_scope_count = 0;
            verified_scope_count = 0;
            all_verified = true;
            resume_cursor = None;
        }
    }
    let mut reports = Vec::new();
    let mut remaining_segments = IntegrityScrubBudget::MAX_SEGMENTS;
    let mut remaining_bytes = IntegrityScrubBudget::MAX_BYTES;
    let mut incomplete_scope_count = 0_usize;
    while let Some(scope) = scopes.get(scope_index).copied() {
        if remaining_segments == 0 || remaining_bytes == 0 {
            break;
        }
        let envelope = identity
            .tenant_key_envelope(scope.tenant_id())
            .map_err(|_| crate::OfflineIntegrityFailure::KeyUnavailable)?;
        let protection = key
            .segment_key_from_tenant_envelope(record.instance, scope, envelope)
            .map_err(|_| crate::OfflineIntegrityFailure::KeyUnavailable)?;
        let report = ActiveSegmentLedger::verify_snapshot_integrity(
            &authority,
            &snapshot,
            record.instance,
            IntegrityVerificationRequest::new(
                scope,
                protection,
                IntegrityScrubBudget::with_bytes(remaining_segments, remaining_bytes)
                    .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?,
                cancellation,
                TransactionId::new([0xf1; 16])
                    .map_err(|_| crate::OfflineIntegrityFailure::CorruptState)?,
                resume_cursor,
            ),
        )
        .map_err(|failure| match failure.code() {
            positron_kernel::IntegrityFailureCode::StorageUnavailable => {
                crate::OfflineIntegrityFailure::StorageUnavailable
            },
            positron_kernel::IntegrityFailureCode::Cancelled
            | positron_kernel::IntegrityFailureCode::InvalidInput
            | positron_kernel::IntegrityFailureCode::DurabilityFrontierAmbiguity
            | positron_kernel::IntegrityFailureCode::AmbiguousIntegrity
            | positron_kernel::IntegrityFailureCode::FindingCapacity => {
                crate::OfflineIntegrityFailure::CorruptState
            },
        })?;
        remaining_segments = remaining_segments.saturating_sub(report.examined_segments());
        remaining_bytes = remaining_bytes.saturating_sub(report.examined_bytes());
        let outcome = report.outcome();
        examined_segments = examined_segments
            .checked_add(
                u64::try_from(report.examined_segments())
                    .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?,
            )
            .ok_or(crate::OfflineIntegrityFailure::CapacityUnavailable)?;
        examined_bytes = examined_bytes
            .checked_add(report.examined_bytes())
            .ok_or(crate::OfflineIntegrityFailure::CapacityUnavailable)?;
        omitted_segments = omitted_segments
            .checked_add(
                u64::try_from(report.omitted_segments())
                    .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?,
            )
            .ok_or(crate::OfflineIntegrityFailure::CapacityUnavailable)?;
        let resumable_scope = report.continuation().is_some();
        let retained_localization = aggregate_evidence.last().is_some_and(|evidence| {
            evidence.scope() == scope
                && evidence.outcome() == positron_kernel::IntegrityVerificationOutcome::Quarantined
        });
        reports
            .try_reserve(1)
            .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?;
        reports.push(report);
        if outcome == positron_kernel::IntegrityVerificationOutcome::Incomplete || resumable_scope {
            incomplete_scope_count = 1;
            if outcome == positron_kernel::IntegrityVerificationOutcome::Quarantined
                && !retained_localization
            {
                if aggregate_evidence.len() == MAX_OFFLINE_AGGREGATE_EVIDENCE {
                    return Err(crate::OfflineIntegrityFailure::CapacityUnavailable);
                }
                aggregate_evidence
                    .try_reserve(1)
                    .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?;
                aggregate_evidence.push(crate::OfflineIntegrityEvidence::from_report(report));
            }
            resume_cursor = reports.last().and_then(|report| report.continuation());
            break;
        }
        let evidence = crate::OfflineIntegrityEvidence::from_report(report);
        let terminal_outcome = if retained_localization
            && outcome == positron_kernel::IntegrityVerificationOutcome::Verified
        {
            positron_kernel::IntegrityVerificationOutcome::Quarantined
        } else {
            outcome
        };
        if retained_localization {
            if outcome != positron_kernel::IntegrityVerificationOutcome::Verified {
                let prior = aggregate_evidence
                    .last_mut()
                    .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
                *prior = evidence;
            }
        } else {
            if aggregate_evidence.len() == MAX_OFFLINE_AGGREGATE_EVIDENCE {
                return Err(crate::OfflineIntegrityFailure::CapacityUnavailable);
            }
            aggregate_evidence
                .try_reserve(1)
                .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?;
            aggregate_evidence.push(evidence);
        }
        covered_scope_count = covered_scope_count
            .checked_add(1)
            .ok_or(crate::OfflineIntegrityFailure::CapacityUnavailable)?;
        if terminal_outcome == positron_kernel::IntegrityVerificationOutcome::Verified {
            verified_scope_count = verified_scope_count
                .checked_add(1)
                .ok_or(crate::OfflineIntegrityFailure::CapacityUnavailable)?;
        } else {
            all_verified = false;
            if terminal_outcome == positron_kernel::IntegrityVerificationOutcome::Fenced {
                fenced_scope_count = fenced_scope_count
                    .checked_add(1)
                    .ok_or(crate::OfflineIntegrityFailure::CapacityUnavailable)?;
            }
        }
        scope_index = scope_index
            .checked_add(1)
            .ok_or(crate::OfflineIntegrityFailure::CapacityUnavailable)?;
        resume_cursor = None;
        if !aggregate {
            break;
        }
    }
    let disk_pressure = match resource_snapshot.disk_pressure() {
        positron_kernel::DiskPressureState::Healthy => crate::OfflineDiskPressure::Healthy,
        positron_kernel::DiskPressureState::SoftPressure => crate::OfflineDiskPressure::Soft,
        positron_kernel::DiskPressureState::HardPressure => crate::OfflineDiskPressure::Hard,
    };
    let facts = crate::OfflineInspectionFacts {
        catalog_generation: snapshot.number(),
        registered_tenant_count: tenants.len(),
        reachable_scope_count,
        verified_envelope_count,
        quarantine_finding_count: findings.len(),
        verified_scope_count,
        fenced_scope_count,
        incomplete_scope_count,
        usable_disk_bytes: resource_snapshot.usable_disk_bytes(),
        disk_pressure,
        backup_repository,
    };
    let needs_continuation = if aggregate {
        covered_scope_count < reachable_scope_count
    } else {
        resume_cursor.is_some()
    };
    let continuation = if needs_continuation {
        let encoded = encode_offline_integrity_continuation(
            snapshot.number(),
            OfflineIntegrityContinuationState {
                mode,
                scope_index,
                covered: covered_scope_count,
                verified: verified_scope_count,
                fenced: fenced_scope_count,
                all_verified,
                examined_segments,
                examined_bytes,
                omitted_segments,
                aggregate_evidence: aggregate_evidence.clone(),
                cursor: resume_cursor,
            },
        )?;
        let protected = key
            .protect(
                record.instance,
                BootstrapObjectPurpose::Initialized,
                &encoded,
            )
            .map_err(|_| crate::OfflineIntegrityFailure::CorruptState)?;
        Some(
            crate::OfflineIntegrityContinuation::from_encoded(protected)
                .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?,
        )
    } else {
        None
    };
    Ok(crate::OfflineIntegrityVerification {
        reports,
        findings,
        facts,
        report_scope,
        continuation,
        covered_scope_count,
        all_covered_scopes_verified: all_verified,
        examined_segments,
        examined_bytes,
        omitted_segments,
        aggregate_evidence,
    })
}

// The canonical scope manifest admits at most 1,024 scopes. Its complete
// terminal account is encoded in the protected continuation (62 bytes each),
// remaining below the 64 KiB continuation limit without silently reducing a
// valid manifest to a partial success claim.

pub(in super::super) fn offline_integrity_claim()
-> Result<positron_kernel::WorkClaim, crate::OfflineIntegrityFailure> {
    positron_kernel::WorkClaim::system_diagnostics(positron_kernel::integrity_scrub_resource_claim())
    .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)
}
