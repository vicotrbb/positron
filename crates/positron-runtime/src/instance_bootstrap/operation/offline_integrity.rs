use positron_governance::{Identity, TenantAdministration};
use positron_kernel::{BootstrapArtifact, BootstrapObjectPurpose, Catalog};

use super::super::{BootstrapPaths, BootstrapState, resources, storage};
use super::support::{decode_record, require_key_identity};

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
        ActiveSegmentLedger, IntegrityScrubBudget, IntegrityVerificationMode, TransactionId,
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
            scope,
            protection,
            IntegrityVerificationMode::Offline,
            IntegrityScrubBudget::with_bytes(remaining_segments, remaining_bytes)
                .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?,
            cancellation,
            TransactionId::new([0xf1; 16])
                .map_err(|_| crate::OfflineIntegrityFailure::CorruptState)?,
            resume_cursor,
        )
        .map_err(|failure| match failure.code() {
            positron_kernel::IntegrityFailureCode::StorageUnavailable => {
                crate::OfflineIntegrityFailure::StorageUnavailable
            },
            positron_kernel::IntegrityFailureCode::Cancelled
            | positron_kernel::IntegrityFailureCode::InvalidInput
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
        reports
            .try_reserve(1)
            .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?;
        reports.push(report);
        if outcome == positron_kernel::IntegrityVerificationOutcome::Incomplete {
            incomplete_scope_count = 1;
            resume_cursor = reports.last().and_then(|report| report.continuation());
            break;
        }
        if aggregate_evidence.len() == MAX_OFFLINE_AGGREGATE_EVIDENCE {
            return Err(crate::OfflineIntegrityFailure::CapacityUnavailable);
        }
        aggregate_evidence
            .try_reserve(1)
            .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?;
        aggregate_evidence.push(crate::OfflineIntegrityEvidence::from_report(report));
        covered_scope_count = covered_scope_count
            .checked_add(1)
            .ok_or(crate::OfflineIntegrityFailure::CapacityUnavailable)?;
        if outcome == positron_kernel::IntegrityVerificationOutcome::Verified {
            verified_scope_count = verified_scope_count
                .checked_add(1)
                .ok_or(crate::OfflineIntegrityFailure::CapacityUnavailable)?;
        } else {
            all_verified = false;
            if outcome == positron_kernel::IntegrityVerificationOutcome::Fenced {
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
    let facts = crate::OfflineInspectionFacts::new(
        snapshot.number(),
        tenants.len(),
        reachable_scope_count,
        verified_envelope_count,
        findings.len(),
        verified_scope_count,
        fenced_scope_count,
        incomplete_scope_count,
        resource_snapshot.usable_disk_bytes(),
        disk_pressure,
        backup_repository,
    );
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
        Some(crate::OfflineIntegrityContinuation(
            key.protect(
                record.instance,
                BootstrapObjectPurpose::Initialized,
                &encoded,
            )
            .map_err(|_| crate::OfflineIntegrityFailure::CorruptState)?,
        ))
    } else {
        None
    };
    Ok(crate::OfflineIntegrityVerification::new(
        reports,
        findings,
        facts,
        continuation,
        covered_scope_count,
        all_verified,
        examined_segments,
        examined_bytes,
        omitted_segments,
        aggregate_evidence,
    ))
}

// The canonical scope manifest admits at most 1,024 scopes. Its complete
// terminal account is encoded in the protected continuation (62 bytes each),
// remaining below the 64 KiB continuation limit without silently reducing a
// valid manifest to a partial success claim.
const MAX_OFFLINE_AGGREGATE_EVIDENCE: usize = 1_024;

fn encode_offline_integrity_continuation(
    generation: u64,
    state: OfflineIntegrityContinuationState,
) -> Result<Vec<u8>, crate::OfflineIntegrityFailure> {
    if state.aggregate_evidence.len() > MAX_OFFLINE_AGGREGATE_EVIDENCE {
        return Err(crate::OfflineIntegrityFailure::CapacityUnavailable);
    }
    let mut encoded = Vec::with_capacity(16_384);
    encoded.push(4);
    encoded.extend_from_slice(&generation.to_be_bytes());
    match state.mode {
        OfflineIntegrityContinuationMode::Aggregate => encoded.push(0),
        OfflineIntegrityContinuationMode::Scope(scope) => {
            encoded.push(1);
            encoded.extend_from_slice(&scope.tenant_id().to_bytes());
            encoded.push(match scope.signal_kind() {
                positron_domain::routing::SignalKind::Logs => 1,
                positron_domain::routing::SignalKind::Traces => 2,
            });
            encoded.extend_from_slice(&scope.shard_id().value().to_be_bytes());
        },
    }
    for value in [
        state.scope_index,
        state.covered,
        state.verified,
        state.fenced,
    ] {
        encoded.extend_from_slice(
            &u16::try_from(value)
                .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?
                .to_be_bytes(),
        );
    }
    encoded.push(u8::from(state.all_verified));
    for value in [
        state.examined_segments,
        state.examined_bytes,
        state.omitted_segments,
    ] {
        encoded.extend_from_slice(&value.to_be_bytes());
    }
    encoded.extend_from_slice(
        &u16::try_from(state.aggregate_evidence.len())
            .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?
            .to_be_bytes(),
    );
    for evidence in &state.aggregate_evidence {
        let scope = evidence.scope();
        encoded.extend_from_slice(&scope.tenant_id().to_bytes());
        encoded.push(match scope.signal_kind() {
            positron_domain::routing::SignalKind::Logs => 1,
            positron_domain::routing::SignalKind::Traces => 2,
        });
        encoded.extend_from_slice(&scope.shard_id().value().to_be_bytes());
        encoded.extend_from_slice(&evidence.catalog_generation().to_be_bytes());
        encoded.push(match evidence.outcome() {
            positron_kernel::IntegrityVerificationOutcome::Verified => 1,
            positron_kernel::IntegrityVerificationOutcome::Stale => 2,
            positron_kernel::IntegrityVerificationOutcome::Quarantined => 3,
            positron_kernel::IntegrityVerificationOutcome::Fenced => 4,
            positron_kernel::IntegrityVerificationOutcome::Incomplete => {
                return Err(crate::OfflineIntegrityFailure::CorruptState);
            },
        });
        encoded.extend_from_slice(&evidence.checksum());
    }
    if let Some(cursor) = state.cursor {
        encoded.push(1);
        encoded.extend_from_slice(&cursor.encode());
    } else {
        encoded.push(0);
    }
    Ok(encoded)
}

#[derive(Clone, Copy)]
enum OfflineIntegrityContinuationMode {
    Aggregate,
    Scope(positron_kernel::SegmentScope),
}

#[derive(Clone)]
struct OfflineIntegrityContinuationState {
    mode: OfflineIntegrityContinuationMode,
    scope_index: usize,
    covered: usize,
    verified: usize,
    fenced: usize,
    all_verified: bool,
    examined_segments: u64,
    examined_bytes: u64,
    omitted_segments: u64,
    aggregate_evidence: Vec<crate::OfflineIntegrityEvidence>,
    cursor: Option<positron_kernel::IntegrityScrubContinuation>,
}

fn decode_offline_integrity_continuation(
    encoded: &[u8],
    generation: u64,
) -> Result<OfflineIntegrityContinuationState, crate::OfflineIntegrityFailure> {
    if encoded.first() != Some(&4) || encoded.get(1..9) != Some(generation.to_be_bytes().as_slice())
    {
        return Err(crate::OfflineIntegrityFailure::CorruptState);
    }
    let (mode, offset) = match encoded.get(9) {
        Some(0) => (OfflineIntegrityContinuationMode::Aggregate, 10),
        Some(1) => {
            let tenant = encoded
                .get(10..26)
                .and_then(|bytes| bytes.try_into().ok())
                .and_then(|bytes| positron_domain::identity::TenantId::from_bytes(bytes).ok())
                .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
            let signal = match encoded.get(26) {
                Some(1) => positron_domain::routing::SignalKind::Logs,
                Some(2) => positron_domain::routing::SignalKind::Traces,
                _ => return Err(crate::OfflineIntegrityFailure::CorruptState),
            };
            let shard = encoded
                .get(27..31)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u32::from_be_bytes)
                .and_then(|value| positron_domain::routing::VirtualShardId::new(value).ok())
                .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
            (
                OfflineIntegrityContinuationMode::Scope(positron_kernel::SegmentScope::new(
                    tenant, signal, shard,
                )),
                31,
            )
        },
        _ => return Err(crate::OfflineIntegrityFailure::CorruptState),
    };
    let number = |offset| {
        encoded
            .get(offset..offset + 2)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u16::from_be_bytes)
            .map(usize::from)
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)
    };
    let scope_index = number(offset)?;
    let covered = number(offset + 2)?;
    let verified = number(offset + 4)?;
    let fenced = number(offset + 6)?;
    let all_verified = match encoded.get(offset + 8) {
        Some(0) => false,
        Some(1) => true,
        _ => return Err(crate::OfflineIntegrityFailure::CorruptState),
    };
    let aggregates_offset = offset + 9;
    let aggregate = |offset| {
        encoded
            .get(offset..offset + 8)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)
    };
    let examined_segments = aggregate(aggregates_offset)?;
    let examined_bytes = aggregate(aggregates_offset + 8)?;
    let omitted_segments = aggregate(aggregates_offset + 16)?;
    let evidence_count_offset = aggregates_offset + 24;
    let evidence_count = encoded
        .get(evidence_count_offset..evidence_count_offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_be_bytes)
        .map(usize::from)
        .filter(|count| *count <= MAX_OFFLINE_AGGREGATE_EVIDENCE)
        .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
    let evidence_offset = evidence_count_offset + 2;
    const EVIDENCE_BYTES: usize = 62;
    let evidence_end = evidence_offset
        .checked_add(
            evidence_count
                .checked_mul(EVIDENCE_BYTES)
                .ok_or(crate::OfflineIntegrityFailure::CorruptState)?,
        )
        .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
    let mut aggregate_evidence = Vec::new();
    aggregate_evidence
        .try_reserve(evidence_count)
        .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?;
    for index in 0..evidence_count {
        let start = evidence_offset + index * EVIDENCE_BYTES;
        let tenant = encoded
            .get(start..start + 16)
            .and_then(|bytes| bytes.try_into().ok())
            .and_then(|bytes| positron_domain::identity::TenantId::from_bytes(bytes).ok())
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
        let signal = match encoded.get(start + 16) {
            Some(1) => positron_domain::routing::SignalKind::Logs,
            Some(2) => positron_domain::routing::SignalKind::Traces,
            _ => return Err(crate::OfflineIntegrityFailure::CorruptState),
        };
        let shard = encoded
            .get(start + 17..start + 21)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_be_bytes)
            .and_then(|value| positron_domain::routing::VirtualShardId::new(value).ok())
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
        let evidence_generation = encoded
            .get(start + 21..start + 29)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_be_bytes)
            .filter(|value| *value == generation)
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
        let outcome = match encoded.get(start + 29) {
            Some(1) => positron_kernel::IntegrityVerificationOutcome::Verified,
            Some(2) => positron_kernel::IntegrityVerificationOutcome::Stale,
            Some(3) => positron_kernel::IntegrityVerificationOutcome::Quarantined,
            Some(4) => positron_kernel::IntegrityVerificationOutcome::Fenced,
            _ => return Err(crate::OfflineIntegrityFailure::CorruptState),
        };
        let checksum = encoded
            .get(start + 30..start + EVIDENCE_BYTES)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
        aggregate_evidence.push(crate::OfflineIntegrityEvidence::from_parts(
            positron_kernel::SegmentScope::new(tenant, signal, shard),
            evidence_generation,
            outcome,
            checksum,
        ));
    }
    let cursor_offset = evidence_end;
    let cursor = match encoded.get(cursor_offset) {
        Some(0) if encoded.len() == cursor_offset + 1 => None,
        Some(1) if encoded.len() == cursor_offset + 57 => Some(
            positron_kernel::IntegrityScrubContinuation::decode(&encoded[cursor_offset + 1..])
                .map_err(|_| crate::OfflineIntegrityFailure::CorruptState)?,
        ),
        _ => return Err(crate::OfflineIntegrityFailure::CorruptState),
    };
    Ok(OfflineIntegrityContinuationState {
        mode,
        scope_index,
        covered,
        verified,
        fenced,
        all_verified,
        examined_segments,
        examined_bytes,
        omitted_segments,
        aggregate_evidence,
        cursor,
    })
}

pub(in super::super) fn offline_integrity_claim()
-> Result<positron_kernel::WorkClaim, crate::OfflineIntegrityFailure> {
    positron_kernel::WorkClaim::system_diagnostics(positron_kernel::integrity_scrub_resource_claim())
    .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)
}
