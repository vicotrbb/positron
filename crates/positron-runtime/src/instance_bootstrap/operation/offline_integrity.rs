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
            all_verified = false;
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
const OFFLINE_EVIDENCE_BYTES: usize = 62;
const LEGACY_LOCALIZED_OBSERVATION_BYTES: usize = 87;
const MAX_LEGACY_LOCALIZED_OBSERVATIONS: usize = 16;
const CURSOR_BYTES: usize = 56;

fn legacy_localized_observations_end(
    encoded: &[u8],
    offset: usize,
) -> Result<usize, crate::OfflineIntegrityFailure> {
    let count = encoded
        .get(offset)
        .copied()
        .map(usize::from)
        .filter(|count| *count <= MAX_LEGACY_LOCALIZED_OBSERVATIONS)
        .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
    let start = offset
        .checked_add(1)
        .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
    let bytes = count
        .checked_mul(LEGACY_LOCALIZED_OBSERVATION_BYTES)
        .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
    let end = start
        .checked_add(bytes)
        .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
    for index in 0..count {
        let observation_start = start
            .checked_add(
                index
                    .checked_mul(LEGACY_LOCALIZED_OBSERVATION_BYTES)
                    .ok_or(crate::OfflineIntegrityFailure::CorruptState)?,
            )
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
        let observation_end = observation_start
            .checked_add(LEGACY_LOCALIZED_OBSERVATION_BYTES)
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
        let observation = encoded
            .get(observation_start..observation_end)
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
        observation
            .get(0..16)
            .and_then(|value| value.try_into().ok())
            .and_then(|value| positron_domain::identity::TenantId::from_bytes(value).ok())
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
        match observation.get(16) {
            Some(1 | 2) => {},
            _ => return Err(crate::OfflineIntegrityFailure::CorruptState),
        }
        observation
            .get(17..21)
            .and_then(|value| value.try_into().ok())
            .map(u32::from_be_bytes)
            .and_then(|value| positron_domain::routing::VirtualShardId::new(value).ok())
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
        observation
            .get(21..37)
            .and_then(|value| value.try_into().ok())
            .and_then(|value| positron_kernel::SegmentId::from_bytes(value).ok())
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
        let signed = |range: std::ops::Range<usize>| {
            observation
                .get(range)
                .and_then(|value| value.try_into().ok())
                .map(i64::from_be_bytes)
                .ok_or(crate::OfflineIntegrityFailure::CorruptState)
        };
        match observation.get(53) {
            Some(1) => {
                let _ = signed(54..62)?;
                let _ = signed(62..70)?;
            },
            Some(2..=4) => {},
            _ => return Err(crate::OfflineIntegrityFailure::CorruptState),
        }
        match observation.get(70) {
            Some(1) => {
                let _ = signed(71..79)?;
                let _ = signed(79..87)?;
            },
            Some(2) => {},
            _ => return Err(crate::OfflineIntegrityFailure::CorruptState),
        }
    }
    Ok(end)
}

fn continuation_plaintext_len(
    mode: OfflineIntegrityContinuationMode,
    evidence_count: usize,
    has_cursor: bool,
) -> Result<usize, crate::OfflineIntegrityFailure> {
    let mode_bytes = match mode {
        OfflineIntegrityContinuationMode::Aggregate => 10_usize,
        OfflineIntegrityContinuationMode::Scope(_) => 31,
    };
    let evidence_bytes = evidence_count
        .checked_mul(OFFLINE_EVIDENCE_BYTES)
        .ok_or(crate::OfflineIntegrityFailure::CapacityUnavailable)?;
    mode_bytes
        .checked_add(8 + 1 + 24 + 2)
        .and_then(|bytes| bytes.checked_add(evidence_bytes))
        .and_then(|bytes| bytes.checked_add(1)) // v5 zero historical localizations
        .and_then(|bytes| bytes.checked_add(if has_cursor { 1 + CURSOR_BYTES } else { 1 }))
        .ok_or(crate::OfflineIntegrityFailure::CapacityUnavailable)
}

fn encode_offline_integrity_continuation(
    generation: u64,
    state: OfflineIntegrityContinuationState,
) -> Result<Vec<u8>, crate::OfflineIntegrityFailure> {
    if state.aggregate_evidence.len() > MAX_OFFLINE_AGGREGATE_EVIDENCE {
        return Err(crate::OfflineIntegrityFailure::CapacityUnavailable);
    }
    let required = continuation_plaintext_len(
        state.mode,
        state.aggregate_evidence.len(),
        state.cursor.is_some(),
    )?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(required)
        .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?;
    encoded.push(5);
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
    encoded.push(0); // v5 carries no historical raw localizations.
    if let Some(cursor) = state.cursor {
        encoded.push(1);
        encoded.extend_from_slice(&cursor.encode());
    } else {
        encoded.push(0);
    }
    if encoded.len() != required {
        return Err(crate::OfflineIntegrityFailure::CorruptState);
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
    let version = encoded
        .first()
        .copied()
        .filter(|version| matches!(version, 4 | 5))
        .filter(|_| encoded.get(1..9) == Some(generation.to_be_bytes().as_slice()))
        .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
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
    let evidence_end = evidence_offset
        .checked_add(
            evidence_count
                .checked_mul(OFFLINE_EVIDENCE_BYTES)
                .ok_or(crate::OfflineIntegrityFailure::CorruptState)?,
        )
        .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
    let mut aggregate_evidence = Vec::new();
    aggregate_evidence
        .try_reserve(evidence_count)
        .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?;
    for index in 0..evidence_count {
        let start = evidence_offset + index * OFFLINE_EVIDENCE_BYTES;
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
            .get(start + 30..start + OFFLINE_EVIDENCE_BYTES)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
        aggregate_evidence.push(crate::OfflineIntegrityEvidence::from_parts(
            positron_kernel::SegmentScope::new(tenant, signal, shard),
            evidence_generation,
            outcome,
            checksum,
        ));
    }
    let cursor_offset = if version == 5 {
        legacy_localized_observations_end(encoded, evidence_end)?
    } else {
        evidence_end
    };
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

#[cfg(test)]
mod continuation_codec_tests {
    use super::*;

    fn state(
        evidence: Vec<crate::OfflineIntegrityEvidence>,
        cursor: Option<positron_kernel::IntegrityScrubContinuation>,
    ) -> OfflineIntegrityContinuationState {
        OfflineIntegrityContinuationState {
            mode: OfflineIntegrityContinuationMode::Aggregate,
            scope_index: 0,
            covered: 0,
            verified: 0,
            fenced: 0,
            all_verified: false,
            examined_segments: 0,
            examined_bytes: 0,
            omitted_segments: 0,
            aggregate_evidence: evidence,
            cursor,
        }
    }

    fn legacy_observation() -> [u8; LEGACY_LOCALIZED_OBSERVATION_BYTES] {
        let mut observation = [0_u8; LEGACY_LOCALIZED_OBSERVATION_BYTES];
        observation[0..16].copy_from_slice(&[0x41; 16]);
        observation[16] = 1;
        observation[17..21].copy_from_slice(&1_u32.to_be_bytes());
        observation[21..37].copy_from_slice(&[1; 16]);
        observation[53] = 1;
        observation[70] = 1;
        observation
    }

    #[test]
    fn v4_continuation_without_retained_localizations_remains_decodable() {
        let mut encoded = vec![4];
        encoded.extend_from_slice(&7_u64.to_be_bytes());
        encoded.push(0);
        encoded.extend_from_slice(&[0; 8]);
        encoded.push(0);
        encoded.extend_from_slice(&[0; 24]);
        encoded.extend_from_slice(&[0; 2]);
        encoded.push(0);
        let decoded = decode_offline_integrity_continuation(&encoded, 7)
            .expect("v4 continuation remains supported");
        assert!(decoded.aggregate_evidence.is_empty());
        assert!(decoded.cursor.is_none());
    }

    #[test]
    fn v5_legacy_localizations_are_validated_then_omitted_from_new_state() {
        let mut encoded = encode_offline_integrity_continuation(7, state(Vec::new(), None))
            .expect("v5 continuation must encode");
        assert_eq!(encoded.pop(), Some(0), "legacy cursor tag");
        assert_eq!(encoded.pop(), Some(0), "new v5 observation count");
        encoded.push(1);
        encoded.extend_from_slice(&legacy_observation());
        encoded.push(0);
        let decoded = decode_offline_integrity_continuation(&encoded, 7)
            .expect("legacy localization must remain resumable");
        assert!(decoded.aggregate_evidence.is_empty());
        assert!(decoded.cursor.is_none());

        let mut malformed = encoded;
        malformed[62] = 9;
        assert!(
            matches!(
                decode_offline_integrity_continuation(&malformed, 7),
                Err(crate::OfflineIntegrityFailure::CorruptState)
            ),
            "legacy payload structure remains fail closed"
        );
    }

    #[test]
    fn continuation_reserves_the_full_aggregate_account_before_encoding() {
        let tenant = positron_domain::identity::TenantId::from_bytes([0x41; 16])
            .expect("nonzero test tenant");
        let mut evidence = Vec::new();
        evidence
            .try_reserve_exact(MAX_OFFLINE_AGGREGATE_EVIDENCE)
            .expect("test allocation");
        for shard in 1..=u32::try_from(MAX_OFFLINE_AGGREGATE_EVIDENCE).expect("scope bound") {
            let scope = positron_kernel::SegmentScope::new(
                tenant,
                positron_domain::routing::SignalKind::Logs,
                positron_domain::routing::VirtualShardId::new(shard).expect("test shard"),
            );
            evidence.push(crate::OfflineIntegrityEvidence::from_parts(
                scope,
                7,
                positron_kernel::IntegrityVerificationOutcome::Verified,
                [0x5a; 32],
            ));
        }
        let plaintext = continuation_plaintext_len(
            OfflineIntegrityContinuationMode::Aggregate,
            evidence.len(),
            true,
        )
        .expect("bounded aggregate plus cursor");
        assert_eq!(plaintext, 63_591);
        let mut cursor_bytes = [0_u8; CURSOR_BYTES];
        cursor_bytes[0] = 1;
        cursor_bytes[8..40].copy_from_slice(&[0x32; 32]);
        cursor_bytes[40..].copy_from_slice(&[0x51; 16]);
        let cursor = positron_kernel::IntegrityScrubContinuation::decode(&cursor_bytes)
            .expect("valid source-bound cursor");
        let encoded = encode_offline_integrity_continuation(7, state(evidence, Some(cursor)))
            .expect("full aggregate with cursor must encode");
        assert_eq!(encoded.len(), plaintext);

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "positron-offline-continuation-bound-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(root.join("data")).expect("create data root");
        std::fs::create_dir_all(root.join("secrets")).expect("create secrets root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.join("secrets"), std::fs::Permissions::from_mode(0o700))
                .expect("protect secrets root");
        }
        let paths = crate::BootstrapPaths::new(
            &root.join("data"),
            &root.join("secrets"),
            positron_kernel::MountQualification::LocalHost,
        )
        .expect("bootstrap paths");
        crate::InstanceBootstrap::initialize(&paths, crate::InitializationPlan::non_interactive())
            .expect("initialize protected continuation fixture");
        let instance = crate::InstanceBootstrap::reopen(&paths).expect("reopen fixture");
        let protected = instance
            .key
            .protect(
                instance.instance,
                positron_kernel::BootstrapObjectPurpose::Initialized,
                &encoded,
            )
            .expect("protect full aggregate continuation");
        assert!(
            crate::OfflineIntegrityContinuation::from_encoded(protected).is_ok(),
            "the protected 1,024-scope account with cursor remains portable"
        );
        drop(instance);
        std::fs::remove_dir_all(root).expect("remove protected continuation fixture");
        assert_eq!(
            continuation_plaintext_len(
                OfflineIntegrityContinuationMode::Aggregate,
                usize::MAX,
                true,
            ),
            Err(crate::OfflineIntegrityFailure::CapacityUnavailable),
            "overflow is an explicit availability failure"
        );
    }
}
