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
        localized_observations: mut retained_localized_observations,
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
            localized_observations: Vec::new(),
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
        if let Some(finding) = report.localized_finding() {
            if retained_localized_observations.len() == MAX_OFFLINE_LOCALIZED_OBSERVATIONS {
                return Err(crate::OfflineIntegrityFailure::CapacityUnavailable);
            }
            retained_localized_observations
                .try_reserve(1)
                .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?;
            retained_localized_observations.push(crate::OfflineLocalizedObservation::from(finding));
        }
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
                localized_observations: retained_localized_observations.clone(),
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
        retained_localized_observations,
    ))
}

// The canonical scope manifest admits at most 1,024 scopes. Its complete
// terminal account is encoded in the protected continuation (62 bytes each),
// remaining below the 64 KiB continuation limit without silently reducing a
// valid manifest to a partial success claim.
const MAX_OFFLINE_AGGREGATE_EVIDENCE: usize = 1_024;
const LOCALIZED_OBSERVATION_BYTES: usize = 87;
const MAX_OFFLINE_LOCALIZED_OBSERVATIONS: usize = 16;

fn encode_localized_observations(
    encoded: &mut Vec<u8>,
    observations: &[crate::OfflineLocalizedObservation],
) -> Result<(), crate::OfflineIntegrityFailure> {
    if observations.len() > MAX_OFFLINE_LOCALIZED_OBSERVATIONS {
        return Err(crate::OfflineIntegrityFailure::CapacityUnavailable);
    }
    encoded.push(
        u8::try_from(observations.len())
            .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?,
    );
    for observation in observations {
        let scope = observation.scope();
        encoded.extend_from_slice(&scope.tenant_id().to_bytes());
        encoded.push(match scope.signal_kind() {
            positron_domain::routing::SignalKind::Logs => 1,
            positron_domain::routing::SignalKind::Traces => 2,
        });
        encoded.extend_from_slice(&scope.shard_id().value().to_be_bytes());
        encoded.extend_from_slice(&observation.segment().to_bytes());
        encoded.extend_from_slice(&observation.base_position().to_be_bytes());
        encoded.extend_from_slice(&observation.sealed_frontier().to_be_bytes());
        match observation.event_range() {
            crate::OfflineEventRange::Known { earliest, latest } => {
                encoded.push(1);
                encoded.extend_from_slice(&earliest.to_be_bytes());
                encoded.extend_from_slice(&latest.to_be_bytes());
            },
            crate::OfflineEventRange::MissingSourceTime => encoded.push(2),
            crate::OfflineEventRange::InvalidSourceTime => encoded.push(3),
            crate::OfflineEventRange::LegacyFormat => encoded.push(4),
        }
        match observation.ingest_range() {
            crate::OfflineIngestRange::Known { earliest, latest } => {
                encoded.push(1);
                encoded.extend_from_slice(&earliest.to_be_bytes());
                encoded.extend_from_slice(&latest.to_be_bytes());
            },
            crate::OfflineIngestRange::Unavailable => encoded.push(2),
        }
    }
    Ok(())
}

fn decode_localized_observations(
    encoded: &[u8],
    offset: usize,
) -> Result<(Vec<crate::OfflineLocalizedObservation>, usize), crate::OfflineIntegrityFailure> {
    let count = encoded
        .get(offset)
        .copied()
        .map(usize::from)
        .filter(|count| *count <= MAX_OFFLINE_LOCALIZED_OBSERVATIONS)
        .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
    let mut observations = Vec::new();
    observations
        .try_reserve(count)
        .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?;
    let mut start = offset + 1;
    for _ in 0..count {
        let end = start
            .checked_add(LOCALIZED_OBSERVATION_BYTES)
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
        let bytes = encoded
            .get(start..end)
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
        let tenant = bytes
            .get(0..16)
            .and_then(|value| value.try_into().ok())
            .and_then(|value| positron_domain::identity::TenantId::from_bytes(value).ok())
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
        let signal = match bytes.get(16) {
            Some(1) => positron_domain::routing::SignalKind::Logs,
            Some(2) => positron_domain::routing::SignalKind::Traces,
            _ => return Err(crate::OfflineIntegrityFailure::CorruptState),
        };
        let shard = bytes
            .get(17..21)
            .and_then(|value| value.try_into().ok())
            .map(u32::from_be_bytes)
            .and_then(|value| positron_domain::routing::VirtualShardId::new(value).ok())
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
        let scope = positron_kernel::SegmentScope::new(tenant, signal, shard);
        let segment = bytes
            .get(21..37)
            .and_then(|value| value.try_into().ok())
            .and_then(|value| positron_kernel::SegmentId::from_bytes(value).ok())
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
        let number = |range: std::ops::Range<usize>| {
            bytes
                .get(range)
                .and_then(|value| value.try_into().ok())
                .map(u64::from_be_bytes)
                .ok_or(crate::OfflineIntegrityFailure::CorruptState)
        };
        let base_position = number(37..45)?;
        let sealed_frontier = number(45..53)?;
        let signed = |range: std::ops::Range<usize>| {
            bytes
                .get(range)
                .and_then(|value| value.try_into().ok())
                .map(i64::from_be_bytes)
                .ok_or(crate::OfflineIntegrityFailure::CorruptState)
        };
        let event_range = match bytes.get(53) {
            Some(1) => crate::OfflineEventRange::Known {
                earliest: signed(54..62)?,
                latest: signed(62..70)?,
            },
            Some(2) => crate::OfflineEventRange::MissingSourceTime,
            Some(3) => crate::OfflineEventRange::InvalidSourceTime,
            Some(4) => crate::OfflineEventRange::LegacyFormat,
            _ => return Err(crate::OfflineIntegrityFailure::CorruptState),
        };
        let ingest_range = match bytes.get(70) {
            Some(1) => crate::OfflineIngestRange::Known {
                earliest: signed(71..79)?,
                latest: signed(79..87)?,
            },
            Some(2) => crate::OfflineIngestRange::Unavailable,
            _ => return Err(crate::OfflineIntegrityFailure::CorruptState),
        };
        observations.push(crate::OfflineLocalizedObservation {
            scope,
            segment,
            base_position,
            sealed_frontier,
            event_range,
            ingest_range,
        });
        start = end;
    }
    Ok((observations, start))
}

fn encode_offline_integrity_continuation(
    generation: u64,
    state: OfflineIntegrityContinuationState,
) -> Result<Vec<u8>, crate::OfflineIntegrityFailure> {
    if state.aggregate_evidence.len() > MAX_OFFLINE_AGGREGATE_EVIDENCE {
        return Err(crate::OfflineIntegrityFailure::CapacityUnavailable);
    }
    let mut encoded = Vec::with_capacity(16_384);
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
    encode_localized_observations(&mut encoded, &state.localized_observations)?;
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
    localized_observations: Vec<crate::OfflineLocalizedObservation>,
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
    let (localized_observations, cursor_offset) = if version == 5 {
        decode_localized_observations(encoded, evidence_end)?
    } else {
        (Vec::new(), evidence_end)
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
        localized_observations,
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

    fn observation(index: u8) -> crate::OfflineLocalizedObservation {
        let tenant = positron_domain::identity::TenantId::from_bytes([0x41; 16])
            .expect("nonzero test tenant");
        let scope = positron_kernel::SegmentScope::new(
            tenant,
            positron_domain::routing::SignalKind::Logs,
            positron_domain::routing::VirtualShardId::new(1).expect("test shard"),
        );
        crate::OfflineLocalizedObservation {
            scope,
            segment: positron_kernel::SegmentId::from_bytes([index; 16])
                .expect("nonzero test segment"),
            base_position: u64::from(index),
            sealed_frontier: u64::from(index) + 1,
            event_range: crate::OfflineEventRange::Known {
                earliest: i64::from(index),
                latest: i64::from(index) + 1,
            },
            ingest_range: crate::OfflineIngestRange::Known {
                earliest: i64::from(index) + 2,
                latest: i64::from(index) + 3,
            },
        }
    }

    fn state(
        observations: Vec<crate::OfflineLocalizedObservation>,
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
            aggregate_evidence: Vec::new(),
            localized_observations: observations,
            cursor: None,
        }
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
        assert!(decoded.localized_observations.is_empty());
        assert!(decoded.cursor.is_none());
    }

    #[test]
    fn retained_localizations_are_bounded_and_authenticated_in_the_continuation() {
        let observations = (1_u8..=MAX_OFFLINE_LOCALIZED_OBSERVATIONS as u8)
            .map(observation)
            .collect::<Vec<_>>();
        let encoded = encode_offline_integrity_continuation(7, state(observations.clone()))
            .expect("the bounded continuation must encode");
        assert!(
            encoded.len() <= crate::OfflineIntegrityContinuation::MAX_ENCODED_BYTES,
            "the canonical limit includes every retained observation"
        );
        let decoded = decode_offline_integrity_continuation(&encoded, 7)
            .expect("the continuation must decode");
        assert_eq!(decoded.localized_observations, observations);

        let excess = (1_u8..=MAX_OFFLINE_LOCALIZED_OBSERVATIONS as u8 + 1)
            .map(observation)
            .collect::<Vec<_>>();
        assert_eq!(
            encode_offline_integrity_continuation(7, state(excess)),
            Err(crate::OfflineIntegrityFailure::CapacityUnavailable),
            "a seventeenth observation must fail rather than being silently dropped"
        );
    }
}
