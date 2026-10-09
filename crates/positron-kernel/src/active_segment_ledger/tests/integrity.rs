use std::error::Error;
use std::fs;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;

use super::support::{TemporaryRoot, establish_authority};
use crate::active_segment_ledger::recovery::segment_name;
use crate::{
    ActiveSegmentLedger, AuthenticatedEventRange, Catalog, CatalogIntegrityVerificationRequest,
    CatalogSecret, CommittedLedgerReader, EventRangeUnavailable, InstanceId, IntegrityCancellation,
    IntegrityFinding, IntegrityScrubBudget, IntegrityVerificationMode,
    IntegrityVerificationOutcome, IntegrityVerificationRequest, IntegrityVerificationScope,
    LedgerFailureCode, MountQualification, PreparedStoreBlock, PrimaryDataVolume,
    SegmentProtectionKey, SegmentScope, StoreBlockIdentity, TransactionId,
    integrity_quarantine_findings,
};

fn catalog_integrity_request<'a>(
    scope: SegmentScope,
    protection: SegmentProtectionKey,
    mode: IntegrityVerificationMode,
    budget: IntegrityScrubBudget,
    cancellation: &'a dyn crate::IntegrityCancellationProbe,
    transaction: TransactionId,
    continuation: Option<crate::IntegrityScrubContinuation>,
) -> CatalogIntegrityVerificationRequest<'a> {
    CatalogIntegrityVerificationRequest::new(
        IntegrityVerificationRequest::new(
            scope,
            protection,
            budget,
            cancellation,
            transaction,
            continuation,
        ),
        mode,
    )
}

#[test]
fn active_integrity_verification_honors_the_byte_budget() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x81; 16])?,
        CatalogSecret::from_owned(Box::new([0x82; 32]), Box::new([0x83; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(9)?,
    );
    let protection = || SegmentProtectionKey::from_owned(Box::new([0x84; 32]));
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, protection())?;
    ledger.append(PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([0x85; 16])?,
        vec![0x86; 1024],
    )?)?;
    for mode in [
        IntegrityVerificationMode::Startup,
        IntegrityVerificationMode::Offline,
    ] {
        let limited = ActiveSegmentLedger::verify_catalog_integrity(
            &authority,
            &catalog,
            catalog_integrity_request(
                scope,
                protection(),
                mode,
                IntegrityScrubBudget::with_bytes(1, 1).map_err(|_| "valid bounded budget")?,
                &IntegrityCancellation::new(),
                TransactionId::new([0x87; 16])?,
                None,
            ),
        )?;
        assert_eq!(limited.outcome(), IntegrityVerificationOutcome::Incomplete);
        assert_eq!(limited.examined_segments(), 0);
        assert_eq!(limited.omitted_segments(), 1);
        assert!(!limited.is_success());
        let complete = ActiveSegmentLedger::verify_catalog_integrity(
            &authority,
            &catalog,
            catalog_integrity_request(
                scope,
                protection(),
                mode,
                IntegrityScrubBudget::new(1).map_err(|_| "valid complete budget")?,
                &IntegrityCancellation::new(),
                TransactionId::new([0x88; 16])?,
                None,
            ),
        )?;
        assert_eq!(complete.outcome(), IntegrityVerificationOutcome::Verified);
        assert_eq!(complete.examined_segments(), 1);
        assert!(complete.examined_bytes() >= 1024);
    }
    Ok(())
}

#[test]
fn sealed_damage_is_durably_quarantined_and_other_scopes_remain_readable()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x91; 16])?,
        CatalogSecret::from_owned(Box::new([0x92; 32]), Box::new([0x93; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let damaged_scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(1)?);
    let healthy_scope = SegmentScope::new(tenant, SignalKind::Traces, VirtualShardId::new(1)?);
    let damaged_key = || SegmentProtectionKey::from_owned(Box::new([0x94; 32]));
    let healthy_key = || SegmentProtectionKey::from_owned(Box::new([0x95; 32]));

    let damaged = ActiveSegmentLedger::open(&authority, &catalog, damaged_scope, damaged_key())?;
    damaged.append(PreparedStoreBlock::new_with_authenticated_ranges_for_test(
        damaged_scope,
        StoreBlockIdentity::new([0x97; 16])?,
        b"missing-source-time".to_vec(),
        AuthenticatedEventRange::unavailable(EventRangeUnavailable::MissingSourceTime),
        crate::IngestTime::from_authenticated_durable(UnixNanoseconds::new(30)),
    )?)?;
    let sealed = damaged.seal()?;
    let damaged = ActiveSegmentLedger::open(&authority, &catalog, damaged_scope, damaged_key())?;
    damaged.append(PreparedStoreBlock::new_with_authenticated_ranges_for_test(
        damaged_scope,
        StoreBlockIdentity::new([0x98; 16])?,
        b"same-scope-healthy".to_vec(),
        AuthenticatedEventRange::known(UnixNanoseconds::new(40), UnixNanoseconds::new(50))
            .map_err(|_| "fixed Event Time range")?,
        crate::IngestTime::from_authenticated_durable(UnixNanoseconds::new(60)),
    )?)?;
    let retained_frontier = damaged.snapshot()?.frontier();
    let lease = damaged.create_snapshot_lease(1, 2)?;
    let lease_identity = lease.identity();
    let leased_generation = lease.snapshot().catalog_generation();
    drop(lease);
    fs::write(
        root.path()
            .join("segments/sealed")
            .join(segment_name(sealed.segment_id())),
        b"corrupt",
    )?;
    let healthy = ActiveSegmentLedger::open(&authority, &catalog, healthy_scope, healthy_key())?;

    let report = ActiveSegmentLedger::verify_catalog_integrity(
        &authority,
        &catalog,
        catalog_integrity_request(
            damaged_scope,
            damaged_key(),
            IntegrityVerificationMode::Online,
            IntegrityScrubBudget::new(8).map_err(|_| "valid scrub budget rejected")?,
            &IntegrityCancellation::new(),
            TransactionId::new([0x96; 16])?,
            None,
        ),
    )?;
    assert_eq!(report.outcome(), IntegrityVerificationOutcome::Quarantined);
    assert_eq!(report.quarantined_segment(), Some(sealed.segment_id()));
    assert_eq!(
        report.finding(),
        Some(IntegrityFinding::LocalizedImmutableCorruption(
            sealed.segment_id()
        ))
    );
    let findings = integrity_quarantine_findings(&catalog.pin()?)?;
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].scope(), damaged_scope);
    assert_eq!(findings[0].segment(), sealed.segment_id());
    assert_eq!(findings[0].sealed_frontier(), sealed.frontier());
    assert_eq!(
        findings[0].event_range(),
        AuthenticatedEventRange::unavailable(EventRangeUnavailable::MissingSourceTime)
    );
    assert_eq!(
        findings[0].ingest_range(),
        crate::AuthenticatedIngestRange::Known {
            earliest: UnixNanoseconds::new(30),
            latest: UnixNanoseconds::new(30),
        }
    );
    assert!(!report.is_success());
    let retained = ActiveSegmentLedger::verify_catalog_integrity(
        &authority,
        &catalog,
        catalog_integrity_request(
            damaged_scope,
            damaged_key(),
            IntegrityVerificationMode::Offline,
            IntegrityScrubBudget::new(8).map_err(|_| "valid scrub budget rejected")?,
            &IntegrityCancellation::new(),
            TransactionId::new([0x97; 16])?,
            None,
        ),
    )?;
    assert_eq!(
        retained.outcome(),
        IntegrityVerificationOutcome::Quarantined
    );
    assert_eq!(retained.quarantined_segment(), Some(sealed.segment_id()));
    let observed = CommittedLedgerReader::open(&authority, &catalog, damaged_scope, damaged_key())?
        .snapshot()?;
    assert_eq!(observed.quarantined_holes().len(), 1);
    assert_eq!(observed.frontier(), retained_frontier);
    assert_eq!(observed.blocks().len(), 1);
    assert_eq!(observed.blocks()[0].payload(), b"same-scope-healthy");
    let resumed = damaged.resume_snapshot_lease(lease_identity, 1)?;
    assert_eq!(resumed.snapshot().catalog_generation(), leased_generation);
    assert_eq!(resumed.snapshot().quarantined_holes().len(), 1);
    assert_eq!(
        resumed.snapshot().quarantined_holes()[0].segment(),
        sealed.segment_id(),
        "a current PQUAR overlays a historical cursor without rebasing it"
    );
    drop(resumed);
    let lease = damaged.create_snapshot_lease(1, 2)?;
    assert_eq!(lease.snapshot().quarantined_holes().len(), 1);
    assert_eq!(lease.snapshot().blocks().len(), 1);
    assert_eq!(
        lease.snapshot().blocks()[0].payload(),
        b"same-scope-healthy"
    );
    let reopened = CommittedLedgerReader::open(&authority, &catalog, damaged_scope, damaged_key())?;
    let observed_after_reopen = reopened.snapshot()?;
    assert_eq!(observed_after_reopen.quarantined_holes().len(), 1);
    assert!(
        healthy.reader()?.snapshot().is_ok(),
        "an unrelated scope remains available"
    );
    Ok(())
}

#[test]
fn retained_quarantine_allows_bounded_same_scope_resume_and_later_bitrot_detection()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x9a; 16])?,
        CatalogSecret::from_owned(Box::new([0x9b; 32]), Box::new([0x9c; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(9)?,
    );
    let key = || SegmentProtectionKey::from_owned(Box::new([0x9d; 32]));

    let first = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    first.append(PreparedStoreBlock::new_with_authenticated_ranges_for_test(
        scope,
        StoreBlockIdentity::new([0x9e; 16])?,
        b"first damaged source".to_vec(),
        AuthenticatedEventRange::known(UnixNanoseconds::new(10), UnixNanoseconds::new(20))
            .map_err(|_| "fixed Event Time range")?,
        crate::IngestTime::from_authenticated_durable(UnixNanoseconds::new(30)),
    )?)?;
    let first_sealed = first.seal()?;

    fs::write(
        root.path()
            .join("segments/sealed")
            .join(segment_name(first_sealed.segment_id())),
        b"corrupt first source",
    )?;
    let first_report = ActiveSegmentLedger::verify_catalog_integrity(
        &authority,
        &catalog,
        catalog_integrity_request(
            scope,
            key(),
            IntegrityVerificationMode::Online,
            IntegrityScrubBudget::new(8).map_err(|_| "valid scrub budget rejected")?,
            &IntegrityCancellation::new(),
            TransactionId::new([0xa1; 16])?,
            None,
        ),
    )?;
    assert_eq!(
        first_report.outcome(),
        IntegrityVerificationOutcome::Quarantined
    );
    assert_eq!(
        first_report.quarantined_segment(),
        Some(first_sealed.segment_id())
    );

    let second = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    second.append(PreparedStoreBlock::new_with_authenticated_ranges_for_test(
        scope,
        StoreBlockIdentity::new([0x9f; 16])?,
        b"same scope healthy source".to_vec(),
        AuthenticatedEventRange::known(UnixNanoseconds::new(40), UnixNanoseconds::new(50))
            .map_err(|_| "fixed Event Time range")?,
        crate::IngestTime::from_authenticated_durable(UnixNanoseconds::new(60)),
    )?)?;
    let second_sealed = second.seal()?;

    let third = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    third.append(PreparedStoreBlock::new_with_authenticated_ranges_for_test(
        scope,
        StoreBlockIdentity::new([0xa0; 16])?,
        b"later same scope healthy source".to_vec(),
        AuthenticatedEventRange::known(UnixNanoseconds::new(70), UnixNanoseconds::new(80))
            .map_err(|_| "fixed Event Time range")?,
        crate::IngestTime::from_authenticated_durable(UnixNanoseconds::new(90)),
    )?)?;
    let third_sealed = third.seal()?;

    let healthy_report = ActiveSegmentLedger::verify_catalog_integrity(
        &authority,
        &catalog,
        catalog_integrity_request(
            scope,
            key(),
            IntegrityVerificationMode::Online,
            IntegrityScrubBudget::new(1).map_err(|_| "valid scrub budget rejected")?,
            &IntegrityCancellation::new(),
            TransactionId::new([0xa2; 16])?,
            None,
        ),
    )?;
    assert_eq!(
        healthy_report.outcome(),
        IntegrityVerificationOutcome::Incomplete
    );
    assert_eq!(
        healthy_report.quarantined_segment(),
        Some(first_sealed.segment_id()),
        "an incomplete later pass retains the existing quarantine evidence"
    );
    assert_eq!(
        healthy_report.examined_segments(),
        1,
        "the retained quarantine is skipped while bounded work authenticates one later source"
    );
    let continuation = healthy_report
        .continuation()
        .ok_or("missing bounded same-scope continuation")?;
    let resumed_report = ActiveSegmentLedger::verify_catalog_integrity(
        &authority,
        &catalog,
        catalog_integrity_request(
            scope,
            key(),
            IntegrityVerificationMode::Online,
            IntegrityScrubBudget::new(1).map_err(|_| "valid scrub budget rejected")?,
            &IntegrityCancellation::new(),
            TransactionId::new([0xa3; 16])?,
            Some(continuation),
        ),
    )?;
    assert_eq!(
        resumed_report.outcome(),
        IntegrityVerificationOutcome::Quarantined
    );
    assert_eq!(
        resumed_report.quarantined_segment(),
        Some(first_sealed.segment_id())
    );
    assert_eq!(resumed_report.examined_segments(), 1);
    assert!(
        CommittedLedgerReader::open(&authority, &catalog, scope, key())?
            .snapshot()?
            .blocks()
            .iter()
            .filter(|block| {
                block.segment == second_sealed.segment_id()
                    || block.segment == third_sealed.segment_id()
            })
            .count()
            == 2,
        "both authenticated same-scope sources remain readable"
    );

    fs::write(
        root.path()
            .join("segments/sealed")
            .join(segment_name(third_sealed.segment_id())),
        b"corrupt late source",
    )?;
    let later_report = ActiveSegmentLedger::verify_catalog_integrity(
        &authority,
        &catalog,
        catalog_integrity_request(
            scope,
            key(),
            IntegrityVerificationMode::Online,
            IntegrityScrubBudget::new(8).map_err(|_| "valid scrub budget rejected")?,
            &IntegrityCancellation::new(),
            TransactionId::new([0xa4; 16])?,
            None,
        ),
    )?;
    assert_eq!(
        later_report.outcome(),
        IntegrityVerificationOutcome::Quarantined
    );
    assert_eq!(
        later_report.quarantined_segment(),
        Some(third_sealed.segment_id())
    );
    let mut findings = integrity_quarantine_findings(&catalog.pin()?)?
        .into_iter()
        .map(|finding| finding.segment())
        .collect::<Vec<_>>();
    findings.sort_unstable();
    let mut expected = vec![first_sealed.segment_id(), third_sealed.segment_id()];
    expected.sort_unstable();
    assert_eq!(findings, expected);
    Ok(())
}

#[test]
fn online_scrub_does_not_claim_an_active_tail_is_an_omission() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xa1; 16])?,
        CatalogSecret::from_owned(Box::new([0xa2; 32]), Box::new([0xa3; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(2)?,
    );
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xa4; 32])),
    )?;
    let report = ledger.verify_integrity(
        IntegrityVerificationMode::Online,
        IntegrityScrubBudget::new(1).map_err(|_| "valid scrub budget rejected")?,
        &IntegrityCancellation::new(),
        TransactionId::new([0xa5; 16])?,
    )?;
    assert_eq!(report.outcome(), IntegrityVerificationOutcome::Verified);
    assert_eq!(
        report.verification_scope(),
        IntegrityVerificationScope::ReachableImmutableSegments
    );
    assert_eq!(report.omitted_segments(), 0);
    let startup = ledger.verify_integrity(
        IntegrityVerificationMode::Startup,
        IntegrityScrubBudget::new(1).map_err(|_| "valid scrub budget rejected")?,
        &IntegrityCancellation::new(),
        TransactionId::new([0xa6; 16])?,
    )?;
    assert_eq!(startup.outcome(), IntegrityVerificationOutcome::Verified);
    assert_eq!(
        startup.verification_scope(),
        IntegrityVerificationScope::StartupFrontiers
    );
    Ok(())
}

#[test]
fn offline_verify_is_read_only_and_fences_localized_damage() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xb1; 16])?,
        CatalogSecret::from_owned(Box::new([0xb2; 32]), Box::new([0xb3; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(3)?,
    );
    let key = || SegmentProtectionKey::from_owned(Box::new([0xb4; 32]));
    let sealed = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?.seal()?;
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    fs::write(
        root.path()
            .join("segments/sealed")
            .join(segment_name(sealed.segment_id())),
        b"corrupt",
    )?;

    let report = ledger.verify_integrity(
        IntegrityVerificationMode::Offline,
        IntegrityScrubBudget::new(8).map_err(|_| "valid scrub budget rejected")?,
        &IntegrityCancellation::new(),
        TransactionId::new([0xb5; 16])?,
    )?;
    assert_eq!(report.outcome(), IntegrityVerificationOutcome::Fenced);
    assert_eq!(report.quarantined_segment(), None);
    assert_eq!(report.finding(), Some(IntegrityFinding::AmbiguousIntegrity));
    let failure = match ledger.reader()?.snapshot() {
        Ok(_) => return Err("offline verification must not mutate quarantine state".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LedgerFailureCode::UnsupportedFormat);
    Ok(())
}

#[test]
fn bounded_scrub_checkpoint_resumes_after_catalog_reopen_and_rejects_changed_source()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([0xc1; 16])?;
    let catalog_secret = || CatalogSecret::from_owned(Box::new([0xc2; 32]), Box::new([0xc3; 32]));
    let catalog = Catalog::open(&authority, instance, catalog_secret())?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(4)?,
    );
    let key = || SegmentProtectionKey::from_owned(Box::new([0xc4; 32]));
    let first_ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    first_ledger.append(PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([0xc8; 16])?,
        b"first-physical-scrub-segment".to_vec(),
    )?)?;
    first_ledger.seal()?;
    let second_ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    second_ledger.append(PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([0xc9; 16])?,
        b"second-physical-scrub-segment".to_vec(),
    )?)?;
    second_ledger.seal()?;

    let first = ActiveSegmentLedger::verify_catalog_integrity(
        &authority,
        &catalog,
        catalog_integrity_request(
            scope,
            key(),
            IntegrityVerificationMode::Online,
            IntegrityScrubBudget::new(1).map_err(|_| "valid scrub budget rejected")?,
            &IntegrityCancellation::new(),
            TransactionId::new([0xc5; 16])?,
            None,
        ),
    )?;
    assert_eq!(first.outcome(), IntegrityVerificationOutcome::Incomplete);
    assert!(
        first.examined_bytes() > 0,
        "the scrub budget and report account for authenticated physical bytes, even for an empty sealed segment"
    );
    let continuation = first.continuation().ok_or("missing bounded continuation")?;

    // A process can crash after its coordinator has durably acknowledged this
    // cursor. Reopening the Catalog proves that the cursor binds the sealed
    // source rather than the mutable Catalog generation.
    drop(catalog);
    let reopened = Catalog::open(&authority, instance, catalog_secret())?;
    let resumed = ActiveSegmentLedger::verify_catalog_integrity(
        &authority,
        &reopened,
        catalog_integrity_request(
            scope,
            key(),
            IntegrityVerificationMode::Online,
            IntegrityScrubBudget::new(8).map_err(|_| "valid scrub budget rejected")?,
            &IntegrityCancellation::new(),
            TransactionId::new([0xc6; 16])?,
            Some(continuation),
        ),
    )?;
    assert_eq!(resumed.outcome(), IntegrityVerificationOutcome::Verified);

    ActiveSegmentLedger::open(&authority, &reopened, scope, key())?.seal()?;
    let stale = ActiveSegmentLedger::verify_catalog_integrity(
        &authority,
        &reopened,
        catalog_integrity_request(
            scope,
            key(),
            IntegrityVerificationMode::Online,
            IntegrityScrubBudget::new(8).map_err(|_| "valid scrub budget rejected")?,
            &IntegrityCancellation::new(),
            TransactionId::new([0xc7; 16])?,
            Some(continuation),
        ),
    )?;
    assert_eq!(stale.outcome(), IntegrityVerificationOutcome::Stale);
    Ok(())
}

#[test]
fn unavailable_or_mismatched_segment_key_fences_without_quarantine() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xd1; 16])?,
        CatalogSecret::from_owned(Box::new([0xd2; 32]), Box::new([0xd3; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(5)?,
    );
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xd4; 32])),
    )?;
    ledger.append(PreparedStoreBlock::new_with_authenticated_ranges_for_test(
        scope,
        StoreBlockIdentity::new([0xd7; 16])?,
        b"known-range key custody boundary".to_vec(),
        AuthenticatedEventRange::known(UnixNanoseconds::new(10), UnixNanoseconds::new(20))
            .map_err(|_| "fixed Event Time range")?,
        crate::IngestTime::from_authenticated_durable(UnixNanoseconds::new(30)),
    )?)?;
    ledger.seal()?;
    let report = ActiveSegmentLedger::verify_catalog_integrity(
        &authority,
        &catalog,
        catalog_integrity_request(
            scope,
            SegmentProtectionKey::from_owned(Box::new([0xd5; 32])),
            IntegrityVerificationMode::Online,
            IntegrityScrubBudget::new(8).map_err(|_| "valid scrub budget rejected")?,
            &IntegrityCancellation::new(),
            TransactionId::new([0xd6; 16])?,
            None,
        ),
    )?;
    assert_eq!(report.outcome(), IntegrityVerificationOutcome::Fenced);
    assert_eq!(report.quarantined_segment(), None);
    Ok(())
}
