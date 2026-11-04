use super::*;

#[test]
fn queued_release_failure_cannot_claim_rejection_when_cleanup_can_still_act()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x79; 32])),
        )?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        let failure = with_catalog_fault(CatalogFileEvent::RenameMarker, || {
            ledger.release_snapshot_lease(identity)
        })
        .expect_err("release publication must fail at the injected boundary");
        assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
        assert_eq!(
            failure.completion_state(),
            LedgerCompletionState::RecoveryRequired
        );
        // Existing pending cleanup can run on the next unrelated ledger call.
        assert_eq!(
            ledger
                .resume_snapshot_lease(identity, 101)
                .expect_err("queued cleanup releases the original lease")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );
        Ok(())
    })
}

#[test]
fn published_cancellation_installation_failure_preserves_possible_effects()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x7a; 32])),
        )?;
        let coordinator = MaintenanceCoordinator::new();
        let lease = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
            &coordinator,
            100,
            std::num::NonZeroU64::new(100).ok_or("ttl")?,
            catalog.pin()?.identity(),
        )?;
        let identity = lease.identity();
        drop(lease);
        let failure = with_ledger_fault(LedgerFileEvent::AfterLeaseCancellationPublication, || {
            ledger.release_snapshot_lease_with_expiry_task(&coordinator, identity)
        })
        .expect_err("post-publication installation failure must remain explicit");
        assert_eq!(failure.code(), LedgerFailureCode::RecoveryRequired);
        assert_eq!(
            failure.completion_state(),
            LedgerCompletionState::RecoveryRequired
        );
        assert_eq!(
            ledger
                .resume_snapshot_lease(identity, 101)
                .expect_err("the cancellation already removed its durable lease")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );
        Ok(())
    })
}
