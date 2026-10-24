//! Clock staging shares Catalog's predecessor-or-successor recovery contract.
use super::*;
use crate::{
    IngestTime, LifecycleClockPolicy, LifecycleClockSource, LifecycleClockState,
    RetentionTimeAuthority,
};
use std::sync::{Arc, atomic::AtomicI64};

struct MutableWall(Arc<AtomicI64>);
impl LifecycleClockSource for MutableWall {
    fn read(&self) -> Result<UnixNanoseconds, crate::LifecycleClockFailure> {
        Ok(UnixNanoseconds::new(self.0.load(Ordering::Acquire)))
    }
}
use positron_domain::time::UnixNanoseconds;

pub(super) fn exercise(data: &[u8]) {
    let Some(root) = FuzzRoot::new() else { return };
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)
        .expect("fresh clock fuzz volume");
    let Some(authority) = fuzz_authority(volume) else {
        return;
    };
    let instance = InstanceId::new(nonzero_id(1)).expect("fixed instance");
    let catalog = Catalog::open(&authority, instance, secret()).expect("fresh clock catalog");
    let epoch = UnixNanoseconds::new(100_000_000_000);
    let wall = Arc::new(AtomicI64::new(epoch.value()));
    let (clock, elapsed) = RetentionTimeAuthority::establish_with_source_and_manual_elapsed(
        MutableWall(Arc::clone(&wall)),
        LifecycleClockPolicy::default(),
    )
    .expect("mutable wall clock");
    let payload = CatalogObject::new(b"clock fuzz payload".to_vec()).expect("bounded payload");
    let anchor = clock
        .catalog_anchor_record(IngestTime::from_authenticated_durable(epoch))
        .expect("initial clock anchor");
    catalog
        .commit(
            catalog.pin().expect("initial pin").identity(),
            CatalogProposal::new(
                TransactionId::new(nonzero_id(1)).expect("transaction"),
                FormatEpoch::CATALOG_V2,
                vec![
                    CatalogObject::new(payload.plaintext.clone()).expect("payload copy"),
                    CatalogObject::new(anchor).expect("anchor object"),
                ],
            )
            .expect("initial proposal"),
            None,
        )
        .expect("initial anchor publication");
    let basis = catalog.pin().expect("clock basis");
    clock
        .recover_catalog_anchor(&basis)
        .expect("recover initial anchor");
    let advance = (u64::from(data.first().copied().unwrap_or_default()) + 1) * 1_000_000_000;
    elapsed.advance(advance).expect("bounded elapsed time");
    let wall_mode = data.get(3).copied().unwrap_or_default() % 3;
    let trusted = epoch.value() + advance as i64;
    wall.store(
        match wall_mode {
            1 => epoch.value() - 1_000_000_000_000,
            2 => trusted + 1_000_000_000_000,
            _ => trusted,
        },
        Ordering::Release,
    );
    let expected_state = if wall_mode == 0 {
        LifecycleClockState::Certain
    } else {
        LifecycleClockState::ClockUncertain
    };
    assert_eq!(
        clock.governance_now_seconds().expect("wall observation"),
        100 + advance / 1_000_000_000
    );
    assert_eq!(clock.status().state(), expected_state);
    let transaction = TransactionId::new(nonzero_id(2)).expect("transaction");
    let proposal = || {
        CatalogProposal::new(
            transaction,
            FormatEpoch::CATALOG_V2,
            basis
                .plaintext_objects()
                .map(|bytes| CatalogObject::new(bytes.to_vec()))
                .collect::<Result<Vec<_>, _>>()
                .expect("bounded existing objects"),
        )
        .expect("clock proposal")
    };
    let cancellation = data.get(1).copied().unwrap_or_default() % 4;
    let mut checks = 0_u8;
    let outcome = with_catalog_fault(
        fault_event(data.get(2).copied().unwrap_or_default()),
        || {
            catalog.commit_interruptibly_with_lifecycle_clock(
                basis.identity(),
                proposal(),
                None,
                &clock,
                &mut || {
                    checks = checks.saturating_add(1);
                    cancellation != 0 && checks >= cancellation
                },
            )
        },
    );
    assert_eq!(clock.status().state(), expected_state);
    if matches!(outcome, Ok(None)) {
        assert_eq!(
            catalog.pin().expect("cancelled pin").identity(),
            basis.identity()
        );
        // Retrying uses the same trusted elapsed interval after staged rollback.
        catalog
            .commit_interruptibly_with_lifecycle_clock(
                basis.identity(),
                proposal(),
                None,
                &clock,
                &mut || false,
            )
            .expect("cancelled clock retry")
            .expect("retry publishes");
    }
    assert_eq!(clock.status().state(), expected_state);
    let predecessor = basis.identity();
    let acknowledged = matches!(outcome, Ok(Some(_)) | Ok(None));
    drop(basis);
    drop(catalog);
    drop(authority);
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)
        .expect("clock fuzz releases volume");
    let Some(authority) = fuzz_authority(volume) else {
        return;
    };
    let recovered = Catalog::open(&authority, instance, secret()).expect("clock catalog recovers");
    let current = recovered.pin().expect("cold clock pin");
    let visible = recovered
        .committed_transaction(transaction)
        .expect("transaction inspection");
    assert_eq!(current.number(), 1 + u64::from(visible.is_some()));
    if acknowledged {
        assert!(
            visible.is_some(),
            "acknowledged clock publication survives recovery"
        );
    }
    assert_eq!(
        current.object(payload.identity()).expect("payload lookup"),
        Some(payload.plaintext.as_slice())
    );
    assert!(
        recovered
            .governance_audit_records()
            .expect("audit reads")
            .is_empty()
    );
    if let Some(commit) = visible {
        assert_eq!(commit.identity(), current.identity());
        assert_eq!(commit.predecessor(), predecessor);
    }
    let (cold, _) = RetentionTimeAuthority::establish_with_manual_elapsed(epoch);
    cold.recover_catalog_anchor(&current)
        .expect("cold anchor recovery");
    assert_eq!(
        cold.status().state(),
        if current.number() == 2 {
            expected_state
        } else {
            LifecycleClockState::Certain
        }
    );
    let restart_wall = if data.get(4).copied().unwrap_or_default() & 1 == 0 {
        epoch.value() - 1_000_000_000_000
    } else {
        trusted + 1_000_000_000_000
    };
    let (restarted, _) = RetentionTimeAuthority::establish_with_source_and_manual_elapsed(
        MutableWall(Arc::new(AtomicI64::new(restart_wall))),
        LifecycleClockPolicy::default(),
    )
    .expect("restart wall clock");
    restarted
        .recover_catalog_anchor(&current)
        .expect("restart observation");
    assert_eq!(
        restarted.status().state(),
        LifecycleClockState::ClockUncertain
    );
    assert_eq!(
        restarted
            .governance_now_seconds()
            .expect("restart safe anchor"),
        cold.governance_now_seconds()
            .expect("persisted safe anchor")
    );
    assert_eq!(
        cold.governance_now_seconds().expect("recovered time"),
        100 + if current.number() == 2 {
            advance / 1_000_000_000
        } else {
            0
        }
    );
}
