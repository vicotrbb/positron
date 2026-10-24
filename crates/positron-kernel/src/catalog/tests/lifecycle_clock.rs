use super::super::*;
use crate::{MountQualification, PrimaryDataVolume, RetentionTimeAuthority};
use positron_domain::time::UnixNanoseconds;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Root(std::path::PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn fixture(
    test: impl FnOnce(&Catalog<'_>) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = Root(std::env::temp_dir().join(format!(
        "positron-clock-checkpoint-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    std::fs::create_dir(&root.0)?;
    let authority = super::support::establish_catalog_authority_with_pool_units(
        PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?,
        70_000_001,
        30_000_000,
    )?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([1; 16])?,
        CatalogSecret::from_owned(Box::new([2; 32]), Box::new([3; 32])),
    )?;
    let (clock, _) = RetentionTimeAuthority::establish_with_manual_elapsed(epoch());
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([4; 16])?,
            FormatEpoch::CATALOG_V2,
            vec![
                CatalogObject::new(b"unchanged native metadata".to_vec())?,
                CatalogObject::new(clock.catalog_anchor_record(
                    crate::IngestTime::from_authenticated_durable(epoch()),
                )?)?,
            ],
        )?,
        None,
    )?;
    test(&catalog)
}
fn epoch() -> UnixNanoseconds {
    UnixNanoseconds::new(100_000_000_000)
}
fn other(snapshot: &CatalogSnapshot) -> Vec<Vec<u8>> {
    snapshot
        .plaintext_objects()
        .filter(|bytes| {
            !crate::retention_time::validate_catalog_anchor_record(bytes)
                .expect("authenticated clock record")
        })
        .map(<[u8]>::to_vec)
        .collect()
}
#[test]
fn reopening_catalog_after_zero_elapsed_recovery_preserves_live_clock_progress()
-> Result<(), Box<dyn std::error::Error>> {
    fixture(|catalog| {
        let (clock, elapsed) = RetentionTimeAuthority::establish_with_manual_elapsed(epoch());
        clock.recover_catalog_anchor(&catalog.pin()?)?;
        assert_eq!(clock.governance_now_seconds()?, 100);
        elapsed.advance(2_000_000_000)?;
        clock.recover_catalog_anchor(&catalog.pin()?)?;
        assert_eq!(clock.governance_now_seconds()?, 102);
        clock.recover_catalog_anchor(&catalog.pin()?)?;
        assert_eq!(clock.governance_now_seconds()?, 102);
        Ok(())
    })
}

#[test]
fn first_catalog_recovery_reconciles_a_wall_jump_against_the_durable_anchor()
-> Result<(), Box<dyn std::error::Error>> {
    struct JumpedWall;
    impl crate::LifecycleClockSource for JumpedWall {
        fn read(&self) -> Result<UnixNanoseconds, crate::LifecycleClockFailure> {
            Ok(UnixNanoseconds::new(200_000_000_000))
        }
    }
    fixture(|catalog| {
        let clock = RetentionTimeAuthority::establish_with_source(
            JumpedWall,
            crate::LifecycleClockPolicy::new(1_000_000_000)?,
        )?;
        clock.recover_catalog_anchor(&catalog.pin()?)?;
        assert_eq!(
            clock.status().state(),
            crate::LifecycleClockState::ClockUncertain
        );
        assert_eq!(clock.governance_now_seconds()?, 100);
        Ok(())
    })
}

#[test]
fn cold_clock_checkpoints_accumulate_only_genuine_elapsed_time()
-> Result<(), Box<dyn std::error::Error>> {
    fixture(|catalog| {
        let original = other(&catalog.pin()?);
        for turn in 1..=3 {
            let (clock, elapsed) = RetentionTimeAuthority::establish_with_manual_elapsed(epoch());
            clock.recover_catalog_anchor(&catalog.pin()?)?;
            elapsed.advance(20_000_000_000)?;
            assert_eq!(clock.governance_now_seconds()?, 100 + turn * 20);
            catalog.checkpoint_lifecycle_time(&clock)?;
            assert_eq!(other(&catalog.pin()?), original);
            let (cold, _) = RetentionTimeAuthority::establish_with_manual_elapsed(epoch());
            cold.recover_catalog_anchor(&catalog.pin()?)?;
            assert_eq!(cold.governance_now_seconds()?, 100 + turn * 20);
        }
        // A fresh wall-derived authority must recover the authenticated anchor
        // before it can propose a new value.
        let (fresh, _) = RetentionTimeAuthority::establish_with_manual_elapsed(
            UnixNanoseconds::new(999_000_000_000),
        );
        catalog.checkpoint_lifecycle_time(&fresh)?;
        assert_eq!(fresh.governance_now_seconds()?, 160);
        Ok(())
    })
}
#[test]
fn clock_checkpoint_refuses_an_unpublished_prepared_intent()
-> Result<(), Box<dyn std::error::Error>> {
    fixture(|catalog| {
        let basis = catalog.pin()?;
        let failed = super::super::storage::with_catalog_fault(
            super::super::storage::fault::CatalogFileEvent::WriteMarker,
            || {
                catalog.commit_prepared(
                    basis.identity(),
                    CatalogProposal::new(
                        TransactionId::new([5; 16]).expect("id"),
                        FormatEpoch::CATALOG_V2,
                        vec![
                            CatalogObject::new(b"pending operation bytes".to_vec())
                                .expect("object"),
                        ],
                    )
                    .expect("proposal"),
                    AuditIntent::new(b"pending administration".to_vec()).expect("audit"),
                    [6; 32],
                )
            },
        );
        assert!(failed.is_err());
        assert!(catalog.has_prepared_transaction()?);
        let (clock, elapsed) = RetentionTimeAuthority::establish_with_manual_elapsed(epoch());
        elapsed.advance(5_000_000_000)?;
        let before = clock.status();
        assert_eq!(
            catalog
                .checkpoint_lifecycle_time(&clock)
                .expect_err("prepared intent is exclusive")
                .code(),
            CatalogFailureCode::ConcurrentWriter
        );
        assert_eq!(catalog.pin()?.identity(), basis.identity());
        assert_eq!(clock.status(), before);
        Ok(())
    })
}
#[test]
fn clock_checkpoint_confirms_exact_publication_or_requires_canonical_recovery()
-> Result<(), Box<dyn std::error::Error>> {
    for faults in 0..=2 {
        fixture(|catalog| {
            let (clock, elapsed) = RetentionTimeAuthority::establish_with_manual_elapsed(epoch());
            clock.recover_catalog_anchor(&catalog.pin()?)?;
            elapsed.advance(5_000_000_000)?;
            assert_eq!(clock.governance_now_seconds()?, 105);
            let original = catalog.pin()?;
            let selected = match faults {
                0 => vec![(crate::CatalogPublicationFault::RenameMarker, 0)],
                1 => vec![(
                    crate::CatalogPublicationFault::SynchronizeGenerationDirectory,
                    0,
                )],
                _ => vec![
                    (
                        crate::CatalogPublicationFault::SynchronizeGenerationDirectory,
                        0
                    );
                    2
                ],
            };
            let result = crate::with_catalog_publication_fault_sequence_after(&selected, || {
                catalog.checkpoint_lifecycle_time(&clock)
            });
            assert_eq!(result.is_ok(), faults == 1);
            catalog.refresh_state()?;
            assert_eq!(other(&catalog.pin()?), other(&original));
            let (cold, _) = RetentionTimeAuthority::establish_with_manual_elapsed(epoch());
            cold.recover_catalog_anchor(&catalog.pin()?)?;
            assert_eq!(
                cold.governance_now_seconds()?,
                if faults == 0 { 100 } else { 105 }
            );
            // Reuse first performs canonical recovery; it cannot replace the
            // already visible 105-second anchor with an older local candidate.
            catalog.checkpoint_lifecycle_time(&clock)?;
            let (recovered, _) = RetentionTimeAuthority::establish_with_manual_elapsed(epoch());
            recovered.recover_catalog_anchor(&catalog.pin()?)?;
            assert_eq!(recovered.governance_now_seconds()?, 105);
            Ok(())
        })?;
    }
    Ok(())
}

#[path = "lifecycle_clock/publication.rs"]
mod publication;
