use super::*;
use crate::{LifecycleClockPolicy, LifecycleClockSource, LifecycleClockState};

struct FixedWall(UnixNanoseconds);
impl LifecycleClockSource for FixedWall {
    fn read(&self) -> Result<UnixNanoseconds, crate::LifecycleClockFailure> {
        Ok(self.0)
    }
}

fn final_proposal(
    snapshot: &CatalogSnapshot,
    transaction: TransactionId,
) -> Result<CatalogProposal, CatalogFailure> {
    let mut objects = snapshot
        .plaintext_objects()
        .map(|bytes| CatalogObject::new(bytes.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    objects.push(CatalogObject::new(b"final publication payload".to_vec())?);
    CatalogProposal::new(transaction, FormatEpoch::CATALOG_V2, objects)
}

#[test]
fn interrupted_clock_publication_leaves_the_predecessor_and_payload_unchanged()
-> Result<(), Box<dyn std::error::Error>> {
    fixture(|catalog| {
        let basis = catalog.pin()?;
        let (clock, elapsed) = RetentionTimeAuthority::establish_with_manual_elapsed(epoch());
        clock.recover_catalog_anchor(&basis)?;
        elapsed.advance(601_000_000_000)?;
        let mut checks = 0;
        let result = catalog.commit_interruptibly_with_lifecycle_clock(
            basis.identity(),
            final_proposal(&basis, TransactionId::new([21; 16])?)?,
            None,
            &clock,
            &mut || {
                checks += 1;
                checks > 1
            },
        )?;
        assert!(result.is_none());
        assert_eq!(catalog.pin()?.identity(), basis.identity());
        assert_eq!(other(&catalog.pin()?), other(&basis));
        let cold = RetentionTimeAuthority::establish_with_source(
            FixedWall(UnixNanoseconds::new(701_000_000_000)),
            LifecycleClockPolicy::default(),
        )?;
        cold.recover_catalog_anchor(&catalog.pin()?)?;
        assert_eq!(cold.status().state(), LifecycleClockState::ClockUncertain);
        Ok(())
    })
}

#[test]
fn clock_publication_confirms_only_its_exact_visible_transaction()
-> Result<(), Box<dyn std::error::Error>> {
    for faults in 0..=2 {
        fixture(|catalog| {
            let basis = catalog.pin()?;
            let (clock, elapsed) = RetentionTimeAuthority::establish_with_manual_elapsed(epoch());
            clock.recover_catalog_anchor(&basis)?;
            elapsed.advance(601_000_000_000)?;
            let transaction = TransactionId::new([22; 16])?;
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
            let proposal = final_proposal(&basis, transaction)?;
            let result = crate::with_catalog_publication_fault_sequence_after(&selected, || {
                catalog.commit_interruptibly_with_lifecycle_clock(
                    basis.identity(),
                    proposal,
                    None,
                    &clock,
                    &mut || false,
                )
            });
            assert_eq!(result.is_ok(), faults == 1);
            catalog.refresh_state()?;
            let current = catalog.pin()?;
            let visible = catalog.committed_transaction(transaction)?;
            assert_eq!(visible.is_some(), faults != 0);
            assert_eq!(current.number(), basis.number() + u64::from(faults != 0));
            let cold = RetentionTimeAuthority::establish_with_source(
                FixedWall(UnixNanoseconds::new(701_000_000_000)),
                LifecycleClockPolicy::default(),
            )?;
            cold.recover_catalog_anchor(&current)?;
            assert_eq!(
                cold.status().state(),
                if faults == 0 {
                    LifecycleClockState::ClockUncertain
                } else {
                    LifecycleClockState::Certain
                }
            );
            if let Some(commit) = visible {
                assert_eq!(commit.predecessor(), basis.identity());
                assert_eq!(commit.identity(), current.identity());
                let mut expected = other(&basis);
                expected.push(b"final publication payload".to_vec());
                expected.sort();
                let mut actual = other(&current);
                actual.sort();
                assert_eq!(actual, expected);
            }
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn clock_publication_cannot_accept_a_wall_jump_or_a_caller_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    fixture(|catalog| {
        let basis = catalog.pin()?;
        let clock = RetentionTimeAuthority::establish_with_source(
            FixedWall(UnixNanoseconds::new(701_000_000_000)),
            LifecycleClockPolicy::default(),
        )?;
        clock.recover_catalog_anchor(&basis)?;
        assert_eq!(clock.status().state(), LifecycleClockState::ClockUncertain);
        catalog
            .commit_interruptibly_with_lifecycle_clock(
                basis.identity(),
                final_proposal(&basis, TransactionId::new([23; 16])?)?,
                None,
                &clock,
                &mut || false,
            )?
            .ok_or("no commit")?;
        let cold = RetentionTimeAuthority::establish_with_source(
            FixedWall(UnixNanoseconds::new(701_000_000_000)),
            LifecycleClockPolicy::default(),
        )?;
        cold.recover_catalog_anchor(&catalog.pin()?)?;
        assert_eq!(cold.status().state(), LifecycleClockState::ClockUncertain);
        Ok(())
    })?;
    fixture(|catalog| {
        let basis = catalog.pin()?;
        let (clock, _) = RetentionTimeAuthority::establish_with_manual_elapsed(epoch());
        let (foreign, _) = RetentionTimeAuthority::establish_with_manual_elapsed(
            UnixNanoseconds::new(200_000_000_000),
        );
        let replacement = foreign.catalog_anchor_record(
            crate::IngestTime::from_authenticated_durable(UnixNanoseconds::new(200_000_000_000)),
        )?;
        let objects = vec![
            CatalogObject::new(b"final publication payload".to_vec())?,
            CatalogObject::new(replacement)?,
        ];
        let proposal = CatalogProposal::new(
            TransactionId::new([24; 16])?,
            FormatEpoch::CATALOG_V2,
            objects,
        )?;
        assert_eq!(
            catalog
                .commit_interruptibly_with_lifecycle_clock(
                    basis.identity(),
                    proposal,
                    None,
                    &clock,
                    &mut || false
                )
                .expect_err("caller cannot replace Clock authority")
                .code(),
            CatalogFailureCode::InvalidInput
        );
        assert_eq!(catalog.pin()?.identity(), basis.identity());
        Ok(())
    })
}

#[test]
fn stale_clock_publication_is_refused_before_recovering_the_caller_clock()
-> Result<(), Box<dyn std::error::Error>> {
    fixture(|catalog| {
        let predecessor = catalog.pin()?;
        catalog.commit(
            predecessor.identity(),
            final_proposal(&predecessor, TransactionId::new([25; 16])?)?,
            None,
        )?;
        let current = catalog.pin()?;
        let (clock, _) = RetentionTimeAuthority::establish_with_manual_elapsed(
            UnixNanoseconds::new(999_000_000_000),
        );
        let before = clock.status();
        let failure = catalog
            .commit_interruptibly_with_lifecycle_clock(
                predecessor.identity(),
                final_proposal(&predecessor, TransactionId::new([26; 16])?)?,
                None,
                &clock,
                &mut || false,
            )
            .expect_err("stale basis");
        assert_eq!(failure.code(), CatalogFailureCode::StaleGeneration);
        assert_eq!(clock.status(), before);
        assert_eq!(catalog.pin()?.identity(), current.identity());
        Ok(())
    })
}
