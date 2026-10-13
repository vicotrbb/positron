//! Bounded Catalog-backed maintenance recovery fuzzing.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::catalog::{
    CatalogFileEvent, CatalogObject, CatalogProposal, CatalogSecret, FormatEpoch, InstanceId,
    TransactionId, with_catalog_fault,
};
use crate::{Catalog, MountQualification, PrimaryDataVolume};

use super::{
    MaintenanceCheckpoint, MaintenanceCoordinator, MaintenanceFailure, MaintenanceTask,
    MaintenanceTaskClass, MaintenanceTaskId, MaintenanceTaskPhase,
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct FuzzRoot(PathBuf);

impl FuzzRoot {
    fn new() -> Option<Self> {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "positron-maintenance-catalog-fuzz-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).ok()?;
        Some(Self(path))
    }
}

impl Drop for FuzzRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Drives durable maintenance transitions through the Catalog publication
/// point, then independently recovers a new coordinator from a reopened
/// Catalog. The input selects only bounded transitions and deterministic
/// Catalog persistence faults; it never supplies task records directly.
pub fn fuzz_maintenance_catalog_stateful(data: &[u8]) {
    if data.len() > 96 {
        return;
    }
    let Some(root) = FuzzRoot::new() else {
        return;
    };
    let Some(volume) = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost).ok()
    else {
        return;
    };
    #[cfg(not(test))]
    let authority = crate::catalog::fuzz_authority(volume);
    #[cfg(test)]
    let authority = crate::catalog::tests::support::establish_catalog_authority_with_pool_units(
        volume,
        70_000_001,
        1_048_576 + 16_384,
    )
    .ok();
    let Some(authority) = authority else {
        return;
    };
    let instance = InstanceId::new(nonzero_id(1)).expect("fixed instance identity is nonzero");
    let Ok(catalog) = Catalog::open(&authority, instance, secret()) else {
        return;
    };
    if install_basis(&catalog).is_err() {
        return;
    }

    let mut identity_bytes = [0x31; 16];
    if let Some(selector) = data.first() {
        identity_bytes[0] = (*selector).max(1);
    }
    let identity = MaintenanceTaskId::new(identity_bytes).expect("nonzero task identity");
    let task = if data.first().is_some_and(|selector| selector & 0x40 != 0) {
        MaintenanceTask::with_contract(
            identity,
            MaintenanceTaskClass::SchemaPromotion,
            super::MaintenanceScope::System,
            super::MaintenanceTrigger::Event,
            super::MaintenancePreconditions::new(1, 1).expect("fixed precondition"),
            vec![super::MaintenanceObjectId::new([0x41; 32]).expect("fixed opaque reference")],
            Vec::new(),
            crate::ResourceAmounts::new([1; 11]),
        )
        .expect("bounded opaque task")
    } else {
        MaintenanceTask::new(identity, MaintenanceTaskClass::SchemaPromotion)
    };
    let coordinator = MaintenanceCoordinator::new();

    for (step, command) in data.iter().copied().take(32).enumerate() {
        let now = u64::try_from(step).expect("bounded fuzz step") + 10;
        let fault = command & 0x80 != 0;
        match command % 7 {
            0 => {
                let submission = || coordinator.submit_and_persist(&catalog, task.clone(), now);
                if fault {
                    let result = with_catalog_fault(fault_event(command), submission);
                    if result == Err(MaintenanceFailure::CatalogUnavailable) {
                        // Preserve the original submission timestamp and task
                        // while acknowledging a possibly published record.
                        submission().expect("exact submission retry resolves publication");
                    }
                } else {
                    let _ = submission();
                }
            },
            1 => {
                let pause = || coordinator.pause_and_persist(&catalog, identity, 1, now + 4, now);
                if fault {
                    let _ = with_catalog_fault(fault_event(command), pause);
                } else {
                    let _ = pause();
                }
            },
            2 => {
                let resume = || coordinator.resume_and_persist(&catalog, identity);
                if fault {
                    let _ = with_catalog_fault(fault_event(command), resume);
                } else {
                    let _ = resume();
                }
            },
            3 => {
                let started = if fault {
                    with_catalog_fault(fault_event(command), || {
                        coordinator.start_next_with_reservation_and_persist(
                            &catalog, &authority, now, false,
                        )
                    })
                } else {
                    coordinator
                        .start_next_with_reservation_and_persist(&catalog, &authority, now, false)
                };
                if let Ok(Some(execution)) = started {
                    let progress = vec![command, u8::try_from(step).expect("bounded fuzz step")];
                    let checkpoint = MaintenanceCheckpoint::new(1, 0, progress)
                        .expect("bounded checkpoint is valid");
                    let checkpoint_result = || {
                        execution.checkpoint_and_persist(&coordinator, &catalog, checkpoint.clone())
                    };
                    if fault {
                        let _ = with_catalog_fault(
                            fault_event(command.wrapping_add(1)),
                            checkpoint_result,
                        );
                    } else {
                        let _ = checkpoint_result();
                    }
                }
            },
            4 => {
                let started = coordinator
                    .start_next_with_reservation_and_persist(&catalog, &authority, now, false);
                if let Ok(Some(execution)) = started {
                    let completion =
                        || execution.complete_and_persist(&coordinator, &catalog, true);
                    if fault {
                        let result = with_catalog_fault(fault_event(command), completion);
                        if result == Err(MaintenanceFailure::CatalogUnavailable) {
                            // The execution remains the exact retry capability after
                            // an unacknowledged terminal publication. Resolve it
                            // before dropping its reservation or comparing recovery.
                            completion().expect("exact completion retry resolves publication");
                        }
                    } else {
                        let _ = completion();
                    }
                }
            },
            5 => {
                let _ = coordinator.replace_from_catalog(&catalog);
            },
            _ => {
                if let Ok(session) = crate::RootRewrapSession::admit(&authority) {
                    let reclaim = || {
                        coordinator.reclaim_terminal_records_for_root_retirement(&session, &catalog)
                    };
                    if fault {
                        let _ = with_catalog_fault(fault_event(command), reclaim);
                    } else {
                        let _ = reclaim();
                    }
                    // Reconcile the same owner receipt after injected ambiguity;
                    // no unrelated submission or record deletion is synthesized.
                    let _ = coordinator
                        .reclaim_terminal_records_for_root_retirement(&session, &catalog);
                }
            },
        }
    }

    let expected = coordinator.status(identity).ok().map(status_shape);
    #[cfg(test)]
    match data {
        [0, 4, 6] | [0, 4, 132, 6] => assert!(
            expected.is_none(),
            "reference-free completion is actually reclaimed"
        ),
        [0, 221] => assert_eq!(
            coordinator
                .status(identity)
                .expect("completion reconciled")
                .phase(),
            MaintenanceTaskPhase::Succeeded,
        ),
        [64, 0, 4, 6] => assert_eq!(
            coordinator
                .status(identity)
                .expect("opaque descriptor retained")
                .phase(),
            MaintenanceTaskPhase::Succeeded
        ),
        _ => {},
    }

    drop(catalog);
    let Ok(reopened) = Catalog::open(&authority, instance, secret()) else {
        return;
    };
    let recovered = MaintenanceCoordinator::restore_from_catalog(&reopened)
        .expect("an authenticated Catalog generation must restore maintenance state");
    let actual = recovered.status(identity).ok().map(status_shape);
    assert_eq!(actual, expected.map(recovered_shape));
}

fn install_basis(catalog: &Catalog<'_>) -> Result<(), MaintenanceFailure> {
    catalog
        .commit(
            catalog
                .pin()
                .map_err(|_| MaintenanceFailure::CatalogUnavailable)?
                .identity(),
            CatalogProposal::new(
                TransactionId::new(nonzero_id(2))
                    .map_err(|_| MaintenanceFailure::CatalogUnavailable)?,
                FormatEpoch::CATALOG_V1,
                vec![
                    CatalogObject::new(b"maintenance fuzz basis".to_vec())
                        .map_err(|_| MaintenanceFailure::CatalogUnavailable)?,
                ],
            )
            .map_err(|_| MaintenanceFailure::CatalogUnavailable)?,
            None,
        )
        .map_err(|_| MaintenanceFailure::CatalogUnavailable)?;
    Ok(())
}

type StatusShape = (MaintenanceTaskPhase, Option<(u64, Vec<u8>)>, Option<u64>);

fn status_shape(status: super::MaintenanceTaskStatus) -> StatusShape {
    (
        status.phase(),
        status
            .checkpoint()
            .map(|checkpoint| (checkpoint.sequence(), checkpoint.opaque_progress().to_vec())),
        status.pause_until(),
    )
}

fn recovered_shape(mut shape: StatusShape) -> StatusShape {
    if shape.0 == MaintenanceTaskPhase::Running {
        shape.0 = MaintenanceTaskPhase::Queued;
    }
    shape
}

fn secret() -> CatalogSecret {
    CatalogSecret::from_owned(Box::new([0x71; 32]), Box::new([0x72; 32]))
}

fn nonzero_id(last: u8) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    bytes[15] = last.max(1);
    bytes
}

fn fault_event(selector: u8) -> CatalogFileEvent {
    let events = [
        CatalogFileEvent::WriteObject,
        CatalogFileEvent::SynchronizeObject,
        CatalogFileEvent::WriteCommit,
        CatalogFileEvent::SynchronizeCommit,
        CatalogFileEvent::WriteMarker,
        CatalogFileEvent::SynchronizeGenerationDirectory,
    ];
    events[usize::from(selector) % events.len()]
}

#[cfg(test)]
mod tests {
    #[test]
    fn ambiguous_submission_preserves_live_and_cold_owner_agreement() {
        super::fuzz_maintenance_catalog_stateful(&[
            239, 203, 205, 76, 139, 139, 139, 148, 195, 53, 52, 116, 53, 53, 52, 42, 50,
        ]);
    }

    #[test]
    fn ambiguous_completion_retries_its_retained_execution_before_cold_comparison() {
        super::fuzz_maintenance_catalog_stateful(&[0, 221]);
        super::fuzz_maintenance_catalog_stateful(&[
            0x30, 0x31, 0xce, 0xdd, 0x26, 0x35, 0x30, 0x39, 0x32, 0x33, 0x34, 0x33, 0x0a, 0x4e,
            0x4e, 0x4e,
        ]);
    }

    #[test]
    fn reclamation_commands_preserve_authenticated_cold_owner_outcomes() {
        for input in [
            vec![0, 4, 6],
            vec![0, 4, 132, 6],
            vec![64, 0, 4, 6],
            vec![64, 0, 3, 4, 6],
            vec![0, 3, 4, 6],
        ] {
            super::fuzz_maintenance_catalog_stateful(&input);
        }
    }
}
