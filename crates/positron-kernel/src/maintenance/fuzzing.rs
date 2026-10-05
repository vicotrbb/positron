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
    let Some(authority) = crate::catalog::fuzz_authority(volume) else {
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
    let task = MaintenanceTask::new(identity, MaintenanceTaskClass::SchemaPromotion);
    let coordinator = MaintenanceCoordinator::new();

    for (step, command) in data.iter().copied().take(32).enumerate() {
        let now = u64::try_from(step).expect("bounded fuzz step") + 10;
        let fault = command & 0x80 != 0;
        match command % 6 {
            0 => {
                let submission = || coordinator.submit_and_persist(&catalog, task.clone(), now);
                if fault {
                    let _ = with_catalog_fault(fault_event(command), submission);
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
                        let _ = with_catalog_fault(fault_event(command), completion);
                    } else {
                        let _ = completion();
                    }
                }
            },
            _ => {
                let _ = coordinator.replace_from_catalog(&catalog);
            },
        }
    }

    let expected = coordinator.status(identity).ok().map(status_shape);
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

fn status_shape(
    status: super::MaintenanceTaskStatus,
) -> (MaintenanceTaskPhase, Option<(u64, Vec<u8>)>, Option<u64>) {
    (
        status.phase(),
        status
            .checkpoint()
            .map(|checkpoint| (checkpoint.sequence(), checkpoint.opaque_progress().to_vec())),
        status.pause_until(),
    )
}

fn recovered_shape(
    mut shape: (MaintenanceTaskPhase, Option<(u64, Vec<u8>)>, Option<u64>),
) -> (MaintenanceTaskPhase, Option<(u64, Vec<u8>)>, Option<u64>) {
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
