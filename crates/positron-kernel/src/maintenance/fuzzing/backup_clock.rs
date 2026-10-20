//! Mutate the existing Backup checkpoint/clock transaction and cold recovery.
use super::*;
use crate::{RepositoryOperationBinding, ResourceAmounts, RetentionTimeAuthority};
use positron_domain::time::UnixNanoseconds;

pub(super) fn run(
    catalog: &Catalog<'_>,
    authority: &crate::StorageKernelResourceAuthority,
    data: &[u8],
) {
    let epoch = UnixNanoseconds::new(100_000_000_000);
    let (clock, _) = RetentionTimeAuthority::establish_with_manual_elapsed(epoch);
    let anchor = clock
        .catalog_anchor_record(crate::IngestTime::from_authenticated_durable(epoch))
        .expect("fixed initial clock anchor");
    let basis = catalog.pin().expect("authenticated basis");
    let mut objects = basis
        .plaintext_objects()
        .map(|bytes| CatalogObject::new(bytes.to_vec()).expect("bounded existing object"))
        .collect::<Vec<_>>();
    objects.push(CatalogObject::new(anchor).expect("bounded clock record"));
    catalog
        .commit(
            basis.identity(),
            CatalogProposal::new(
                TransactionId::new(nonzero_id(3)).expect("fixed transaction"),
                basis.format_epoch().expect("basis epoch"),
                objects,
            )
            .expect("bounded initial clock proposal"),
            None,
        )
        .expect("initial anchor publication");
    let binding = RepositoryOperationBinding::new([0x71; 16], [0x72; 32]).expect("binding");
    let resources = ResourceAmounts::new([8_519_680, 1, 1, 0, 1, 0, 1, 1, 1, 8, 16_384]);
    let mut coordinator = MaintenanceCoordinator::new();
    let task = coordinator
        .submit_backup_operation_with_resources_and_persist(
            catalog,
            binding,
            super::super::MaintenancePreconditions::new(catalog.pin().expect("basis").number(), 1)
                .expect("preconditions"),
            resources,
            100,
        )
        .expect("bounded Backup task");
    let before = coordinator.status(task.identity()).expect("submitted task");
    let generation = catalog.pin().expect("submitted basis").number();
    let memory = authority
        .governor()
        .inspect()
        .expect("resource accounting")
        .usage(crate::ResourceDimension::MemoryBytes);
    assert!(
        coordinator
            .start_backup_operation_with_reservation_and_persist(
                catalog,
                authority,
                99,
                false,
                task.identity(),
            )
            .expect("pre-submission admission")
            .is_none()
    );
    assert_eq!(
        coordinator.status(task.identity()).expect("queued task"),
        before
    );
    assert_eq!(catalog.pin().expect("unchanged basis").number(), generation);
    assert_eq!(
        authority
            .governor()
            .inspect()
            .expect("unchanged accounting")
            .usage(crate::ResourceDimension::MemoryBytes),
        memory
    );
    let mut previous_time = 100;
    for (step, command) in data.iter().copied().skip(1).take(12).enumerate() {
        let (clock, elapsed) = RetentionTimeAuthority::establish_with_manual_elapsed(epoch);
        clock
            .recover_catalog_anchor(&catalog.pin().expect("cold basis"))
            .expect("clock recovery");
        let mut execution = coordinator
            .start_backup_operation_with_reservation_and_persist(
                catalog,
                authority,
                previous_time,
                false,
                task.identity(),
            )
            .expect("admitted exact task")
            .expect("queued Backup dispatch");
        let sequence = u64::try_from(step).expect("bounded step") + 2;
        let checkpoint = binding
            .backup_checkpoint(sequence, &[command])
            .expect("bounded checkpoint");
        execution
            .checkpoint_and_persist(&coordinator, catalog, checkpoint.clone())
            .expect("checkpoint");
        elapsed
            .advance((u64::from(command % 4) + 1) * 1_000_000_000)
            .expect("bounded elapsed");
        let observed = clock.governance_now_seconds().expect("trusted elapsed");
        execution
            .requeue_backup_with_resources_and_persist(
                &coordinator,
                catalog,
                binding,
                resources,
                observed,
            )
            .expect("ordinary durable requeue");
        drop(execution);
        let before = coordinator
            .status(task.identity())
            .expect("queued checkpoint");
        let result = match command % 4 {
            0 => catalog.checkpoint_lifecycle_time(&clock),
            1 => with_catalog_fault(CatalogFileEvent::WriteMarker, || {
                catalog.checkpoint_lifecycle_time(&clock)
            }),
            2 => with_catalog_fault(CatalogFileEvent::SynchronizeGenerationDirectory, || {
                catalog.checkpoint_lifecycle_time(&clock)
            }),
            _ => crate::with_catalog_publication_fault_sequence_after(
                &[
                    (
                        crate::CatalogPublicationFault::SynchronizeGenerationDirectory,
                        0,
                    ),
                    (
                        crate::CatalogPublicationFault::SynchronizeGenerationDirectory,
                        0,
                    ),
                ],
                || catalog.checkpoint_lifecycle_time(&clock),
            ),
        };
        assert_eq!(
            coordinator.status(task.identity()).expect("unchanged task"),
            before
        );
        catalog.refresh_state().expect("canonical recovery basis");
        coordinator = MaintenanceCoordinator::restore_from_catalog(catalog).expect("task recovery");
        let recovered = coordinator.status(task.identity()).expect("same task");
        assert_eq!(recovered.phase(), MaintenanceTaskPhase::Queued);
        assert_eq!(recovered.checkpoint(), Some(&checkpoint));
        let (cold, _) = RetentionTimeAuthority::establish_with_manual_elapsed(epoch);
        cold.recover_catalog_anchor(&catalog.pin().expect("published basis"))
            .expect("cold clock");
        let actual = cold.governance_now_seconds().expect("retained clock");
        assert!(previous_time <= actual && actual <= observed);
        if result.is_ok() {
            assert_eq!(actual, observed);
        }
        previous_time = actual;
    }
}
