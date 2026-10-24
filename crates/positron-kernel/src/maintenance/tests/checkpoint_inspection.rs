use super::*;

#[test]
fn readonly_checkpoint_refuses_matching_corruption_and_duplicate_records() {
    let root = CatalogRoot::new().expect("valid fixture");
    let volume =
        PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost).expect("valid fixture");
    let authority =
        crate::catalog::tests::support::establish_catalog_authority(volume).expect("valid fixture");
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(nonzero_id(1)).expect("valid fixture"),
        CatalogSecret::from_owned(Box::new([0x51; 32]), Box::new([0x52; 32])),
    )
    .expect("valid fixture");
    let coordinator = MaintenanceCoordinator::new();
    let task = task(
        9,
        MaintenanceTaskClass::Compaction,
        MaintenanceTrigger::Event,
        MaintenancePriority::Ordinary,
        Vec::new(),
    );
    let identity = task.identity();
    coordinator.submit(task).expect("valid fixture");
    coordinator.start_next(1, false).expect("valid fixture");
    coordinator
        .checkpoint(
            identity,
            MaintenanceCheckpoint::new(1, 0, vec![9, 8]).expect("valid fixture"),
        )
        .expect("valid fixture");
    let first = coordinator
        .durable_records()
        .expect("valid fixture")
        .into_iter()
        .next()
        .ok_or("record")
        .expect("valid fixture");
    coordinator
        .checkpoint(
            identity,
            MaintenanceCheckpoint::new(2, 0, vec![7, 6]).expect("valid fixture"),
        )
        .expect("valid fixture");
    let second = coordinator
        .durable_records()
        .expect("valid fixture")
        .into_iter()
        .next()
        .ok_or("record")
        .expect("valid fixture");
    let malformed = first
        .as_bytes()
        .get(..24)
        .ok_or("record header")
        .expect("valid fixture")
        .to_vec();
    for (transaction, objects, expected) in [
        (
            1,
            vec![first.catalog_object().expect("first record")],
            Ok(Some(
                MaintenanceCheckpoint::new(1, 0, vec![9, 8]).expect("first checkpoint"),
            )),
        ),
        (
            2,
            vec![CatalogObject::new(malformed.clone()).expect("valid fixture")],
            Err(MaintenanceFailure::InvalidInput),
        ),
        (
            3,
            vec![
                first.catalog_object().expect("valid fixture"),
                second.catalog_object().expect("valid fixture"),
            ],
            Err(MaintenanceFailure::CatalogUnavailable),
        ),
        (
            4,
            vec![second.catalog_object().expect("valid fixture")],
            Ok(Some(
                MaintenanceCheckpoint::new(2, 0, vec![7, 6]).expect("valid fixture"),
            )),
        ),
    ] {
        catalog
            .commit(
                catalog.pin().expect("valid fixture").identity(),
                CatalogProposal::new(
                    TransactionId::new(nonzero_id(transaction)).expect("valid fixture"),
                    FormatEpoch::CATALOG_V1,
                    objects,
                )
                .expect("valid fixture"),
                None,
            )
            .expect("valid fixture");
        let snapshot = catalog.pin().expect("valid fixture");
        assert_eq!(
            MaintenanceCoordinator::inspect_checkpoint_snapshot(&snapshot, identity),
            expected
        );
        assert_eq!(
            MaintenanceCoordinator::inspect_checkpoint_snapshot(
                &snapshot,
                MaintenanceTaskId::new([99; 16]).expect("valid fixture")
            )
            .expect("valid fixture"),
            None
        );
        assert_eq!(
            catalog.pin().expect("valid fixture").identity(),
            snapshot.identity()
        );
    }
}
