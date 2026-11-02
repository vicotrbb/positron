use super::*;

#[test]
fn terminal_native_verification_reference_remains_a_retirement_fence()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let authority = crate::catalog::tests::support::establish_catalog_authority_with_pool_units(
        PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?,
        70_000_001,
        30_000_000,
    )?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(nonzero_id(1))?,
        CatalogSecret::from_owned(Box::new([0x61; 32]), Box::new([0x62; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(2))?,
            FormatEpoch::CATALOG_V2,
            vec![CatalogObject::new(b"native-reference retirement".to_vec())?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let binding = RepositoryOperationBinding::new([91; 16], [92; 32]).expect("binding");
    let task = coordinator
        .submit_backup_operation_with_resources_and_persist(
            &catalog,
            binding,
            MaintenancePreconditions::new(1, 1).expect("preconditions"),
            ResourceAmounts::new([4_194_304, 1, 1, 0, 1, 0, 1, 1, 1, 8, 16_384]),
            7,
        )
        .expect("submit");
    let execution = coordinator
        .start_backup_operation_with_reservation_and_persist(
            &catalog,
            &authority,
            8,
            false,
            task.identity(),
        )
        .expect("admit")
        .ok_or("execution")?;
    execution
        .checkpoint_and_persist(
            &coordinator,
            &catalog,
            binding
                .backup_verification_checkpoint(
                    2,
                    b"legacy handler body",
                    crate::BackupVerificationReference {
                        identity: [0x71; 32],
                        sequence: 1,
                        predecessor: [0; 32],
                    },
                )
                .expect("typed native reference"),
        )
        .expect("publish");
    execution
        .complete_and_persist(&coordinator, &catalog, true)
        .expect("terminal task");
    drop(execution);
    let session = crate::RootRewrapSession::admit(&authority)?;
    assert_eq!(
        coordinator
            .reclaim_terminal_records_for_root_retirement(&session, &catalog)
            .expect("reference reclamation"),
        0,
        "a typed native artifact is not a reference-free repository association"
    );
    drop(session);
    assert!(crate::ActiveSegmentLedger::guard_local_root_retirement(&authority, &catalog).is_err());
    Ok(())
}
