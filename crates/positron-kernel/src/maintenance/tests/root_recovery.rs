use super::*;

#[test]
fn recovered_digest_scrub_keeps_its_exact_record_without_blocking_root_proof()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let authority = crate::catalog::tests::support::establish_catalog_authority_with_pool_units(
        PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?,
        70_000_001,
        70_000_001,
    )?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(nonzero_id(91))?,
        CatalogSecret::from_owned(Box::new([0xb1; 32]), Box::new([0xb2; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(92))?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"recovered scrub root proof".to_vec())?],
        )?,
        None,
    )?;
    let scope = MaintenanceScope::segment(
        positron_domain::identity::TenantId::from_bytes([0x43; 16])?,
        positron_domain::routing::SignalKind::Logs,
        positron_domain::routing::VirtualShardId::new(1)?,
    );
    let identity = MaintenanceTaskId::new([93; 16]).expect("scrub identity");
    let task = MaintenanceTask::integrity_scrub(
        identity,
        scope,
        MaintenanceTrigger::Event,
        MaintenancePreconditions::new(catalog.pin()?.number(), 1).expect("basis"),
        [94; 32],
        0,
    )
    .expect("digest descriptor");
    let coordinator = MaintenanceCoordinator::new();
    coordinator
        .submit_and_persist(&catalog, task.clone(), 1)
        .expect("persist scrub");
    let execution = coordinator
        .start_integrity_scrub_task_with_reservation_and_persist(
            &catalog, &authority, 2, false, identity,
        )
        .expect("start scrub")
        .ok_or("scrub execution")?;
    drop(execution);
    let basis = catalog.pin()?;
    let recovered =
        MaintenanceCoordinator::restore_from_catalog(&catalog).expect("service recovery");
    assert_eq!(
        recovered.status(identity).expect("recovered task").phase(),
        MaintenanceTaskPhase::Queued
    );
    let session = crate::RootRewrapSession::admit(&authority)?;
    assert_eq!(
        recovered.reclaim_terminal_records_for_root_retirement(&session, &catalog),
        Ok(0),
        "recovery must preserve the nonterminal scrub without inventing key corruption"
    );
    assert_eq!(catalog.pin()?.identity(), basis.identity());
    let proof = recovered
        .guard_root_retirement_references(&session, &catalog, &basis)
        .expect("a recovered digest-only descriptor holds no physical reference");
    let guard = crate::ActiveSegmentLedger::guard_local_root_retirement_with_references(
        &authority, &catalog, &proof,
    )?;
    drop((guard, proof));
    for changed_source in [false, true] {
        let altered = MaintenanceCoordinator::new();
        let mut changed = task.clone();
        if changed_source {
            changed = MaintenanceTask::integrity_scrub(
                identity,
                scope,
                MaintenanceTrigger::Event,
                task.preconditions,
                [95; 32],
                0,
            )
            .expect("changed source descriptor");
        }
        altered.submit_at(changed, 1).expect("altered descriptor");
        altered
            .start_next(2, false)
            .expect("start altered descriptor");
        if !changed_source {
            altered
                .checkpoint(
                    identity,
                    MaintenanceCheckpoint::new(1, 0, vec![7]).expect("opaque progress"),
                )
                .expect("checkpoint");
        }
        let altered =
            MaintenanceCoordinator::restore(altered.durable_records().expect("altered record"))
                .expect("altered recovery");
        assert_eq!(
            altered.reclaim_terminal_records_for_root_retirement(&session, &catalog),
            Err(MaintenanceFailure::PreconditionFailed)
        );
        assert!(
            altered
                .guard_root_retirement_references(&session, &catalog, &basis)
                .is_err()
        );
        assert_eq!(catalog.pin()?.identity(), basis.identity());
    }
    Ok(())
}
