use super::*;

#[test]
fn startup_recovers_an_accepted_multi_block_history_without_a_shutdown_checkpoint()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    for index in 0..64 {
        assert_eq!(
            services
                .ingest_otlp_logs(
                    &ingest,
                    request(&format!("accepted-{index}")).encode_to_vec()
                )?
                .accepted_records(),
            1
        );
    }
    drop(services);
    drop(initialized);
    let initialized = fixture.reopen()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let catalog = open_catalog(&initialized)?;
    let checkpoint = load_schema_checkpoint(
        &catalog.pin()?,
        initialized.tenant,
        initialized.resource_governor(),
    )
    .map_err(|_| "recovered schema checkpoint load")?
    .ok_or("recovered schema checkpoint")?;
    assert!(!checkpoint.is_empty());
    drop((catalog, services));
    Ok(())
}

#[test]
fn service_startup_restores_catalog_backed_maintenance_before_serving() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::new()?;
    let (initialized, _, _) = fixture.initialized()?;
    let task = MaintenanceTask::new(
        MaintenanceTaskId::new([0x91; 16]).expect("stable maintenance identity"),
        MaintenanceTaskClass::SchemaPromotion,
    );
    let identity = task.identity();
    let catalog = open_catalog(&initialized)?;
    initialized
        .maintenance_coordinator()
        .submit_and_persist(&catalog, task, 7)
        .expect("durable task submission");
    drop(catalog);

    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .status(identity)
            .expect("restored task")
            .task()
            .class(),
        MaintenanceTaskClass::SchemaPromotion
    );
    drop(services);
    Ok(())
}

#[test]
fn startup_rebuild_publishes_before_service_and_preserves_unrelated_objects()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _) = fixture.initialized()?;
    let unrelated = publish_unrelated(&initialized)?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("rebuild").encode_to_vec())?
            .accepted_records(),
        1
    );
    drop(services);
    let services = ServiceHandle::new(Arc::clone(&initialized))?;

    let catalog = open_catalog(&initialized)?;
    let snapshot = catalog.pin()?;
    assert_eq!(
        snapshot.object(unrelated)?,
        Some(b"unrelated-runtime-state".as_slice())
    );
    assert!(
        load_schema_checkpoint(
            &snapshot,
            initialized.tenant,
            initialized.resource_governor()
        )
        .map_err(|_| "schema checkpoint load failed")?
        .is_some()
    );
    drop((snapshot, catalog, services));
    Ok(())
}

#[test]
fn serving_updates_live_schema_without_catalog_publication() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let initial_audits = schema_audit_count(&initialized)?;

    for body in ["first", "latest"] {
        assert_eq!(
            services
                .ingest_otlp_logs(&ingest, request(body).encode_to_vec())?
                .accepted_records(),
            1
        );
    }
    assert_eq!(schema_audit_count(&initialized)?, initial_audits);
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
                .with_cpu_work_units(15)?,
        )?,
        ["first", "latest"]
    );

    services.prepare_shutdown_schema_checkpoint()?;
    services.publish_prepared_shutdown_schema_checkpoint(&mut || false)?;
    assert_eq!(schema_audit_count(&initialized)?, initial_audits + 1);
    Ok(())
}

#[test]
fn production_query_publishes_a_durable_snapshot_lease_expiry_task() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.ingest_otlp_logs(&ingest, request("lease-task").encode_to_vec())?;
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
                .with_cpu_work_units(15)?,
        )?,
        ["lease-task"]
    );
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .durable_records()
            .expect("query expiry task is coordinator-owned")
            .len(),
        1,
        "the runtime query path asks the kernel lease publisher to atomically create expiry work"
    );
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let facts = initialized.doctor_runtime_facts(actor)?;
    assert_eq!(
        facts.snapshot_leases(),
        0,
        "a completed query must not be reported as a live Snapshot Lease"
    );
    assert_eq!(facts.durable_operations(), 0);
    let catalog = open_catalog(&initialized)?;
    assert!(
        initialized
            .maintenance_coordinator()
            .start_next_with_reservation_and_persist(
                &catalog,
                &initialized._authority,
                u64::MAX,
                false,
            )
            .expect("released query expiry task is terminal")
            .is_none(),
        "collecting the ordinary query releases its lease and cancels its paired expiry task"
    );
    Ok(())
}

#[test]
fn runtime_maintenance_worker_wake_dispatches_and_completes_a_due_snapshot_lease_expiry()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (mut initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    Arc::get_mut(&mut initialized)
        .ok_or("sole initialized instance")?
        .install_retention_time_for_test(retention_time)?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let scope = SegmentScope::new(
        initialized.tenant,
        positron_domain::routing::SignalKind::Logs,
        initialized.logs_shard,
    );
    let catalog = open_catalog(&initialized)?;
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    let protection = super::super::super::tenant_segment_key(&initialized, &identity, scope)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        protection,
    )?;
    let coordinator = initialized.maintenance_coordinator();
    let lease = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
        coordinator,
        0,
        std::num::NonZeroU64::new(1).ok_or("nonzero ttl")?,
        catalog.pin()?.identity(),
    )?;
    let lease_id = lease.identity();
    let task = MaintenanceTaskId::new(lease_id.to_bytes()).expect("lease task id");
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let facts = initialized.doctor_runtime_facts(actor)?;
    assert_eq!(
        facts.snapshot_leases(),
        1,
        "Doctor reads the paired live lease through the coordinator's durable expiry inventory"
    );
    drop(lease);
    drop(ledger);
    drop(catalog);
    elapsed.advance(1_000_000_000)?;

    assert!(services.wake_maintenance_worker()?);

    let catalog = open_catalog(&initialized)?;
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    let protection = super::super::super::tenant_segment_key(&initialized, &identity, scope)?;
    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        protection,
    )?;
    assert!(
        reopened
            .resume_snapshot_lease(lease_id, 11)
            .expect_err("the runtime handler removed the expired lease")
            .code()
            == positron_kernel::LedgerFailureCode::SnapshotExpired,
        "the runtime handler removes the expired lease"
    );
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .status(task)
            .expect("terminal task")
            .phase(),
        MaintenanceTaskPhase::Succeeded
    );
    Ok(())
}
