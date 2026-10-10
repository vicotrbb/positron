use super::super::ServiceHandle;
use super::schema_maintenance::{Fixture, request};
use prost::Message;
use std::sync::Arc;

#[test]
fn migrated_tenant_without_completed_verifier_audits_retirement_refusal()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let tenant = initialized.default_tenant_id();
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.ingest_otlp_logs(
        &ingest,
        request("missing-verification-proof").encode_to_vec(),
    )?;
    services.begin_tenant_key_rotation(&administrator, tenant)?;
    for expected in [1, 2] {
        assert_eq!(
            services
                .advance_tenant_key_rotation(&administrator, tenant)?
                .active_epoch(),
            expected
        );
    }
    for remaining in [true, true, false] {
        assert_eq!(
            services
                .advance_tenant_key_migration(&administrator, tenant)?
                .remaining_segments(),
            remaining
        );
    }
    let unlock = age::x25519::Identity::generate();
    let bundle = fixture
        .recovery_export_directory()?
        .join("missing-proof.age");
    initialized.create_recovery_bundle(
        &bundle,
        &positron_kernel::RecoveryRecipients::parse(&[unlock.to_public().to_string()])?,
    )?;
    initialized
        .verify_recovery_bundle(&bundle, positron_kernel::RecoveryUnlock::Identity(&unlock))?;
    let before = {
        let _gate = services
            .catalog_operation
            .lock()
            .map_err(|_| "Catalog gate")?;
        super::schema_maintenance::open_catalog(&initialized)?
            .pin()?
            .object_identities()
            .collect::<Vec<_>>()
    };
    assert_eq!(
        services.retire_tenant_key_predecessors(&administrator, tenant),
        Err(super::super::ServiceFailure::CatalogBusy)
    );
    let _gate = services
        .catalog_operation
        .lock()
        .map_err(|_| "Catalog gate")?;
    let catalog = super::schema_maintenance::open_catalog(&initialized)?;
    assert_eq!(
        catalog.pin()?.object_identities().collect::<Vec<_>>(),
        before
    );
    let mut refusals = 0;
    for record in catalog.governance_audit_records()? {
        let entry = positron_governance::GovernanceAuditEntry::decode(&record)?;
        if entry.as_tenant_key_rotation().is_some_and(|entry| {
            entry.tenant() == tenant
                && entry.stage() == positron_governance::TenantKeyRotationStage::RetirementRefused
        }) {
            refusals += 1;
        }
    }
    assert_eq!(refusals, 1);
    Ok(())
}

#[test]
fn authenticated_premature_tenant_retirement_audits_without_changing_key_or_task_objects()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let tenant = initialized.default_tenant_id();
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let unlock = age::x25519::Identity::generate();
    let bundle = fixture
        .recovery_export_directory()?
        .join("premature-retirement.age");
    initialized.create_recovery_bundle(
        &bundle,
        &positron_kernel::RecoveryRecipients::parse(&[unlock.to_public().to_string()])?,
    )?;
    initialized
        .verify_recovery_bundle(&bundle, positron_kernel::RecoveryUnlock::Identity(&unlock))?;
    services.begin_tenant_key_rotation(&administrator, tenant)?;
    let before = {
        let _gate = services
            .catalog_operation
            .lock()
            .map_err(|_| "Catalog gate")?;
        super::schema_maintenance::open_catalog(&initialized)?
            .pin()?
            .object_identities()
            .collect::<Vec<_>>()
    };
    assert_eq!(
        services.retire_tenant_key_predecessors(&administrator, tenant),
        Err(super::super::ServiceFailure::CatalogBusy)
    );
    {
        let _gate = services
            .catalog_operation
            .lock()
            .map_err(|_| "Catalog gate")?;
        let catalog = super::schema_maintenance::open_catalog(&initialized)?;
        assert_eq!(
            catalog.pin()?.object_identities().collect::<Vec<_>>(),
            before
        );
        let mut refused = 0;
        for record in catalog.governance_audit_records()? {
            let entry = positron_governance::GovernanceAuditEntry::decode(&record)?;
            if entry.as_tenant_key_rotation().is_some_and(|entry| {
                entry.tenant() == tenant
                    && entry.stage()
                        == positron_governance::TenantKeyRotationStage::RetirementRefused
            }) {
                refused += 1;
            }
        }
        assert_eq!(
            refused, 1,
            "authenticated premature retirement needs a durable typed audit"
        );
    }
    drop((services, initialized));
    let initialized = fixture.reopen()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .tenant_key_rotation_status(&administrator, tenant)?
            .successor_epoch(),
        Some(2)
    );
    Ok(())
}

#[test]
fn tenant_retirement_ambiguous_publication_reconciles_only_its_consumed_verifier()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::{
        CatalogPublicationFault, MaintenanceTaskClass,
        with_catalog_publication_fault_sequence_after,
    };
    for fault in [
        CatalogPublicationFault::SynchronizeGenerationDirectory,
        CatalogPublicationFault::SynchronizeCommit,
    ] {
        let fixture = Fixture::new()?;
        let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
        let tenant = initialized.default_tenant_id();
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        services.ingest_otlp_logs(&ingest, request("retirement fault").encode_to_vec())?;
        services.begin_tenant_key_rotation(&administrator, tenant)?;
        for expected in [1, 2] {
            assert_eq!(
                services
                    .advance_tenant_key_rotation(&administrator, tenant)?
                    .active_epoch(),
                expected
            );
        }
        for remaining in [true, true, false] {
            assert_eq!(
                services
                    .advance_tenant_key_migration(&administrator, tenant)?
                    .remaining_segments(),
                remaining
            );
        }
        let recovery_identity = age::x25519::Identity::generate();
        let bundle = fixture
            .recovery_export_directory()?
            .join("retirement-fault.age");
        initialized.create_recovery_bundle(
            &bundle,
            &positron_kernel::RecoveryRecipients::parse(&[recovery_identity
                .to_public()
                .to_string()])?,
        )?;
        initialized.verify_recovery_bundle(
            &bundle,
            positron_kernel::RecoveryUnlock::Identity(&recovery_identity),
        )?;
        for complete in [false, false, true] {
            assert_eq!(
                services
                    .advance_tenant_key_verification(&administrator, tenant)?
                    .is_complete(),
                complete
            );
        }
        let failed = with_catalog_publication_fault_sequence_after(&[(fault, 0); 2], || {
            services.retire_tenant_key_predecessors(&administrator, tenant)
        });
        assert!(
            failed.is_err(),
            "ambiguous publication must not acknowledge success"
        );
        services.retire_tenant_key_predecessors(&administrator, tenant)?;
        assert!(
            !initialized
                .maintenance_coordinator()
                .statuses()
                .map_err(|_| "task inventory")?
                .iter()
                .any(|status| status.task().class() == MaintenanceTaskClass::EnvelopeVerification),
            "exact consumed verifier must not remain after confirmed retirement"
        );
        for complete in [false, false, true] {
            assert_eq!(
                services
                    .advance_tenant_key_verification(&administrator, tenant)?
                    .is_complete(),
                complete
            );
        }
        let fresh = initialized
            .maintenance_coordinator()
            .statuses()
            .map_err(|_| "fresh inventory")?
            .into_iter()
            .find(|status| status.task().class() == MaintenanceTaskClass::EnvelopeVerification)
            .ok_or("fresh verifier")?
            .task()
            .identity();
        services.retire_tenant_key_predecessors(&administrator, tenant)?;
        assert!(
            initialized.maintenance_coordinator().status(fresh).is_ok(),
            "retirement replay must not consume a fresh verifier"
        );
        drop((services, initialized));
        let initialized = fixture.reopen()?;
        ServiceHandle::new(Arc::clone(&initialized))?
            .retire_tenant_key_predecessors(&administrator, tenant)?;
        assert!(initialized.maintenance_coordinator().status(fresh).is_ok());
    }
    Ok(())
}

#[test]
fn tenant_retirement_requires_verified_recovery_and_consumes_exact_completed_proof()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query, administrator) = fixture.initialized_with_admin()?;
    let tenant = initialized.default_tenant_id();
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.ingest_otlp_logs(
        &ingest,
        request("retirement retains old data").encode_to_vec(),
    )?;
    services.begin_tenant_key_rotation(&administrator, tenant)?;
    for expected in [1, 2] {
        assert_eq!(
            services
                .advance_tenant_key_rotation(&administrator, tenant)?
                .active_epoch(),
            expected
        );
    }
    for remaining in [true, true, false] {
        assert_eq!(
            services
                .advance_tenant_key_migration(&administrator, tenant)?
                .remaining_segments(),
            remaining
        );
    }
    for complete in [false, false, true] {
        assert_eq!(
            services
                .advance_tenant_key_verification(&administrator, tenant)?
                .is_complete(),
            complete
        );
    }
    assert_eq!(
        services.retire_tenant_key_predecessors(&administrator, tenant),
        Err(super::super::ServiceFailure::KeyUnavailable)
    );
    let recovery_identity = age::x25519::Identity::generate();
    let bundle = fixture
        .recovery_export_directory()?
        .join("tenant-retirement.age");
    initialized.create_recovery_bundle(
        &bundle,
        &positron_kernel::RecoveryRecipients::parse(&[recovery_identity.to_public().to_string()])?,
    )?;
    assert_eq!(
        services.retire_tenant_key_predecessors(&administrator, tenant),
        Err(super::super::ServiceFailure::KeyUnavailable)
    );
    initialized.verify_recovery_bundle(
        &bundle,
        positron_kernel::RecoveryUnlock::Identity(&recovery_identity),
    )?;
    services.restart_tenant_key_verification(&administrator, tenant)?;
    for complete in [false, false, true] {
        assert_eq!(
            services
                .advance_tenant_key_verification(&administrator, tenant)?
                .is_complete(),
            complete
        );
    }
    services.retire_tenant_key_predecessors(&administrator, tenant)?;
    assert!(
        !initialized
            .maintenance_coordinator()
            .statuses()
            .expect("remaining owners")
            .iter()
            .any(|status| status.task().class()
                == positron_kernel::MaintenanceTaskClass::EnvelopeVerification)
    );
    services.retire_tenant_key_predecessors(&administrator, tenant)?;
    drop((services, initialized));
    let initialized = fixture.reopen()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let budget = positron_query::QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
        .with_cpu_work_units(15)?;
    let result =
        services.query_log_bodies(&query, "logs | range query_time 0 100 | limit 16", budget)?;
    assert_eq!(result, ["retirement retains old data"]);
    services.ingest_otlp_logs(
        &ingest,
        request("epoch two before second rotation").encode_to_vec(),
    )?;
    {
        let _gate = services
            .catalog_operation
            .lock()
            .map_err(|_| "Catalog gate")?;
        let catalog = super::schema_maintenance::open_catalog(&initialized)?;
        let basis = catalog.pin()?;
        let shard = positron_domain::routing::VirtualShardId::new(1)?;
        assert!(
            basis.has_active_ledger_scope(positron_kernel::SegmentScope::new(
                tenant,
                positron_domain::routing::SignalKind::Logs,
                shard
            ))?
        );
        assert!(
            !basis.has_active_ledger_scope(positron_kernel::SegmentScope::new(
                tenant,
                positron_domain::routing::SignalKind::Traces,
                shard
            ))?
        );
    }
    assert_eq!(
        services
            .begin_tenant_key_rotation(&administrator, tenant)?
            .successor_epoch(),
        Some(3)
    );
    assert_eq!(
        services
            .advance_tenant_key_rotation(&administrator, tenant)?
            .active_epoch(),
        3
    );
    for remaining in [true, true, true, false] {
        let progress = services
            .advance_tenant_key_migration(&administrator, tenant)
            .map_err(|error| format!("epoch 3 migration remaining={remaining}: {error:?}"))?;
        assert!(progress.migrated_segment());
        assert_eq!(progress.remaining_segments(), remaining);
    }
    // Query completion released the durable lease, but its opaque immutable
    // binding remains a managed reference until ordinary task reclamation.
    {
        let _gate = services
            .catalog_operation
            .lock()
            .map_err(|_| "Catalog gate")?;
        let catalog = super::schema_maintenance::open_catalog(&initialized)?;
        let coordinator = initialized.maintenance_coordinator();
        let records = coordinator.statuses().map_err(|_| "task inventory")?;
        assert_eq!(records.len(), 1);
        let expiry = records.first().ok_or("expiry owner")?;
        assert_eq!(
            expiry.task().class(),
            positron_kernel::MaintenanceTaskClass::SnapshotLeaseExpiry
        );
        assert_eq!(
            expiry.phase(),
            positron_kernel::MaintenanceTaskPhase::Cancelled
        );
        let expiry_identity = expiry.task().identity();
        for index in 0_u8..127 {
            let mut bytes = [0xb0; 16];
            bytes[15] = index;
            let identity =
                positron_kernel::MaintenanceTaskId::new(bytes).map_err(|_| "task identity")?;
            coordinator
                .submit_and_persist(
                    &catalog,
                    positron_kernel::MaintenanceTask::new(
                        identity,
                        positron_kernel::MaintenanceTaskClass::SchemaStatistics,
                    ),
                    u64::from(index) + 2,
                )
                .map_err(|_| "task submission")?;
            coordinator
                .cancel_and_persist(&catalog, identity)
                .map_err(|_| "task cancellation")?;
        }
        assert_eq!(
            coordinator.statuses().map_err(|_| "task inventory")?.len(),
            128
        );
        let replacement = positron_kernel::MaintenanceTaskId::new([0xb1; 16])
            .map_err(|_| "replacement identity")?;
        coordinator
            .submit_and_persist(
                &catalog,
                positron_kernel::MaintenanceTask::new(
                    replacement,
                    positron_kernel::MaintenanceTaskClass::SchemaStatistics,
                ),
                129,
            )
            .map_err(|_| "terminal reference reclamation")?;
        coordinator
            .cancel_and_persist(&catalog, replacement)
            .map_err(|_| "replacement cancellation")?;
        assert!(coordinator.status(expiry_identity).is_err());
        assert_eq!(
            coordinator.statuses().map_err(|_| "task inventory")?.len(),
            128
        );
    }
    for complete in [false, false, false, true] {
        assert_eq!(
            services
                .advance_tenant_key_verification(&administrator, tenant)
                .map_err(|error| format!("epoch 3 verification complete={complete}: {error:?}"))?
                .is_complete(),
            complete
        );
    }
    services
        .retire_tenant_key_predecessors(&administrator, tenant)
        .map_err(|error| {
            let owners = initialized
                .maintenance_coordinator()
                .statuses()
                .map(|statuses| {
                    statuses
                        .iter()
                        .map(|status| {
                            (
                                status.task().class(),
                                status.phase(),
                                status.task().inputs().len(),
                                status.task().outputs().len(),
                            )
                        })
                        .collect::<Vec<_>>()
                });
            format!("epoch 3 retirement: {error:?}; authenticated task contracts: {owners:?}")
        })?;
    drop((services, initialized));
    let initialized = fixture.reopen()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let budget = positron_query::QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
        .with_cpu_work_units(15)?;
    assert_eq!(
        services.query_log_bodies(&query, "logs | range query_time 0 100 | limit 16", budget)?,
        [
            "retirement retains old data",
            "epoch two before second rotation"
        ]
    );
    Ok(())
}
