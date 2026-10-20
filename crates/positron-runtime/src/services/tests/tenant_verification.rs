use super::super::ServiceHandle;
use super::schema_maintenance::{Fixture, request};
use prost::Message;
use std::sync::Arc;

fn advance_recovered_verifier(
    services: &ServiceHandle,
    administrator: &str,
    tenant: positron_domain::identity::TenantId,
) -> Result<crate::TenantKeyVerificationProgress, Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let result = services.advance_tenant_key_verification(administrator, tenant);
        if result != Err(super::super::ServiceFailure::CatalogBusy) {
            return result.map_err(Into::into);
        }
        let now = services
            .instance
            .retention_time
            .inspect_governance_now_seconds()?;
        let future = services
            .instance
            .maintenance_coordinator()
            .statuses()
            .map_err(|_| "recovered verifier status")?
            .into_iter()
            .find(|status| {
                status.task().class() == positron_kernel::MaintenanceTaskClass::EnvelopeVerification
                    && status.task().scope() == positron_kernel::MaintenanceScope::tenant(tenant)
                    && status.phase() == positron_kernel::MaintenanceTaskPhase::Queued
                    && status.submitted_at() > now
            });
        let Some(task) = future else {
            return result.map_err(Into::into);
        };
        while services
            .instance
            .retention_time
            .inspect_governance_now_seconds()?
            < task.submitted_at()
        {
            if std::time::Instant::now() >= deadline {
                return Err(
                    "recovered verifier clock did not reach submission within 10 seconds".into(),
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

fn verified_audits(
    initialized: &crate::InitializedInstance,
    services: &ServiceHandle,
) -> Result<usize, Box<dyn std::error::Error>> {
    let _gate = services
        .catalog_operation
        .lock()
        .map_err(|_| "Catalog gate")?;
    let catalog = super::schema_maintenance::open_catalog(initialized)?;
    let mut count = 0;
    for record in catalog.governance_audit_records()? {
        let entry = positron_governance::GovernanceAuditEntry::decode(&record)?;
        if entry.as_tenant_key_rotation().is_some_and(|entry| {
            entry.tenant() == initialized.default_tenant_id()
                && entry.stage() == positron_governance::TenantKeyRotationStage::Verified
        }) {
            count += 1;
        }
    }
    Ok(count)
}

#[test]
fn native_host_background_handler_completes_a_resumed_target_only_verifier()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::{
        ApplicationRuntime, HostInputs, InitializationMode, NativeBindings, NativeHost,
        ServeConfiguration, ShutdownTrigger,
    };
    use positron_kernel::{MaintenanceTaskClass, MaintenanceTaskPhase};
    let _native = super::schema_maintenance::live_native_maintenance_test_guard();
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let tenant = initialized.default_tenant_id();
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.ingest_otlp_logs(
        &ingest,
        request("native-background-target-only").encode_to_vec(),
    )?;
    services.ingest_otlp_traces(
        &ingest,
        super::schema_lifecycle_support::trace_request().encode_to_vec(),
    )?;
    services.begin_tenant_key_rotation(&administrator, tenant)?;
    services.advance_tenant_key_rotation(&administrator, tenant)?;
    assert_eq!(
        services
            .advance_tenant_key_rotation(&administrator, tenant)?
            .active_epoch(),
        2
    );
    let source_object_bound = super::schema_maintenance::open_catalog(&initialized)?
        .pin()?
        .object_identities()
        .count();
    for _ in 0..source_object_bound {
        let progress = services.advance_tenant_key_migration(&administrator, tenant)?;
        if !progress.remaining_segments() {
            break;
        }
    }
    assert!(
        super::schema_maintenance::open_catalog(&initialized)?
            .pin()?
            .next_unmigrated_ledger_scope(tenant, 2)?
            .is_none()
    );
    // Retire the empty sealed predecessors while preserving the two real-data
    // sources. Query-purpose observation does not create another active segment.
    let source_scopes = {
        let catalog = super::schema_maintenance::open_catalog(&initialized)?;
        let mut scopes = Vec::new();
        for signal in [
            positron_domain::routing::SignalKind::Logs,
            positron_domain::routing::SignalKind::Traces,
        ] {
            scopes.extend(catalog.pin()?.reachable_ledger_scopes(tenant, signal)?);
        }
        let mut empty_predecessors = 0;
        for scope in &scopes {
            assert!(!catalog.pin()?.has_active_ledger_scope(*scope)?);
            let ledger = positron_kernel::ActiveSegmentLedger::open_for_query_with_retention_time(
                &initialized._authority,
                &initialized.retention_time,
                &catalog,
                *scope,
                initialized.tenant_segment_key_for_test(*scope)?,
            )?;
            assert!(
                !ledger.snapshot()?.blocks().is_empty(),
                "real source remains in each scope"
            );
            empty_predecessors += 1;
            let preparation = ledger.prepare_retention_publication()?;
            let publication = preparation.task().identity();
            assert_eq!(preparation.task().inputs().len(), 1);
            let now = initialized
                .retention_time
                .inspect_governance_now_seconds()?;
            let coordinator = initialized.maintenance_coordinator();
            preparation.submit_and_persist(coordinator, &catalog, now)?;
            let execution = coordinator
                .start_next_with_reservation_and_persist_for_class(
                    &catalog,
                    &initialized._authority,
                    now,
                    false,
                    Some(MaintenanceTaskClass::RetentionPublication),
                )
                .map_err(|failure| format!("predecessor publication dispatch: {failure:?}"))?
                .ok_or("predecessor publication")?;
            assert_eq!(execution.task().identity(), publication);
            let reclamation =
                ledger.complete_running_retention_publication_task(coordinator, &execution)?;
            drop(execution);
            let execution = coordinator
                .start_next_with_reservation_and_persist_for_class(
                    &catalog,
                    &initialized._authority,
                    now,
                    false,
                    Some(MaintenanceTaskClass::RetentionReclamation),
                )
                .map_err(|failure| format!("predecessor reclamation dispatch: {failure:?}"))?
                .ok_or("predecessor reclamation")?;
            assert_eq!(execution.task().identity(), reclamation);
            ledger.complete_running_retention_reclamation_task(coordinator, &execution)?;
            assert_eq!(
                coordinator
                    .status(reclamation)
                    .map_err(|failure| format!("predecessor status: {failure:?}"))?
                    .phase(),
                MaintenanceTaskPhase::Succeeded
            );
        }
        assert_eq!(empty_predecessors, 2);
        let mut remaining = Vec::new();
        for signal in [
            positron_domain::routing::SignalKind::Logs,
            positron_domain::routing::SignalKind::Traces,
        ] {
            remaining.extend(catalog.pin()?.reachable_ledger_scopes(tenant, signal)?);
        }
        u64::try_from(remaining.len())?
    };
    assert!(
        !services
            .advance_tenant_key_verification(&administrator, tenant)?
            .is_complete()
    );
    let task = initialized
        .maintenance_coordinator()
        .statuses()
        .map_err(|_| "statuses")?
        .into_iter()
        .find(|status| status.task().class() == MaintenanceTaskClass::EnvelopeVerification)
        .ok_or("durable verifier")?
        .task()
        .identity();
    {
        let _gate = services
            .catalog_operation
            .lock()
            .map_err(|_| "Catalog gate")?;
        let catalog = super::schema_maintenance::open_catalog(&initialized)?;
        let basis = catalog.pin()?;
        assert!(basis.next_active_ledger_scope(tenant)?.is_none());
    }
    drop((services, initialized));
    let ephemeral = "127.0.0.1:0".parse()?;
    let host = NativeHost::new(NativeBindings::new(
        fixture.control_socket_path(),
        ephemeral,
        ephemeral,
        ephemeral,
        ephemeral,
        ephemeral,
    )?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(fixture.paths()?, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let services = process.services().ok_or("native services")?;
    let phase_budget = std::time::Duration::from_secs(5);
    let preparation_deadline = std::time::Instant::now() + phase_budget;
    let mut deadline = preparation_deadline;
    let mut reset_after_startup = false;
    loop {
        let status = services
            .instance
            .maintenance_coordinator()
            .status(task)
            .map_err(|_| "native task status")?;
        match status.phase() {
            MaintenanceTaskPhase::Succeeded => {
                assert!(
                    std::time::Instant::now() <= deadline,
                    "resumed verifier completion exceeded its bounded phase"
                );
                break;
            },
            MaintenanceTaskPhase::Queued | MaintenanceTaskPhase::Running => {
                if std::time::Instant::now() >= deadline {
                    return Err(format!(
                        "native verifier bounded wait exhausted: phase={:?}, checkpoint_sequence={:?}, startup_reset={}, resources={:?}",
                        status.phase(), status.checkpoint().map(|checkpoint| checkpoint.sequence()),
                        reset_after_startup, services.instance.resource_governor().inspect(),
                    ).into());
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            },
            phase => {
                let _gate = services
                    .catalog_operation
                    .lock()
                    .map_err(|_| "Catalog gate")?;
                let catalog = super::schema_maintenance::open_catalog(&services.instance)?;
                let basis = catalog.pin()?;
                let statuses = services
                    .instance
                    .maintenance_coordinator()
                    .statuses()
                    .map_err(|_| "statuses")?
                    .into_iter()
                    .map(|status| {
                        (
                            status.task().identity(),
                            status.task().class(),
                            status.phase(),
                        )
                    })
                    .collect::<Vec<_>>();
                if phase == MaintenanceTaskPhase::Failed && !reset_after_startup {
                    // Startup creates one active scope for each signal.
                    for signal in [
                        positron_domain::routing::SignalKind::Logs,
                        positron_domain::routing::SignalKind::Traces,
                    ] {
                        let mut active = 0;
                        for scope in basis.reachable_ledger_scopes(tenant, signal)? {
                            if basis.has_active_ledger_scope(scope)? {
                                active += 1;
                            }
                        }
                        assert_eq!(active, 1, "one new active {signal:?} scope");
                    }
                    assert_eq!(
                        statuses
                            .into_iter()
                            .filter(|(identity, _, _)| *identity == task)
                            .map(|(_, class, phase)| (class, phase))
                            .collect::<Vec<_>>(),
                        vec![(
                            MaintenanceTaskClass::EnvelopeVerification,
                            MaintenanceTaskPhase::Failed
                        )]
                    );
                    drop((basis, catalog));
                    let actor = services
                        .authorize_system_administration(&administrator)
                        .map_err(|_| "system administrator")?;
                    // The actual startup created two successor-only active
                    // segments. Authenticate their existing inline routes and
                    // publish their Catalog envelopes before capturing proof.
                    for remaining in [true, false] {
                        let migration = services
                            .instance
                            .advance_tenant_key_migration(actor, tenant)
                            .map_err(|failure| {
                                format!(
                                    "successor startup migration remaining={remaining}: {failure:?}"
                                )
                            })?;
                        assert!(!migration.migrated_segment());
                        assert_eq!(migration.remaining_segments(), remaining);
                    }
                    services
                        .instance
                        .restart_tenant_key_verification(actor, tenant)
                        .map_err(|failure| format!("same-owner startup reset: {failure:?}"))?;
                    reset_after_startup = true;
                    drop(_gate);
                    // Startup invalidation and foreground source preparation
                    // have their own five-second bound. Only now is the native
                    // handler notified to resume its bounded traversal.
                    assert!(
                        std::time::Instant::now() <= preparation_deadline,
                        "startup invalidation and reset exceeded their bounded phase"
                    );
                    deadline = std::time::Instant::now() + phase_budget;
                    services.notify_maintenance_worker();
                    continue;
                }
                return Err(format!(
                    "native verifier terminal phase {phase:?}; tasks={statuses:?}"
                )
                .into());
            },
        }
    }
    assert!(
        reset_after_startup,
        "native startup must invalidate the captured source basis"
    );
    assert_eq!(
        services
            .instance
            .maintenance_coordinator()
            .status(task)
            .map_err(|_| "completed status")?
            .checkpoint()
            .ok_or("completed checkpoint")?
            .sequence(),
        source_scopes + 2
    );
    assert!(
        services
            .advance_tenant_key_verification(&administrator, tenant)?
            .is_complete()
    );
    services.ingest_otlp_logs(
        &ingest,
        request("native-write-invalidates-proof").encode_to_vec(),
    )?;
    assert_eq!(
        services.advance_tenant_key_verification(&administrator, tenant),
        Err(super::super::ServiceFailure::CatalogBusy)
    );
    drop(services);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn installed_maintenance_dispatch_resumes_the_durable_tenant_verifier()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let tenant = initialized.default_tenant_id();
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.ingest_otlp_logs(&ingest, request("maintenance-target-only").encode_to_vec())?;
    services.begin_tenant_key_rotation(&administrator, tenant)?;
    services.advance_tenant_key_rotation(&administrator, tenant)?;
    assert_eq!(
        services
            .advance_tenant_key_rotation(&administrator, tenant)?
            .active_epoch(),
        2
    );
    for remaining in [true, true, false] {
        let migration = services.advance_tenant_key_migration(&administrator, tenant)?;
        assert_eq!(migration.remaining_segments(), remaining);
    }
    let first = services.advance_tenant_key_verification(&administrator, tenant)?;
    assert_eq!(first.examined_segments(), 1);
    assert!(!first.is_complete());
    assert!(super::super::maintenance::wake_runtime_maintenance(
        &services, None
    )?);
    assert!(super::super::maintenance::wake_runtime_maintenance(
        &services, None
    )?);
    assert!(
        services
            .advance_tenant_key_verification(&administrator, tenant)?
            .is_complete()
    );
    drop((services, initialized));
    let initialized = fixture.reopen()?;
    let services = ServiceHandle::new(initialized)?;
    assert!(
        services
            .advance_tenant_key_verification(&administrator, tenant)?
            .is_complete()
    );
    Ok(())
}

#[test]
fn tenant_target_only_verification_is_bounded_and_resumes_durable_checkpoint_after_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let tenant = initialized.default_tenant_id();
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.ingest_otlp_logs(
        &ingest,
        request("verified-with-successor-only").encode_to_vec(),
    )?;
    services.begin_tenant_key_rotation(&administrator, tenant)?;
    assert_eq!(
        services
            .advance_tenant_key_rotation(&administrator, tenant)?
            .active_epoch(),
        1
    );
    assert_eq!(
        services
            .advance_tenant_key_rotation(&administrator, tenant)?
            .active_epoch(),
        2
    );
    for remaining in [true, true, false] {
        let migration = services.advance_tenant_key_migration(&administrator, tenant)?;
        assert!(migration.migrated_segment());
        assert_eq!(migration.remaining_segments(), remaining);
    }
    let first = services
        .advance_tenant_key_verification(&administrator, tenant)
        .map_err(|failure| format!("first pass: {failure:?}"))?;
    assert!(!first.is_complete());
    assert_eq!(first.examined_segments(), 1);
    let before = {
        let _gate = services
            .catalog_operation
            .lock()
            .map_err(|_| "Catalog gate")?;
        let catalog = super::schema_maintenance::open_catalog(&initialized)?;
        let snapshot = catalog.pin()?;
        assert!(snapshot.next_active_ledger_scope(tenant)?.is_none());
        snapshot.object_identities().collect::<Vec<_>>()
    };
    drop((services, initialized));
    let initialized = fixture.reopen()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    {
        let _gate = services
            .catalog_operation
            .lock()
            .map_err(|_| "Catalog gate")?;
        let catalog = super::schema_maintenance::open_catalog(&initialized)?;
        let snapshot = catalog.pin()?;
        assert!(
            snapshot.next_active_ledger_scope(tenant)?.is_none(),
            "reopen must preserve the sealed source of its durable verification task"
        );
        let after = snapshot.object_identities().collect::<Vec<_>>();
        let removed: Vec<_> = before.iter().filter(|id| !after.contains(id)).collect();
        let added: Vec<_> = after.iter().filter(|id| !before.contains(id)).collect();
        assert_eq!(
            (removed, added),
            (Vec::new(), Vec::new()),
            "quiescent schema must preserve the authenticated inventory across reopen"
        );
    }
    let second = advance_recovered_verifier(&services, &administrator, tenant)
        .map_err(|failure| format!("second after reopen: {failure:?}"))?;
    assert!(!second.is_complete());
    assert_eq!(second.examined_segments(), 1);
    let third = services
        .advance_tenant_key_verification(&administrator, tenant)
        .map_err(|failure| format!("third pass: {failure:?}"))?;
    assert!(third.is_complete());
    assert_eq!(third.examined_segments(), 1);
    assert_eq!(verified_audits(&initialized, &services)?, 1);
    assert!(
        services
            .advance_tenant_key_verification(&administrator, tenant)?
            .is_complete()
    );
    assert_eq!(
        verified_audits(&initialized, &services)?,
        1,
        "idempotent completion must not duplicate its durable verification audit"
    );
    services.ingest_otlp_logs(
        &ingest,
        request("new-schema-and-write-invalidates-proof").encode_to_vec(),
    )?;
    assert_eq!(
        services.advance_tenant_key_verification(&administrator, tenant),
        Err(super::super::ServiceFailure::CatalogBusy),
        "a new authenticated write must invalidate the completed source proof"
    );
    let successor = services.advance_tenant_key_migration(&administrator, tenant)?;
    assert!(!successor.migrated_segment());
    assert!(!successor.remaining_segments());
    services.restart_tenant_key_verification(&administrator, tenant)?;
    drop((services, initialized));
    let initialized = fixture.reopen()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        verified_audits(&initialized, &services)?,
        1,
        "restart and reset preserve the original durable audit"
    );
    for complete in [false, false, false, true] {
        let progress = advance_recovered_verifier(&services, &administrator, tenant)?;
        assert_eq!(progress.is_complete(), complete);
        assert_eq!(progress.examined_segments(), 1);
    }
    assert_eq!(
        verified_audits(&initialized, &services)?,
        2,
        "new exact-source verification publishes one new durable event"
    );
    Ok(())
}

#[test]
fn verification_schema_publication_fault_never_publishes_a_proof_task()
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
        services.ingest_otlp_logs(&ingest, request("schema-publication-fault").encode_to_vec())?;
        services.begin_tenant_key_rotation(&administrator, tenant)?;
        for epoch in [1, 2] {
            assert_eq!(
                services
                    .advance_tenant_key_rotation(&administrator, tenant)?
                    .active_epoch(),
                epoch
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
        let failed = with_catalog_publication_fault_sequence_after(&[(fault, 0); 3], || {
            services.advance_tenant_key_verification(&administrator, tenant)
        });
        assert_eq!(
            failed,
            Err(super::super::ServiceFailure::CatalogUnavailable)
        );
        assert!(
            initialized
                .maintenance_coordinator()
                .statuses()
                .expect("inspect existing durable task owner")
                .iter()
                .all(|status| status.task().class() != MaintenanceTaskClass::EnvelopeVerification)
        );
        drop((services, initialized));
        let initialized = fixture.reopen()?;
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        let resumed = advance_recovered_verifier(&services, &administrator, tenant)?;
        assert!(!resumed.is_complete());
        assert_eq!(resumed.examined_segments(), 1);
    }
    Ok(())
}

#[test]
fn verifier_reset_publication_fault_resumes_the_same_owner_after_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::{
        CatalogPublicationFault, MaintenanceTaskClass, with_catalog_publication_fault_after,
    };
    for fault in [
        CatalogPublicationFault::SynchronizeGenerationDirectory,
        CatalogPublicationFault::SynchronizeCommit,
    ] {
        let fixture = Fixture::new()?;
        let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
        let tenant = initialized.default_tenant_id();
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        services.ingest_otlp_logs(&ingest, request("reset-publication-fault").encode_to_vec())?;
        services.begin_tenant_key_rotation(&administrator, tenant)?;
        for epoch in [1, 2] {
            assert_eq!(
                services
                    .advance_tenant_key_rotation(&administrator, tenant)?
                    .active_epoch(),
                epoch
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
        let task = initialized
            .maintenance_coordinator()
            .statuses()
            .expect("statuses")
            .into_iter()
            .find(|status| status.task().class() == MaintenanceTaskClass::EnvelopeVerification)
            .ok_or("verification owner")?
            .task()
            .clone();
        let failed = with_catalog_publication_fault_after(fault, 0, || {
            services.restart_tenant_key_verification(&administrator, tenant)
        });
        assert_eq!(
            failed,
            Err(super::super::ServiceFailure::CatalogUnavailable)
        );
        drop((services, initialized));
        let initialized = fixture.reopen()?;
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        services.restart_tenant_key_verification(&administrator, tenant)?;
        let reset = initialized
            .maintenance_coordinator()
            .status(task.identity())
            .expect("same owner");
        assert_eq!(reset.task(), &task);
        assert!(reset.checkpoint().is_none());
        for complete in [false, false, true] {
            let progress = advance_recovered_verifier(&services, &administrator, tenant)?;
            assert_eq!(progress.is_complete(), complete);
            assert_eq!(progress.examined_segments(), 1);
        }
    }
    Ok(())
}
