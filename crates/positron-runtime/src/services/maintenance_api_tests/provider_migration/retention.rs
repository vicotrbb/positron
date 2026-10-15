use super::*;

#[test]
fn root_verification_and_retirement_wait_for_the_retention_reference_owner()
-> Result<(), Box<dyn std::error::Error>> {
    for (action, blocked_clock) in [("verify", false), ("retire", false), ("verify", true)] {
        let fixture = Fixture::new()?;
        let configuration = fixture.migration_configuration()?;
        let (mut initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
        let (clock, elapsed) = RetentionTimeAuthority::establish_with_manual_elapsed(
            UnixNanoseconds::new(10_000_000_000),
        );
        Arc::get_mut(&mut initialized)
            .ok_or("sole instance")?
            .install_retention_time_for_test(clock)?;
        initialized.begin_local_key_rotation()?;
        initialized.activate_local_key_rotation()?;
        let directory = fixture.recovery_export_directory()?;
        let unlock = age::x25519::Identity::generate();
        let bundle = directory.join("successor.age");
        initialized.create_recovery_bundle(
            &bundle,
            &positron_kernel::RecoveryRecipients::parse(&[unlock.to_public().to_string()])?,
        )?;
        initialized
            .verify_recovery_bundle(&bundle, positron_kernel::RecoveryUnlock::Identity(&unlock))?;
        if action == "retire" {
            initialized.verify_local_key_rotation()?;
        }
        let actor = initialized.attribute(
            positron_governance::PresentedCredential::parse(&administrator)?,
            positron_governance::RequestedIntent::SystemAdministration,
            positron_governance::CompatibilityHints::none(),
        )?;
        let tenant = initialized.default_tenant_id();
        let duration = std::num::NonZeroU64::new(1).ok_or("retention duration")?;
        let preview = initialized.inspect_tenant_retention_impact(actor, tenant, duration)?;
        initialized.update_tenant_retention(
            actor,
            tenant,
            duration,
            positron_governance::ResourceGeneration::new(1)?,
            Some(&preview),
            positron_governance::AdministrativeIdempotencyKey::new([0xb6; 16])?,
        )?;
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        assert_eq!(
            services
                .ingest_otlp_logs(
                    &ingest,
                    request("retention owns this source").encode_to_vec()
                )?
                .accepted_records(),
            1
        );
        let scope = {
            let catalog = open_catalog(&initialized)?;
            let scope = catalog
                .pin()?
                .reachable_ledger_scopes(tenant, SignalKind::Logs)?
                .into_iter()
                .next()
                .ok_or("log scope")?;
            ActiveSegmentLedger::open_for_maintenance_with_retention_time(
                &initialized._authority,
                &initialized.retention_time,
                &catalog,
                scope,
                initialized.tenant_segment_key_for_test(scope)?,
            )?
            .seal()?;
            scope
        };
        let current = services
            .manage_provider_migration(&administrator, br#"{"action":"status"}"#)
            .expect("migration status");
        let accepted = services
            .manage_provider_migration(
                &administrator,
                &ProviderMigrationRequest {
                    action: action.into(),
                    expected_catalog_generation: Some(current.catalog_generation),
                    idempotency_key: Some("36363636-3636-4636-8636-363636363636".into()),
                    configuration_reference: Some(configuration.to_string_lossy().into_owned()),
                    operation_id: None,
                }
                .encode()?,
            )
            .expect("root phase accepted");
        let lookup = ProviderMigrationRequest {
            action: "status".into(),
            expected_catalog_generation: None,
            idempotency_key: None,
            configuration_reference: None,
            operation_id: accepted.operation.map(|operation| operation.id),
        }
        .encode()?;
        // The root request is older and otherwise wins the urgent scheduler's
        // ordering. Its existing reference owner must still run first.
        elapsed.advance(2_000_000_000)?;
        let retention = {
            let catalog = open_catalog(&initialized)?;
            let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
                &initialized._authority,
                &initialized.retention_time,
                &catalog,
                scope,
                initialized.tenant_segment_key_for_test(scope)?,
            )?;
            let preparation = ledger.prepare_retention_publication()?;
            assert!(!preparation.task().inputs().is_empty());
            let identity = preparation.task().identity();
            preparation.submit_and_persist(initialized.maintenance_coordinator(), &catalog, 12)?;
            let session = positron_kernel::RootRewrapSession::admit(&initialized._authority)?;
            assert!(
                initialized
                    .maintenance_coordinator()
                    .guard_root_retirement_references(&session, &catalog, &catalog.pin()?,)
                    .is_err(),
                "the queued checkpoint remains a real reference fence"
            );
            identity
        };
        assert!(
            matches!(
                services.pause_maintenance(
                    &administrator,
                    &MaintenancePauseRequest::new(
                        hex(retention.to_bytes()),
                        1,
                        60,
                        "37373737-3737-4737-8737-373737373737".into(),
                    )
                    .encode()?
                ),
                Err(MaintenanceServiceFailure::PreconditionFailed)
            ),
            "retention is safety work and cannot be paused through administration"
        );
        if blocked_clock {
            drop(services);
            let wall = Arc::new(Mutex::new(UnixNanoseconds::new(12_000_000_000)));
            Arc::get_mut(&mut initialized)
                .ok_or("sole instance for clock transition")?
                .install_retention_time_for_test(RetentionTimeAuthority::establish_with_source(
                    MutableWallClock(wall),
                    LifecycleClockPolicy::new(10)?,
                )?)?;
            let services = ServiceHandle::new(Arc::clone(&initialized))
                .map_err(|failure| format!("clock-blocked services: {failure:?}"))?;
            initialized.retention_time.governance_now_seconds()?;
            assert_eq!(
                initialized.retention_time.status().state(),
                positron_kernel::LifecycleClockState::ClockUncertain
            );
            let scrub = MaintenanceTaskId::new([0xb8; 16]).expect("safe work identity");
            {
                let catalog = open_catalog(&initialized)?;
                let basis = catalog.pin()?;
                let task = MaintenanceTask::integrity_scrub(
                    scrub,
                    MaintenanceScope::segment(
                        scope.tenant_id(),
                        scope.signal_kind(),
                        scope.shard_id(),
                    ),
                    MaintenanceTrigger::Event,
                    MaintenancePreconditions::new(basis.number(), 1).expect("safe work basis"),
                    basis.integrity_scope_source_identity(scope)?,
                    0,
                )
                .expect("safe integrity work");
                initialized
                    .maintenance_coordinator()
                    .submit_and_persist(&catalog, task, 12)
                    .expect("queue safe work");
            }
            assert!(services.wake_maintenance_worker()?);
            assert_eq!(
                initialized
                    .maintenance_coordinator()
                    .status(scrub)
                    .expect("safe work status")
                    .phase(),
                MaintenanceTaskPhase::Succeeded,
                "other eligible installed work must progress while retention is blocked"
            );
            let mut idle = false;
            for _ in 0..4 {
                match services.wake_maintenance_worker() {
                    Ok(false) | Err(crate::ServiceFailure::CapacityUnavailable) => {
                        idle = true;
                        break;
                    },
                    Ok(true) => {},
                    Err(failure) => return Err(format!("clock-blocked worker: {failure:?}").into()),
                }
            }
            assert!(
                idle,
                "blocked retention uses the existing idle or bounded capacity backoff"
            );
            assert_eq!(
                initialized
                    .maintenance_coordinator()
                    .status(retention)
                    .expect("blocked retention")
                    .phase(),
                MaintenanceTaskPhase::Queued
            );
            assert_eq!(
                services
                    .manage_provider_migration(&administrator, &lookup)
                    .expect("waiting phase")
                    .operation
                    .as_ref()
                    .map(|operation| operation.status.as_str()),
                Some("pending")
            );
            continue;
        }
        assert!(services.wake_maintenance_worker()?);
        assert_eq!(
            initialized
                .maintenance_coordinator()
                .status(retention)
                .expect("retention status")
                .phase(),
            MaintenanceTaskPhase::Succeeded,
            "{action} must let the retention owner publish first"
        );
        assert_eq!(
            services
                .manage_provider_migration(&administrator, &lookup)
                .expect("pending phase")
                .operation
                .as_ref()
                .map(|operation| operation.status.as_str()),
            Some("pending")
        );
        for _ in 0..16 {
            if services
                .manage_provider_migration(&administrator, &lookup)
                .expect("phase progress")
                .operation
                .as_ref()
                .is_some_and(|operation| operation.status == "succeeded")
            {
                break;
            }
            services.wake_maintenance_worker()?;
        }
        let terminal = services
            .manage_provider_migration(&administrator, &lookup)
            .expect("terminal phase");
        assert_eq!(
            terminal
                .operation
                .as_ref()
                .map(|operation| operation.status.as_str()),
            Some("succeeded"),
            "{action}: {terminal:?}"
        );
        assert_eq!(terminal.active_epoch, 2);
        assert_eq!(
            terminal.predecessor_epoch,
            (action == "verify").then_some(1)
        );
    }
    Ok(())
}
