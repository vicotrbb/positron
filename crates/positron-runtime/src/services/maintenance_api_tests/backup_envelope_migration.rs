use super::*;

#[test]
fn retained_backup_remains_recoverable_after_verified_root_retirement()
-> Result<(), Box<dyn std::error::Error>> {
    migration_overlay(false, false)
}
#[test]
fn interrupted_overlay_publication_recovers_every_retained_backup_after_cancel_and_restart()
-> Result<(), Box<dyn std::error::Error>> {
    migration_overlay(true, false)
}
#[test]
fn corrupt_registered_repository_fails_migration_without_retiring_predecessor()
-> Result<(), Box<dyn std::error::Error>> {
    migration_overlay(false, true)
}
fn migration_overlay(interrupt: bool, corrupt: bool) -> Result<(), Box<dyn std::error::Error>> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let fixture = Fixture::new()?;
    let configuration = fixture.migration_configuration()?;
    let (mut initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let directory = fixture.recovery_export_directory()?;
    let path = directory.join("overlay-repository");
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local(
        [91; 16],
        initialized.instance.to_bytes(),
        initialized.integrity_key_fingerprint(),
        &path,
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    drop(runtime.block_on(LocalRepository::initialize(&path, identity.clone()))?);
    let unlock = age::x25519::Identity::generate();
    let recipients = positron_kernel::RecoveryRecipients::parse(&[unlock.to_public().to_string()])?;
    let bundle = directory.join("original.age");
    initialized.create_recovery_bundle(&bundle, &recipients)?;
    initialized
        .verify_recovery_bundle(&bundle, positron_kernel::RecoveryUnlock::Identity(&unlock))?;
    let mut services = ServiceHandle::new(Arc::clone(&initialized))?;
    let first = publish(
        &mut services,
        &administrator,
        &path,
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    )?;
    let mut snapshots = vec![(
        first.operation.id,
        first.receipt.ok_or("receipt")?.manifest_checksum,
    )];
    if interrupt {
        let second = publish(
            &mut services,
            &administrator,
            &path,
            "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        )?;
        snapshots.push((
            second.operation.id,
            second.receipt.ok_or("second receipt")?.manifest_checksum,
        ));
    }
    let mut routes = None;
    let actions: &[&str] = if !interrupt && !corrupt {
        &["prepare", "activate", "verify", "retire"]
    } else {
        &["prepare", "activate", "verify"]
    };
    for (index, action) in actions.iter().copied().enumerate() {
        let status = services
            .manage_provider_migration(&administrator, br#"{"action":"status"}"#)
            .map_err(|e| format!("status {e:?}"))?;
        let request = positron_api::provider_migration::ProviderMigrationRequest {
            action: action.into(),
            expected_catalog_generation: Some(status.catalog_generation),
            idempotency_key: Some(format!("cccccccc-cccc-4ccc-8ccc-{:012}", index + 1)),
            configuration_reference: Some(configuration.to_string_lossy().into_owned()),
            operation_id: None,
        }
        .encode()?;
        let accepted = services
            .manage_provider_migration(&administrator, &request)
            .map_err(|e| format!("phase {action} {e:?}"))?;
        let operation = accepted.operation.ok_or("accepted root operation")?.id;
        if action == "verify" && corrupt {
            let identity_path = path.join("identity");
            let original = fs::read(&identity_path)?;
            fs::write(&identity_path, b"corrupt repository identity")?;
            let failed = finish_root(&mut services, &administrator, &operation)?;
            assert_eq!(
                failed.operation.as_ref().map(|op| op.status.as_str()),
                Some("failed")
            );
            assert_eq!(failed.predecessor_epoch, Some(1));
            assert!(initialized.retire_local_key_predecessor().is_err());
            fs::write(&identity_path, original)?;
            return Ok(());
        }
        if action == "verify" && interrupt {
            services = ServiceHandle::new(Arc::clone(&initialized))?;
            let stop = crate::services::backup_administration::stop_after(
                crate::services::backup_administration::StopPoint::BackupOverlayPublished,
            )?;
            let cancellation = crate::TaskCancellation::new();
            let worker_services = services.clone();
            let worker_cancel = cancellation.clone();
            let worker =
                std::thread::spawn(move || worker_services.run_maintenance_worker(&worker_cancel));
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            while !stop.observed() && !worker.is_finished() && std::time::Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            cancellation.cancel();
            worker.join().map_err(|_| "root worker panic")??;
            assert!(stop.observed(), "missing overlay publication boundary");
            drop(stop);
            drop(services);
            drop(initialized);
            initialized = fixture.reopen()?;
            services = ServiceHandle::new(Arc::clone(&initialized))?;
            initialized.cancel_key_provider_migration()?;
            assert!(initialized.backup_migration_envelopes(None).is_err());
            initialized.resume_key_provider_migration()?;
            let replay = services
                .manage_provider_migration(&administrator, &request)
                .map_err(|e| format!("exact verify retry {e:?}"))?;
            assert_eq!(
                replay.operation.as_ref().map(|op| op.id.as_str()),
                Some(operation.as_str())
            );
        }
        let completed = finish_root(&mut services, &administrator, &operation)
            .map_err(|e| format!("{action}: {e}"))?;
        assert_eq!(
            completed.operation.as_ref().map(|op| op.status.as_str()),
            Some("succeeded"),
            "{action}: {completed:?}; maintenance={:?}; readiness={:?}",
            services.maintenance_status(&administrator, br"{}"),
            initialized.backup_key_recovery_readiness()
        );
        if action == "activate" {
            routes = Some(initialized.backup_migration_envelopes(None)?);
            let successor = directory.join("successor.age");
            initialized.create_recovery_bundle(&successor, &recipients)?;
            initialized.verify_recovery_bundle(
                &successor,
                positron_kernel::RecoveryUnlock::Identity(&unlock),
            )?;
            initialized.retire_recovery_predecessor()?;
        }
        if action == "retire" {
            assert_eq!(completed.predecessor_epoch, None);
            assert_eq!(completed.root_phase, "active");
        }
    }
    let (source, target) = routes.ok_or("verified root routes")?;
    let (_, registration, _, signer) =
        crate::services::backup_administration::registered::registered(
            &services,
            identity.repository_id(),
        )
        .map_err(|e| format!("registration {e:?}"))?;
    let resources = backup_read_resources(&services)?;
    let repository = runtime.block_on(LocalRepository::attach(&path, &identity))?;
    let publisher = positron_backup::BackupPublisher::new(&repository, &identity, &signer)
        .with_control_resources(&resources, 0)?
        .with_trusted_generation(registration.registry_generation().ok_or("anchor")?)?;
    let proof = backup_inspection_proof(&runtime, &publisher, [0x79; 16])?;
    let publisher = publisher.with_registry_verification(&proof)?;
    for (snapshot, expected_manifest) in snapshots {
        let snapshot = crate::services::maintenance_verification::decode_fixed_hex(&snapshot)
            .ok_or("snapshot")?;
        let overlay = runtime
            .block_on(publisher.read_envelope_overlay(snapshot, target.identity()))?
            .ok_or("missing migrated recovery path")?;
        assert_eq!(overlay.source(), &source);
        assert_eq!(overlay.target(), &target);
        assert_eq!(
            overlay.manifest().checksum(),
            crate::services::maintenance_verification::decode_fixed_hex(&expected_manifest)
                .ok_or("manifest")?
        );
        assert_eq!(
            runtime.block_on(publisher.verify(snapshot))?.snapshot_id(),
            snapshot
        );
    }
    Ok(())
}
fn publish(
    services: &mut ServiceHandle,
    administrator: &str,
    path: &std::path::Path,
    key: &str,
) -> Result<BackupResponse, Box<dyn std::error::Error>> {
    *services = ServiceHandle::new(Arc::clone(&services.instance))?;
    let created = services
        .manage_backup(administrator, &create(services, path, key)?.encode()?)
        .map_err(|e| format!("backup create {e:?}"))?;
    let cancellation = crate::TaskCancellation::new();
    let worker_services = services.clone();
    let worker_cancel = cancellation.clone();
    let worker = std::thread::spawn(move || worker_services.run_maintenance_worker(&worker_cancel));
    let result = retention::finish_direct(services, administrator, &created.operation.id);
    cancellation.cancel();
    worker.join().map_err(|_| "backup worker panic")??;
    result
}
pub(super) fn finish_root(
    services: &mut ServiceHandle,
    administrator: &str,
    id: &str,
) -> Result<positron_api::provider_migration::ProviderMigrationResponse, Box<dyn std::error::Error>>
{
    // A prior fixture worker has joined. Re-enter normal service recovery
    // before replacing it so an interrupted scrub is queued with a new owner.
    *services = ServiceHandle::new(Arc::clone(&services.instance))?;
    let request = positron_api::provider_migration::ProviderMigrationRequest {
        action: "status".into(),
        expected_catalog_generation: None,
        idempotency_key: None,
        configuration_reference: None,
        operation_id: Some(id.into()),
    }
    .encode()?;
    let cancellation = crate::TaskCancellation::new();
    let worker_services = services.clone();
    let worker_cancel = cancellation.clone();
    let worker = std::thread::spawn(move || worker_services.run_maintenance_worker(&worker_cancel));
    let result = (|| -> Result<_, Box<dyn std::error::Error>> {
        // Use the existing long-work fixture budget: the owning no-progress SLO
        // alone is 60 seconds, before any queued prerequisite. Status reads
        // share the Catalog gate with checkpoints; 100 ms polling reduces
        // contention tenfold from the former 10 ms cadence.
        let deadline = std::time::Instant::now() + Duration::from_secs(120);
        loop {
            let status = match services.manage_provider_migration(administrator, &request) {
                Ok(status) => status,
                Err(MaintenanceServiceFailure::CapacityUnavailable)
                    if !worker.is_finished() && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                },
                Err(failure) => return Err(format!("root lookup {failure:?}").into()),
            };
            status.encode()?;
            if status.operation.as_ref().is_some_and(|op| {
                matches!(op.status.as_str(), "succeeded" | "failed" | "cancelled")
            }) {
                return Ok(status);
            }
            if worker.is_finished() || std::time::Instant::now() >= deadline {
                return Err(format!("root completion deadline: {status:?}").into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    })();
    cancellation.cancel();
    let worker_result = worker.join().map_err(|_| "root worker panic")?;
    let status = result.map_err(|e| {
        format!(
            "{e}; worker={worker_result:?}; maintenance={:?}",
            services.maintenance_status(administrator, br"{}")
        )
    })?;
    worker_result?;
    Ok(status)
}

#[path = "backup_envelope_completion.rs"]
mod completion_publication;

#[path = "backup_envelope_worker.rs"]
mod worker_recovery;
