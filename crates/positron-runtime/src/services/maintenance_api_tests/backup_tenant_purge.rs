use super::*;

#[test]
fn purged_default_can_register_a_clean_repository_and_back_up_after_cold_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let fixture = Fixture::new()?;
    let (instance, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    let input = serde_json::to_vec(
        &serde_json::json!({"action":"start", "tenant_id":instance.tenant.to_canonical_text(), "confirmation_slug":"default", "expected_catalog_generation":open_catalog(&instance)?.pin()?.number(), "expected_lifecycle_generation":1, "idempotency_key":"e1e1e1e1-e1e1-41e1-81e1-e1e1e1e1e1e1"}),
    )?;
    services
        .manage_tenant_purge(&administrator, &input)
        .map_err(|e| format!("purge: {e:?}"))?;
    drive(&services, || {
        Ok(services
            .manage_tenant_purge(
                &administrator,
                br#"{"action":"lookup","idempotency_key":"e1e1e1e1-e1e1-41e1-81e1-e1e1e1e1e1e1"}"#,
            )
            .map_err(|e| format!("purge status: {e:?}"))?
            .operation
            .is_some_and(|op| op.status == "succeeded"))
    })?;
    assert_eq!(
        positron_governance::TenantAdministration::lifecycle_state(
            &open_catalog(&instance)?.pin()?,
            instance.tenant
        )?
        .0,
        positron_domain::lifecycle::TenantLifecycleState::Purged
    );
    drop(services);
    drop(instance);
    let instance = fixture.reopen()?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    let unlock = age::x25519::Identity::generate();
    let recipients = positron_kernel::RecoveryRecipients::parse(&[unlock.to_public().to_string()])?;
    let export = fixture.recovery_export_directory()?;
    let bundle = export.join("purged.age");
    instance.create_recovery_bundle(&bundle, &recipients)?;
    instance.verify_recovery_bundle(&bundle, positron_kernel::RecoveryUnlock::Identity(&unlock))?;
    let path = export.join("clean-after-purge");
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local(
        [91; 16],
        instance.instance.to_bytes(),
        instance.integrity_key_fingerprint(),
        &path,
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    drop(runtime.block_on(LocalRepository::initialize(&path, identity.clone()))?);
    let accepted = services
        .manage_backup(
            &administrator,
            &create(&services, &path, "e2e2e2e2-e2e2-42e2-82e2-e2e2e2e2e2e2")?.encode()?,
        )
        .map_err(|e| format!("clean registration: {e:?}"))?;
    let catalog = open_catalog(&instance)?;
    let snapshot = catalog.pin()?;
    let registration = snapshot
        .object_identities()
        .find_map(|id| {
            snapshot.object(id).ok().flatten().and_then(|bytes| {
                positron_backup::BackupRepositoryRegistration::decode(bytes)
                    .ok()
                    .flatten()
            })
        })
        .ok_or("registration")?;
    assert!(registration.registry_generation().is_some());
    let (_, governance) = snapshot.governance_object()?;
    let signer = instance
        .key
        .backup_control_signer(instance.instance, governance.protected_integrity_key())?;
    let repository = runtime.block_on(LocalRepository::attach(&path, &identity))?;
    let resources = backup_read_resources(&services)?;
    let publisher = positron_backup::BackupPublisher::new(&repository, &identity, &signer)
        .with_control_resources(&resources, 0)?
        .with_trusted_generation(registration.registry_generation().ok_or("anchor")?)?;
    let proof = backup_inspection_proof(&runtime, &publisher, [0xe3; 16])?;
    let publisher = publisher.with_registry_verification(&proof)?;
    assert_eq!(runtime.block_on(publisher.purge_tombstones())?.len(), 1);
    drop(publisher);
    drop(proof);
    drop(resources);
    drop(repository);
    drop(runtime);
    drop(snapshot);
    drop(catalog);
    let status = BackupRequest::decode(&serde_json::to_vec(
        &serde_json::json!({"action":"status", "operation_id":accepted.operation.id}),
    )?)?;
    drive(&services, || {
        Ok(services
            .manage_backup(&administrator, &status.encode()?)
            .map_err(|e| format!("backup status: {e:?}"))?
            .operation
            .status
            == "succeeded")
    })?;
    assert_eq!(
        services
            .manage_backup(&administrator, &status.encode()?)
            .map_err(|e| format!("backup status: {e:?}"))?
            .operation
            .status,
        "succeeded"
    );
    drop(services);
    drop(instance);
    let instance = fixture.reopen()?;
    assert_eq!(
        positron_governance::TenantAdministration::restore_purge_exclusions(
            &open_catalog(&instance)?.pin()?
        )?
        .len(),
        1
    );
    fs::remove_dir_all(path)?;
    Ok(())
}

#[test]
fn purge_drains_a_backup_stopped_before_its_key_put_before_destroying_keys()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::services::backup_administration::{StopPoint, stop_after};
    use positron_backup::{ListKind, ListRequest, Repository};
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let fixture = Fixture::new()?;
    let (instance, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let export = fixture.recovery_export_directory()?;
    let path = export.join("paused-key-upload");
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local(
        [91; 16],
        instance.instance.to_bytes(),
        instance.integrity_key_fingerprint(),
        &path,
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    drop(runtime.block_on(LocalRepository::initialize(&path, identity.clone()))?);
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    services.ingest_otlp_logs(&ingest, request("paused tenant key upload").encode_to_vec())?;
    let unlock = age::x25519::Identity::generate();
    let recipients = positron_kernel::RecoveryRecipients::parse(&[unlock.to_public().to_string()])?;
    let bundle = export.join("paused.age");
    instance.create_recovery_bundle(&bundle, &recipients)?;
    instance.verify_recovery_bundle(&bundle, positron_kernel::RecoveryUnlock::Identity(&unlock))?;
    services
        .manage_backup(
            &administrator,
            &create(&services, &path, "f1f1f1f1-f1f1-41f1-81f1-f1f1f1f1f1f1")?.encode()?,
        )
        .map_err(|e| format!("backup: {e:?}"))?;
    let stop = stop_after(StopPoint::BeforeKeyUpload)?;
    let cancellation = crate::TaskCancellation::new();
    let worker_services = services.clone();
    let worker_cancellation = cancellation.clone();
    let worker =
        std::thread::spawn(move || worker_services.run_maintenance_worker(&worker_cancellation));
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !stop.observed() && !worker.is_finished() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    cancellation.cancel();
    assert_eq!(worker.join().map_err(|_| "worker panic")?, Ok(()));
    assert!(stop.observed());
    drop(stop);
    let input = serde_json::to_vec(
        &serde_json::json!({"action":"start", "tenant_id":instance.tenant.to_canonical_text(), "confirmation_slug":"default", "expected_catalog_generation":open_catalog(&instance)?.pin()?.number(), "expected_lifecycle_generation":1, "idempotency_key":"f2f2f2f2-f2f2-42f2-82f2-f2f2f2f2f2f2"}),
    )?;
    let accepted = services
        .manage_tenant_purge(&administrator, &input)
        .map_err(|e| format!("purge: {e:?}"))?;
    assert!(open_catalog(&instance)?.has_backup_capture_references()?);
    drop(services);
    drop(instance);
    let instance = fixture.reopen()?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    // A resumed capture still owns the pre-purge wrapped key. Purge must let
    // that publisher drain before it can publish its irreversible boundary.
    let stop = stop_after(StopPoint::BeforeKeyUpload)?;
    let cancellation = crate::TaskCancellation::new();
    let worker_services = services.clone();
    let worker_cancellation = cancellation.clone();
    let worker =
        std::thread::spawn(move || worker_services.run_maintenance_worker(&worker_cancellation));
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !stop.observed() && !worker.is_finished() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    cancellation.cancel();
    assert_eq!(worker.join().map_err(|_| "worker panic")?, Ok(()));
    assert!(stop.observed());
    assert_eq!(
        positron_governance::TenantAdministration::lifecycle_state(
            &open_catalog(&instance)?.pin()?,
            instance.tenant
        )?
        .0,
        positron_domain::lifecycle::TenantLifecycleState::Active
    );
    drop(stop);
    drop(services);
    drop(instance);
    let instance = fixture.reopen()?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    let status = serde_json::to_vec(
        &serde_json::json!({"action":"status", "operation_id":accepted.operation.ok_or("purge")?.id}),
    )?;
    drive(&services, || {
        Ok(services
            .manage_tenant_purge(&administrator, &status)
            .map_err(|e| format!("status: {e:?}"))?
            .operation
            .is_some_and(|op| op.status == "succeeded"))
    })?;
    assert_eq!(
        services
            .manage_tenant_purge(&administrator, &status)
            .map_err(|e| format!("status: {e:?}"))?
            .operation
            .ok_or("purge")?
            .status,
        "succeeded"
    );
    assert!(!open_catalog(&instance)?.has_backup_capture_references()?);
    let repository = runtime.block_on(LocalRepository::attach(&path, &identity))?;
    let page =
        runtime.block_on(repository.list(ListRequest::new(ListKind::Objects, None, 128)?))?;
    assert!(page.next_cursor().is_none());
    for entry in page.entries() {
        if let positron_backup::ListEntry::Object(object) = entry {
            let body = runtime.block_on(
                repository.read_range(positron_backup::ObjectRange::new(*object, 0, 8)?),
            )?;
            assert_ne!(body.bytes(), b"POSBKE01");
        }
    }
    drop(repository);
    drop(runtime);
    drop(services);
    drop(instance);
    fs::remove_dir_all(path)?;
    Ok(())
}

fn drive(
    services: &ServiceHandle,
    mut done: impl FnMut() -> Result<bool, Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cancellation = crate::TaskCancellation::new();
    let worker_services = services.clone();
    let worker_cancellation = cancellation.clone();
    let worker =
        std::thread::spawn(move || worker_services.run_maintenance_worker(&worker_cancellation));
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let result = loop {
        match done() {
            Ok(true) => break Ok(()),
            Err(e) => break Err(e),
            Ok(false) => {},
        }
        if worker.is_finished() || std::time::Instant::now() >= deadline {
            break Err("maintenance did not complete".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    cancellation.cancel();
    assert_eq!(worker.join().map_err(|_| "worker panic")?, Ok(()));
    result
}
