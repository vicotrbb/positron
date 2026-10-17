use super::*;
#[test]
fn tenant_purge_is_audited_restartable_irreversible_and_identity_stays_reserved()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (instance, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    services.ingest_otlp_logs(
        &ingest,
        request("tenant purge private telemetry").encode_to_vec(),
    )?;
    let tenant = instance.tenant.to_canonical_text();
    let generation = open_catalog(&instance)?.pin()?.number();
    let input = format!(
        r#"{{"action":"start","tenant_id":"{tenant}","confirmation_slug":"default","expected_catalog_generation":{generation},"expected_lifecycle_generation":1,"idempotency_key":"11111111-1111-4111-8111-111111111111"}}"#
    );
    assert_eq!(
        services.manage_tenant_purge(&ingest, input.as_bytes()),
        Err(MaintenanceServiceFailure::AuthenticationRejected)
    );
    let accepted = services
        .manage_tenant_purge(&administrator, input.as_bytes())
        .map_err(|failure| format!("accept: {failure:?}"))?;
    assert_eq!(
        accepted
            .operation
            .as_ref()
            .map(|operation| operation.status.as_str()),
        Some("pending")
    );
    let retry = services
        .manage_tenant_purge(&administrator, input.as_bytes())
        .map_err(|failure| format!("replay: {failure:?}"))?;
    assert_eq!(accepted.operation, retry.operation);
    drop(services);
    drop(instance);
    let instance = fixture.reopen()?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    drive_purge(&services, || {
        Ok(services
            .manage_tenant_purge(
                &administrator,
                br#"{"action":"lookup","idempotency_key":"11111111-1111-4111-8111-111111111111"}"#,
            )
            .map_err(|e| format!("lookup: {e:?}"))?
            .operation
            .is_some_and(|op| op.status == "succeeded"))
    })?;
    let status = services
        .manage_tenant_purge(
            &administrator,
            br#"{"action":"lookup","idempotency_key":"11111111-1111-4111-8111-111111111111"}"#,
        )
        .map_err(|failure| format!("lookup: {failure:?}"))?;
    let operation = status.operation.ok_or("operation")?;
    assert_eq!(operation.status, "succeeded");
    assert_eq!(
        operation.irreversible_boundary,
        "catalog_generation_published"
    );
    assert_eq!(
        instance
            .inspect_tenant(
                instance.attribute(
                    positron_governance::PresentedCredential::parse(&administrator)?,
                    positron_governance::RequestedIntent::SystemAdministration,
                    positron_governance::CompatibilityHints::none()
                )?,
                instance.tenant
            )?
            .lifecycle(),
        positron_domain::lifecycle::TenantLifecycleState::Purged
    );
    drop(services);
    drop(instance);
    let instance = fixture.reopen()?;
    let catalog = open_catalog(&instance)?;
    assert!(
        !positron_governance::TenantAdministration::restore_purge_exclusions(&catalog.pin()?)?
            .is_empty()
    );
    assert!(
        catalog
            .pin()?
            .reachable_ledger_scopes(instance.tenant, SignalKind::Logs)?
            .is_empty()
    );
    assert!(
        catalog
            .pin()?
            .reachable_ledger_scopes(instance.tenant, SignalKind::Traces)?
            .is_empty()
    );
    drop(catalog);
    let actor = instance.attribute(
        positron_governance::PresentedCredential::parse(&administrator)?,
        positron_governance::RequestedIntent::SystemAdministration,
        positron_governance::CompatibilityHints::none(),
    )?;
    let config = |slug| {
        positron_governance::TenantCreateConfiguration::new(
            positron_domain::identity::TenantSlug::parse_canonical(slug).expect("slug"),
            "Replacement",
            3600,
            1,
            [
                32_000_000, 32, 32, 5_000_000, 2048, 32, 32, 32, 32, 32, 2_000_000,
            ],
        )
    };
    assert!(
        instance
            .create_tenant(
                actor,
                positron_domain::identity::TenantId::from_bytes([0xa1; 16])?,
                config("default"),
                positron_governance::AdministrativeIdempotencyKey::new([0xa2; 16])?
            )
            .is_err()
    );
    instance.create_tenant(
        actor,
        positron_domain::identity::TenantId::from_bytes([0xa3; 16])?,
        config("replacement"),
        positron_governance::AdministrativeIdempotencyKey::new([0xa4; 16])?,
    )?;
    Ok(())
}

#[test]
fn tenant_purge_repository_outage_cannot_complete_or_cancel_and_recovers_on_restart()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_backup::{BackupRepositoryRegistration, LocalRepository, RepositoryIdentity};
    use positron_kernel::{CatalogObject, CatalogProposal, TransactionId};
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new()?;
    let (instance, _, _, administrator) = fixture.initialized_with_admin()?;
    let export = fixture.recovery_export_directory()?;
    let path = export.join("purge-repository");
    let unlock = age::x25519::Identity::generate();
    let recipients = positron_kernel::RecoveryRecipients::parse(&[unlock.to_public().to_string()])?;
    let bundle = export.join("scope-race.age");
    instance.create_recovery_bundle(&bundle, &recipients)?;
    instance.verify_recovery_bundle(&bundle, positron_kernel::RecoveryUnlock::Identity(&unlock))?;
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local(
        [0xc1; 16],
        instance.instance.to_bytes(),
        instance.integrity_key_fingerprint(),
        &path,
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    drop(runtime.block_on(LocalRepository::initialize(&path, identity.clone()))?);
    drop(runtime);
    {
        let catalog = open_catalog(&instance)?;
        let snapshot = catalog.pin()?;
        let mut objects = Vec::new();
        for id in snapshot.object_identities() {
            objects.push(CatalogObject::new(
                snapshot.object(id)?.ok_or("object")?.to_vec(),
            )?);
        }
        objects.push(
            BackupRepositoryRegistration::new(identity, path.to_str().ok_or("path")?)?
                .catalog_object()?,
        );
        catalog.commit(
            snapshot.identity(),
            CatalogProposal::new(
                TransactionId::new([0xc2; 16])?,
                snapshot.format_epoch().ok_or("format")?,
                objects,
            )?,
            None,
        )?;
    }
    let absent = path.with_extension("unavailable");
    fs::rename(&path, &absent)?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    let input = serde_json::to_vec(
        &serde_json::json!({"action":"start", "tenant_id":instance.tenant.to_canonical_text(), "confirmation_slug":"default", "expected_catalog_generation":open_catalog(&instance)?.pin()?.number(), "expected_lifecycle_generation":1, "idempotency_key":"c3c3c3c3-c3c3-43c3-83c3-c3c3c3c3c3c3"}),
    )?;
    let accepted = services
        .manage_tenant_purge(&administrator, &input)
        .map_err(|failure| format!("accept: {failure:?}"))?;
    let id = accepted.operation.ok_or("operation")?.id;
    let boundary_status =
        serde_json::to_vec(&serde_json::json!({"action":"status", "operation_id":id}))?;
    drive_purge(&services, || {
        Ok(services
            .manage_tenant_purge(&administrator, &boundary_status)
            .map_err(|e| format!("boundary status: {e:?}"))?
            .operation
            .is_some_and(|op| op.irreversible_boundary == "catalog_generation_published"))
    })?;
    let status_input =
        serde_json::to_vec(&serde_json::json!({"action":"status", "operation_id":id}))?;
    let pending = services
        .manage_tenant_purge(&administrator, &status_input)
        .map_err(|failure| format!("pending: {failure:?}"))?;
    let operation = pending.operation.ok_or("operation")?;
    assert_eq!(operation.status, "running");
    assert_eq!(
        operation.irreversible_boundary,
        "catalog_generation_published"
    );
    let cancel = serde_json::to_vec(
        &serde_json::json!({"action":"cancel", "operation_id":id, "expected_catalog_generation":pending.catalog_generation, "idempotency_key":"c4c4c4c4-c4c4-44c4-84c4-c4c4c4c4c4c4"}),
    )?;
    assert_eq!(
        services.manage_tenant_purge(&administrator, &cancel),
        Err(MaintenanceServiceFailure::PreconditionFailed)
    );
    // Admission can enlarge managed scope while an unavailable Repository
    // keeps purge nonterminal. The new candidate must receive the permanent
    // exclusion before registration, and the resumed purge must include it.
    let additional = export.join("registered-during-purge");
    fs::create_dir(&additional)?;
    fs::set_permissions(&additional, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local(
        [91; 16],
        instance.instance.to_bytes(),
        instance.integrity_key_fingerprint(),
        &additional,
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    drop(runtime.block_on(LocalRepository::initialize(&additional, identity))?);
    drop(runtime);
    let creation = serde_json::to_vec(
        &serde_json::json!({"action":"create", "repository_id":"5b5b5b5b-5b5b-5b5b-5b5b-5b5b5b5b5b5b", "locator":additional, "retention_seconds":3600, "expected_catalog_generation":open_catalog(&instance)?.pin()?.number(), "idempotency_key":"c5c5c5c5-c5c5-45c5-85c5-c5c5c5c5c5c5"}),
    )?;
    services
        .manage_backup(&administrator, &creation)
        .map_err(|e| format!("admit during purge: {e:?}"))?;
    let snapshot = open_catalog(&instance)?.pin()?;
    let mut found = false;
    for id in snapshot.object_identities() {
        if let Some(row) =
            BackupRepositoryRegistration::decode(snapshot.object(id)?.ok_or("object")?)?
            && row.identity().repository_id() == [91; 16]
        {
            assert!(row.registry_generation().is_some());
            found = true;
        }
    }
    assert!(found);
    drop(snapshot);
    drop(services);
    drop(instance);
    fs::rename(&absent, &path)?;
    let instance = fixture.reopen()?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    drive_purge(&services, || {
        Ok(services
            .manage_tenant_purge(&administrator, &status_input)
            .map_err(|e| format!("status: {e:?}"))?
            .operation
            .is_some_and(|op| op.status == "succeeded"))
    })?;
    let completed = services
        .manage_tenant_purge(&administrator, &status_input)
        .map_err(|failure| format!("completed: {failure:?}"))?;
    assert_eq!(completed.operation.ok_or("operation")?.status, "succeeded");
    fs::remove_dir_all(path)?;
    fs::remove_dir_all(additional)?;
    Ok(())
}

#[test]
fn tenant_purge_confirmation_conflicts_and_preboundary_cancellation_are_durable()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (instance, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    let mut input = serde_json::json!({"action":"start", "tenant_id":instance.tenant.to_canonical_text(), "confirmation_slug":"wrong-slug", "expected_catalog_generation":open_catalog(&instance)?.pin()?.number(), "expected_lifecycle_generation":1, "idempotency_key":"d1d1d1d1-d1d1-41d1-81d1-d1d1d1d1d1d1"});
    assert_eq!(
        services.manage_tenant_purge(&administrator, &serde_json::to_vec(&input)?),
        Err(MaintenanceServiceFailure::PreconditionFailed)
    );
    input["confirmation_slug"] = "default".into();
    let accepted = services
        .manage_tenant_purge(&administrator, &serde_json::to_vec(&input)?)
        .map_err(|failure| format!("accept: {failure:?}"))?;
    input["expected_lifecycle_generation"] = 2.into();
    assert_eq!(
        services.manage_tenant_purge(&administrator, &serde_json::to_vec(&input)?),
        Err(MaintenanceServiceFailure::IdempotencyConflict)
    );
    let id = accepted.operation.ok_or("operation")?.id;
    let cancel = serde_json::to_vec(
        &serde_json::json!({"action":"cancel", "operation_id":id, "expected_catalog_generation":accepted.catalog_generation, "idempotency_key":"d2d2d2d2-d2d2-42d2-82d2-d2d2d2d2d2d2"}),
    )?;
    let cancelled = services
        .manage_tenant_purge(&administrator, &cancel)
        .map_err(|failure| format!("cancel: {failure:?}"))?;
    assert_eq!(cancelled.operation.ok_or("operation")?.status, "cancelled");
    drop(services);
    drop(instance);
    let instance = fixture.reopen()?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    let status = serde_json::to_vec(&serde_json::json!({"action":"status", "operation_id":id}))?;
    assert_eq!(
        services
            .manage_tenant_purge(&administrator, &status)
            .map_err(|failure| format!("status: {failure:?}"))?
            .operation
            .ok_or("operation")?
            .status,
        "cancelled"
    );
    let snapshot = open_catalog(&instance)?.pin()?;
    assert_eq!(
        positron_governance::TenantAdministration::lifecycle_state(&snapshot, instance.tenant)?.0,
        positron_domain::lifecycle::TenantLifecycleState::Active
    );
    assert!(
        positron_governance::TenantAdministration::restore_purge_exclusions(&snapshot)?.is_empty()
    );
    Ok(())
}

fn drive_purge(
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
            break Err("purge maintenance did not complete".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    cancellation.cancel();
    assert_eq!(worker.join().map_err(|_| "worker panic")?, Ok(()));
    result
}
