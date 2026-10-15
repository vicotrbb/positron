use super::*;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};
use positron_kernel::{
    Catalog, MaintenanceTask, MaintenanceTaskClass, MaintenanceTaskId, MaintenanceTaskPhase,
    RootRewrapSession,
};
use std::{num::NonZeroU64, sync::Arc};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pruned_recovery_creation_audit_never_proves_retained_bundle_absent()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|e| format!("paths: {e:?}"))?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let mut instance = InstanceBootstrap::reopen(&paths)?;
    // Begin at midnight, when a discovered scrub may be scheduled for later.
    let (retention_time, elapsed) =
        positron_kernel::RetentionTimeAuthority::establish_with_manual_elapsed(
            positron_domain::time::UnixNanoseconds::new(86_400_000_000_000),
        );
    instance.install_retention_time_for_test(retention_time)?;
    let instance = Arc::new(instance);
    let parent = roots.data.parent().ok_or("fixture parent")?;
    let recovery = parent.join("recovery");
    let credentials = parent.join("credentials");
    for directory in [&recovery, &credentials] {
        std::fs::create_dir(directory)?;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    }
    let unlock = age::x25519::Identity::generate();
    let bundle = recovery.join("retained-source.age");
    instance.create_recovery_bundle(
        &bundle,
        &positron_kernel::RecoveryRecipients::parse(&[unlock.to_public().to_string()])?,
    )?;
    let actor = instance.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    for (limit, generation, key) in [(2, 1, 0xd1), (1, 2, 0xd2)] {
        instance.update_system_audit_retention(
            actor,
            NonZeroU64::new(limit).ok_or("limit")?,
            ResourceGeneration::new(generation)?,
            AdministrativeIdempotencyKey::new([key; 16])?,
        )?;
    }
    let coordinator = instance.maintenance_coordinator();
    let audit_task = coordinator
        .statuses()
        .map_err(|_| "task inventory")?
        .into_iter()
        .find(|status| status.task().class() == MaintenanceTaskClass::CatalogReclamation)
        .ok_or("audit reclaimer")?
        .task()
        .identity();
    let services = crate::ServiceHandle::new(Arc::clone(&instance))?;
    assert!(services.wake_maintenance_worker()?);
    assert_eq!(
        coordinator
            .status(audit_task)
            .map_err(|_| "audit completion")?
            .phase(),
        MaintenanceTaskPhase::Succeeded
    );
    drop(services);
    let visible = instance.governance_audit_for_test()?;
    assert!(visible.first().is_some_and(|entry| entry.position() > 1));
    assert!(!visible.iter().any(|entry| matches!(entry,
        positron_governance::GovernanceAuditEntry::RecoveryBundle(record)
        if record.operation() == positron_governance::RecoveryBundleAction::Created)));
    // The existing bounded ordinary owner may evict any oldest terminal task.
    // This legitimate activity removes the incidental audit-task guard, not
    // the retained recovery artifact or its source encryption route.
    {
        let session = RootRewrapSession::admit(&instance._authority)?;
        let catalog = Catalog::open(
            &instance._authority,
            instance.instance,
            session.rotation_catalog_secret(&instance.key, instance.instance)?,
        )?;
        for index in 0_u8..127 {
            let mut id = [0xa5; 16];
            id[15] = index;
            let identity = MaintenanceTaskId::new(id).map_err(|_| "task identity")?;
            coordinator
                .submit_and_persist(
                    &catalog,
                    MaintenanceTask::new(identity, MaintenanceTaskClass::SchemaStatistics),
                    u64::from(index) + 1,
                )
                .map_err(|_| "ordinary submission")?;
            coordinator
                .cancel_and_persist(&catalog, identity)
                .map_err(|_| "ordinary cancellation")?;
        }
        assert_eq!(
            coordinator.statuses().map_err(|_| "task inventory")?.len(),
            128
        );
        let identity = MaintenanceTaskId::new([0xa6; 16]).map_err(|_| "replacement identity")?;
        coordinator
            .submit_and_persist(
                &catalog,
                MaintenanceTask::new(identity, MaintenanceTaskClass::SchemaStatistics),
                128,
            )
            .map_err(|_| "bounded terminal eviction")?;
        coordinator
            .cancel_and_persist(&catalog, identity)
            .map_err(|_| "replacement cancellation")?;
        assert!(coordinator.status(audit_task).is_err());
    }
    let (port, server) = transcript_transport(
        |port| migration_replies(&instance, port, "immutable-id", 4),
        &[&rustls::version::TLS13],
    )
    .await?;
    let target = ProviderKeyUri::new(
        ProviderFamily::Kmip21,
        &format!("kmip://localhost:{port}/objects/immutable-id"),
        PIN,
    )?;
    let config = || -> Result<_, Box<dyn std::error::Error>> {
        Ok(NativeRootConfiguration::Kmip {
            identity: target.clone(),
            credentials: model(&credentials)?,
        })
    };
    instance.begin_key_provider_migration(config()?)?;
    instance.activate_key_provider_migration(config()?)?;
    let services = crate::ServiceHandle::new(Arc::clone(&instance))?;
    // Make every scrub in this daily scheduling window due before draining.
    // A false wake alone does not mean a future scheduled task is terminal.
    elapsed.advance(900_000_000_000)?;
    let mut quiescent = false;
    for _ in 0..32 {
        if !services.wake_maintenance_worker()? {
            quiescent = true;
            break;
        }
    }
    assert!(quiescent, "bounded maintenance work reaches quiescence");
    drop(services);
    assert!(
        coordinator
            .statuses()
            .map_err(|_| "task inventory")?
            .iter()
            .filter(|status| status.task().class() == MaintenanceTaskClass::IntegrityScrub)
            .all(|status| matches!(
                status.phase(),
                MaintenanceTaskPhase::Succeeded
                    | MaintenanceTaskPhase::Cancelled
                    | MaintenanceTaskPhase::Failed
            ))
    );
    let before = instance.key_provider_migration_status()?;
    assert_eq!(
        instance.retire_key_provider_predecessor(config()?),
        Err(crate::LocalKeyRotationFailure::Busy)
    );
    assert_eq!(instance.key_provider_migration_status()?, before);
    assert!(parent.join("secrets/local-root-key.v1").exists());
    assert!(bundle.exists());
    drop(instance);
    let reopened = InstanceBootstrap::reopen_with_provider(&paths, config()?)?;
    assert_eq!(reopened.key_provider_migration_status()?, before);
    assert!(parent.join("secrets/local-root-key.v1").exists());
    assert!(bundle.exists());
    assert_eq!(server.await?.len(), 25);
    Ok(())
}
