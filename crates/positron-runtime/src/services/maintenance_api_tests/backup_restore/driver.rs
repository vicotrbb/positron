//! Restore lifecycle scenarios through the offline public operation interface.
use super::*;

pub(super) fn drive_restore(
    context: RestoreTestContext<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let RestoreTestContext {
        case,
        initialized,
        source_configuration,
        services,
        repository_path,
        runtime,
        target,
        paths,
        configuration,
        restore,
        unlock,
        query,
        pin,
        provider,
    } = context;
    // Repeated cold retries retain one bounded session off the test-thread stack.
    let begin = || -> Result<Box<crate::BackupRestoreSession>, crate::BootstrapFailure> {
        let session = match provider {
            Some(provider) => crate::InstanceBootstrap::begin_restore_with_provider(
                paths,
                configuration,
                restore,
                provider.configuration().map_err(|_| {
                    crate::BootstrapFailure::new(crate::BootstrapFailureCode::CorruptState)
                })?,
            ),
            None => crate::InstanceBootstrap::begin_restore(
                paths,
                configuration,
                restore,
                positron_kernel::RecoveryUnlock::Identity(unlock),
            ),
        };
        session.map(Box::new)
    };
    if case == RestoreCase::InspectFresh {
        assert!(
            crate::InstanceBootstrap::inspect_restore(
                paths,
                configuration,
                restore,
                positron_kernel::RecoveryUnlock::Identity(unlock)
            )
            .is_err()
        );
        assert!(!target.join("data/catalog").exists());
        assert_eq!(fs::read_dir(target.join("secrets"))?.count(), 0);
        return Ok(());
    }
    if case == RestoreCase::MissingLive {
        assert!(begin().is_err());
        assert!(!target.join("data/catalog").exists());
        assert_eq!(fs::read_dir(target.join("secrets"))?.count(), 0);
        return Ok(());
    }
    if case == RestoreCase::Nonempty {
        let catalog = target.join("data/catalog");
        fs::create_dir(&catalog)?;
        fs::set_permissions(&catalog, fs::Permissions::from_mode(0o700))?;
        assert!(begin().is_err());
        assert_eq!(
            fs::read_dir(&catalog)?.count(),
            0,
            "empty proof must precede writable Catalog opening"
        );
        assert_eq!(fs::read_dir(target.join("secrets"))?.count(), 0);
        return Ok(());
    }
    if case == RestoreCase::OriginInterruption {
        let failed = positron_kernel::with_catalog_publication_fault_after(
            positron_kernel::CatalogPublicationFault::PartialObjectWrite,
            0,
            begin,
        );
        assert!(
            failed.is_err(),
            "initial object staging must encounter the injected write failure"
        );
        assert_restore_target_offline(paths);
        assert!(
            begin().is_ok(),
            "exact cold retry must recover ownership before the origin descriptor existed"
        );
    }
    let mut session = begin().map_err(|failure| format!("begin restore: {failure:?}"))?;
    if case == RestoreCase::InspectAccepted {
        let expected = session.status();
        drop(session);
        let before = restore_target_bytes(target)?;
        let actual = crate::InstanceBootstrap::inspect_restore(
            paths,
            configuration,
            restore,
            positron_kernel::RecoveryUnlock::Identity(unlock),
        )?;
        assert_eq!(actual, expected);
        assert_eq!(
            restore_target_bytes(target)?,
            before,
            "status must not reconcile or publish target artifacts"
        );
        assert_restore_target_offline(paths);
        return Ok(());
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    if case == RestoreCase::Cancel {
        let cancelled = session.cancel(
            positron_governance::AdministrativeIdempotencyKey::new([0x78; 16])?,
            session.status().revision(),
        )?;
        assert_eq!(
            cancelled.status(),
            positron_governance::DurableOperationStatus::Cancelled
        );
        let id = cancelled.operation_id();
        drop(session);
        let mut retry = begin()?;
        assert_eq!(
            retry.step()?.status(),
            positron_governance::DurableOperationStatus::Cancelled
        );
        assert_eq!(retry.status().operation_id(), id);
        drop(retry);
        assert!(crate::InstanceBootstrap::reopen(paths).is_err());
        assert!(!target.join("data/.positron-bootstrap.initialized").exists());
        return Ok(());
    }
    let original_operation = session.status().operation_id();
    let mut cold_stops = vec![
        positron_governance::DurableOperationPhase::BackupTransfer,
        positron_governance::DurableOperationPhase::BackupVerification,
        positron_governance::DurableOperationPhase::CatalogPublication,
    ];
    let mut transfer_observations = 0;
    let operation = loop {
        if std::time::Instant::now() >= deadline {
            return Err("restore deadline".into());
        }
        let result = if case == RestoreCase::PublicationGap
            && session.status().phase()
                == positron_governance::DurableOperationPhase::CatalogPublication
        {
            positron_kernel::RootRewrapSession::with_custody_publication_fault(
                positron_kernel::RootCustodyPublicationFault::RouteFileSync,
                || session.step(),
            )
        } else {
            session.step()
        };
        if case == RestoreCase::PublicationGap
            && result.is_err()
            && session.status().status() == positron_governance::DurableOperationStatus::Succeeded
        {
            assert!(!target.join("data/.positron-bootstrap.initialized").exists());
            assert_restore_target_offline(paths);
            assert!(session.status().backup_restore_report().is_some());
            drop(session);
            session = begin()?;
            assert_eq!(session.status().operation_id(), original_operation);
            assert_eq!(
                session.status().status(),
                positron_governance::DurableOperationStatus::Succeeded
            );
            break session.step()?;
        }
        let operation = result.map_err(|failure| {
            format!("restore step {:?}: {failure:?}", session.status().phase())
        })?;
        if case == RestoreCase::PublicationGap
            && operation.status() == positron_governance::DurableOperationStatus::Succeeded
        {
            return Err("publication fault was not reached".into());
        }
        if operation.status().is_terminal() {
            break operation;
        }
        if operation.phase() == positron_governance::DurableOperationPhase::BackupTransfer {
            transfer_observations += 1;
        }
        if cold_stops.first().copied() == Some(operation.phase())
            && (transfer_observations >= 2 || case.purged())
        {
            assert!(begin().is_err(), "one physical target owner");
            cold_stops.remove(0);
            if case == RestoreCase::HeadRace
                && operation.phase()
                    == positron_governance::DurableOperationPhase::CatalogPublication
            {
                let catalog = open_catalog(initialized)?;
                let source = catalog.pin()?;
                let (_, governance) = source.governance_object()?;
                let signer = initialized.key.backup_control_signer(
                    initialized.instance,
                    governance.protected_integrity_key(),
                )?;
                let identity = RepositoryIdentity::local(
                    [91; 16],
                    initialized.instance.to_bytes(),
                    initialized.integrity_key_fingerprint(),
                    repository_path,
                )?;
                let repository =
                    runtime.block_on(LocalRepository::attach(repository_path, &identity))?;
                let resources = backup_read_resources(services)?;
                let publisher =
                    positron_backup::BackupPublisher::new(&repository, &identity, &signer)
                        .with_control_resources(&resources, 0)?;
                let proof = backup_inspection_proof(runtime, &publisher, [0x79; 16])?;
                let publisher = publisher.with_registry_verification(&proof)?;
                runtime.block_on(
                    publisher.record_purge_tombstone(&positron_backup::BackupPurgeTombstone::new(
                        governance.tenant().to_bytes(),
                        governance.tenant_slug().as_str(),
                        [0x7a; 16],
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)?
                            .as_secs(),
                    )?),
                )?;
                assert!(
                    session.step().is_err(),
                    "publication must fence a changed authoritative head"
                );
                assert!(!target.join("data/.positron-bootstrap.initialized").exists());
                drop(session);
                std::thread::scope(|scope| {
                    scope
                        .spawn(|| {
                            assert_failed_restore_replay(
                                paths,
                                configuration,
                                restore,
                                unlock,
                                original_operation,
                            )
                            .map_err(|error| error.to_string())
                        })
                        .join()
                })
                .map_err(|_| "restore replay thread panicked")??;
                assert!(!target.join("data/.positron-bootstrap.initialized").exists());
                return Ok(());
            }
            drop(session);
            if case == RestoreCase::Tamper
                && operation.phase()
                    == positron_governance::DurableOperationPhase::CatalogPublication
            {
                let segment = fs::read_dir(target.join("data/segments/sealed"))?
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .find(|path| {
                        path.extension()
                            .is_some_and(|extension| extension == "segment")
                    })
                    .ok_or("sealed segment")?;
                let mut bytes = fs::read(&segment)?;
                *bytes.first_mut().ok_or("nonempty segment")? ^= 1;
                fs::write(segment, bytes)?;
                let mut retry = crate::InstanceBootstrap::begin_restore(
                    paths,
                    configuration,
                    restore,
                    positron_kernel::RecoveryUnlock::Identity(unlock),
                )?;
                let deadline = std::time::Instant::now() + Duration::from_secs(30);
                loop {
                    match retry.step() {
                        Err(_) => break,
                        Ok(operation) => {
                            assert_ne!(
                                operation.status(),
                                positron_governance::DurableOperationStatus::Succeeded,
                                "cold publication cannot trust an earlier native verification"
                            );
                            if std::time::Instant::now() >= deadline {
                                return Err("tamper verification deadline".into());
                            }
                        },
                    }
                }
                drop(retry);
                assert_corrupt_restore_failed(
                    paths,
                    configuration,
                    restore,
                    unlock,
                    original_operation,
                )?;
                assert_restore_target_offline(paths);
                assert!(!target.join("data/.positron-bootstrap.initialized").exists());
                return Ok(());
            }

            session = begin().map_err(|failure| format!("cold restore: {failure:?}"))?;
            assert_eq!(session.status().operation_id(), original_operation);
        }
    };
    assert!(cold_stops.is_empty(), "all cold boundaries exercised");
    assert_eq!(
        operation.status(),
        positron_governance::DurableOperationStatus::Succeeded
    );
    let restored_id = operation.operation_id();
    drop(session);
    let mut replay = begin().map_err(|failure| format!("completed retry: {failure:?}"))?;
    assert_eq!(replay.status().operation_id(), restored_id);
    assert_eq!(
        replay.step()?.status(),
        positron_governance::DurableOperationStatus::Succeeded
    );
    drop(replay);
    if source_configuration.is_some() {
        let document = format!(
            "schema_version=1\n[runtime]\nshutdown_grace_seconds=31\n[storage]\ndata_directory={:?}\nsecrets_directory={:?}\n",
            target.join("data"),
            target.join("secrets"),
        );
        let changed = positron_config::resolve(
            positron_config::ConfigurationInputs::try_new(
                Some(&document),
                positron_config::EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])
                    .map_err(|error| format!("environment: {error:?}"))?,
                positron_config::CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])
                    .map_err(|error| format!("overrides: {error:?}"))?,
            )
            .map_err(|error| format!("changed configuration: {error:?}"))?,
        )?;
        let before = restore_target_bytes(target)?;
        assert!(
            crate::InstanceBootstrap::begin_restore(
                paths,
                &changed,
                restore,
                positron_kernel::RecoveryUnlock::Identity(unlock)
            )
            .is_err(),
            "same physical roots with a changed accepted configuration must refuse"
        );
        assert_eq!(restore_target_bytes(target)?, before);
    }
    let restored = Arc::new(
        match provider {
            Some(provider) => {
                crate::InstanceBootstrap::reopen_with_provider(paths, provider.configuration()?)
            },
            None => crate::InstanceBootstrap::reopen(paths),
        }
        .map_err(|failure| format!("normal reopen: {failure:?}"))?,
    );
    if let Some((source_configuration, source_generation)) = source_configuration {
        let source = crate::CatalogConfigurationPublication::new(Arc::clone(initialized));
        assert_eq!(
            source.establish(source_configuration)?,
            *source_generation,
            "restore must preserve source active configuration"
        );
        let publication = crate::CatalogConfigurationPublication::new(Arc::clone(&restored));
        let generation = publication.establish(configuration)?;
        assert_eq!(
            publication.establish(configuration)?,
            generation,
            "target publication is idempotent after exact restore replay"
        );
        assert!(matches!(
            publication.establish(source_configuration),
            Err(crate::ConfigurationRuntimeFailure::ImmutableConfiguration)
        ));
        assert_eq!(
            publication.establish(configuration)?,
            generation,
            "ordinary startup cannot replace restored immutable binding"
        );
    }
    crate::instance_bootstrap::recover_initial_ledgers(&restored)
        .map_err(|failure| format!("native startup: {failure:?}"))?;
    let restored_services = ServiceHandle::new(Arc::clone(&restored))
        .map_err(|failure| format!("services startup: {failure:?}"))?;
    {
        let catalog = open_catalog(&restored)?;
        let basis = catalog.pin()?;
        let report = operation
            .backup_restore_report()
            .ok_or("restore report pointer")?;
        let address = basis
            .object_identities()
            .find(|id| id.to_bytes() == report)
            .ok_or("restore report")?;
        let identity = RepositoryIdentity::local(
            [91; 16],
            restored.instance.to_bytes(),
            restored.integrity_key_fingerprint(),
            repository_path,
        )?;
        let report = positron_backup::BackupRestoreReport::verify(
            basis.object(address)?.ok_or("restore report bytes")?,
            &identity,
            pin.integrity(),
        )?;
        assert_eq!(report.recovered_keys(), if case.purged() { 0 } else { 1 });
        assert_eq!(
            report.excluded_tenants().len(),
            if case.purged() { 1 } else { 0 }
        );
    }
    if case.purged() {
        assert!(
            restored_services
                .query_log_bodies(
                    query,
                    "logs | range query_time 0 100 | limit 10",
                    QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 60)?
                        .with_cpu_work_units(16)?
                )
                .is_err(),
            "signed tombstone prevents resurrection from an older snapshot"
        );
        let catalog = open_catalog(&restored)?;
        let basis = catalog.pin()?;
        assert_eq!(
            basis.governance_object()?.1.lifecycle(),
            positron_domain::lifecycle::TenantLifecycleState::Purging
        );
        assert!(
            basis
                .reachable_ledger_scopes(
                    restored.tenant,
                    positron_domain::routing::SignalKind::Logs
                )?
                .is_empty()
        );
        return Ok(());
    }
    assert_eq!(
        restored_services.query_log_bodies(
            query,
            "logs | range query_time 0 100 | limit 10",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 60)?
                .with_cpu_work_units(16)?
        )?,
        vec![String::from("restored telemetry")]
    );
    let catalog = open_catalog(&restored)?;
    assert_eq!(
        positron_governance::DurableOperationAdministration::inspect(&catalog, restored_id)?
            .ok_or("restored operation")?
            .status(),
        positron_governance::DurableOperationStatus::Succeeded
    );
    Ok(())
}

// Simulates the #111 key-registry successor after destruction, using the actual
// signed wire format and CAS, while preserving every non-key control record.
