use super::*;

#[test]
fn backup_resource_growth_is_durable_and_releases_the_old_grant()
-> Result<(), Box<dyn std::error::Error>> {
    restart_at(crate::services::backup_administration::StopPoint::ResourcesRequeued)
}
#[test]
fn signed_registry_cursor_and_phase_checkpoint_resume_after_cold_stop()
-> Result<(), Box<dyn std::error::Error>> {
    restart_at(crate::services::backup_administration::StopPoint::RegistryCursorPersisted)
}
#[test]
fn partially_prepared_backup_keys_resume_after_cold_stop() -> Result<(), Box<dyn std::error::Error>>
{
    restart_at(crate::services::backup_administration::StopPoint::KeyPreparationPersisted)
}
fn restart_at(
    point: crate::services::backup_administration::StopPoint,
) -> Result<(), Box<dyn std::error::Error>> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let repository_path = std::env::temp_dir().join(format!(
        "positron-backup-resource-restart-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    fs::create_dir(&repository_path)?;
    fs::set_permissions(&repository_path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local(
        [91; 16],
        initialized.instance.to_bytes(),
        initialized.integrity_key_fingerprint(),
        &repository_path,
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    drop(runtime.block_on(LocalRepository::initialize(
        &repository_path,
        identity.clone(),
    ))?);
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let key_stop =
        point == crate::services::backup_administration::StopPoint::KeyPreparationPersisted;
    if key_stop {
        let request = positron_api::tenant_service::TenantCreateRequest::new(
            "backup-second-tenant".into(),
            "Backup second tenant".into(),
            2_592_000,
            1,
            [1; 11],
            "88888888-8888-4888-8888-888888888888".into(),
        );
        services.create_tenant_service(&administrator, &request.encode()?).map_err(|failure| match failure {
            crate::services::tenant_service::TenantServiceHttpFailure::Code(status, code) => format!("second tenant creation: HTTP {status} {code}"),
            crate::services::tenant_service::TenantServiceHttpFailure::StaleDisplayGeneration { .. } => "second tenant creation stale generation".into(),
        })?;
    }
    services.ingest_otlp_logs(&ingest, request("readmission telemetry").encode_to_vec())?;
    let unlock = age::x25519::Identity::generate();
    let recipients = positron_kernel::RecoveryRecipients::parse(&[unlock.to_public().to_string()])?;
    let bundle = fixture.recovery_export_directory()?.join("publication.age");
    initialized.create_recovery_bundle(&bundle, &recipients)?;
    initialized
        .verify_recovery_bundle(&bundle, positron_kernel::RecoveryUnlock::Identity(&unlock))?;
    seed_remote_registry(&services, &runtime, &repository_path, &identity)?;
    let accepted = services
        .manage_backup(
            &administrator,
            &create(
                &services,
                &repository_path,
                "77777777-7777-4777-8777-777777777777",
            )?
            .encode()?,
        )
        .map_err(|failure| format!("accept backup: {failure:?}"))?;

    let task = positron_kernel::MaintenanceTaskId::new(
        crate::services::maintenance_verification::decode_fixed_hex(&accepted.operation.id)
            .ok_or("task identity")?,
    )
    .map_err(|failure| format!("task: {failure:?}"))?;
    let original = initialized
        .maintenance_coordinator()
        .status(task)
        .map_err(|failure| format!("task status: {failure:?}"))?;
    let before = initialized.resource_governor().inspect()?;
    let stop = crate::services::backup_administration::stop_after(
        services.instance.instance.to_bytes(),
        task.to_bytes(),
        point,
    )?;
    let cancellation = crate::TaskCancellation::new();
    let worker_services = services.clone();
    let worker_cancellation = cancellation.clone();
    let worker =
        std::thread::spawn(move || worker_services.run_maintenance_worker(&worker_cancellation));
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !stop.observed() && !worker.is_finished() {
        if std::time::Instant::now() >= deadline {
            cancellation.cancel();
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let worker_result = worker.join().map_err(|_| "worker panic")?;
    assert!(
        stop.observed(),
        "worker stopped before durable readmission: {worker_result:?}"
    );
    assert_eq!(worker_result, Ok(()));
    let queued = initialized
        .maintenance_coordinator()
        .status(task)
        .map_err(|failure| format!("task status: {failure:?}"))?;
    let cursor_stop = key_stop
        || point == crate::services::backup_administration::StopPoint::RegistryCursorPersisted;
    assert_eq!(
        queued.phase(),
        if cursor_stop {
            MaintenanceTaskPhase::Running
        } else {
            MaintenanceTaskPhase::Queued
        }
    );
    assert_eq!(queued.task().identity(), original.task().identity());
    let memory = positron_kernel::ResourceDimension::MemoryBytes;
    assert!(queued.task().reservations().get(memory) > original.task().reservations().get(memory));
    assert!(queued.checkpoint().is_some());
    if cursor_stop {
        assert!(
            queued
                .checkpoint()
                .ok_or("cursor checkpoint")?
                .opaque_progress()
                .len()
                > 56 + 333
        );
        let snapshot = task.to_bytes();
        let _gate = services.catalog_operation()?;
        let catalog = open_catalog(&initialized)?;
        let basis = catalog.pin()?;
        let (_, governance) = basis.governance_object()?;
        let signer = initialized
            .key
            .backup_control_signer(initialized.instance, governance.protected_integrity_key())?;
        let repository = runtime.block_on(LocalRepository::attach(&repository_path, &identity))?;
        let resources = backup_read_resources(&services)?;
        let publisher = positron_backup::BackupPublisher::new(&repository, &identity, &signer)
            .with_control_resources(&resources, 0)?;
        let proof = backup_inspection_proof(&runtime, &publisher, snapshot)?;
        let publisher = publisher.with_registry_verification(&proof)?;
        assert_eq!(
            runtime
                .block_on(publisher.cancellation_candidate(snapshot))?
                .ok_or("reserved candidate")?
                .snapshot_id(),
            snapshot
        );
        assert!(positron_kernel::BackupCapture::exists(
            &initialized._authority,
            snapshot
        )?);
        if key_stop {
            use positron_backup::Repository;
            assert_eq!(
                positron_governance::TenantAdministration::registered_tenant_ids(&basis)?.len(),
                2
            );
            // This Local fixture has a complete bounded advisory page. Inspect
            // public immutable object headers only to prove exactly one of two
            // protected envelopes reached the Repository before the cold stop.
            let page = runtime.block_on(repository.list(positron_backup::ListRequest::new(
                positron_backup::ListKind::Objects,
                None,
                128,
            )?))?;
            assert!(page.next_cursor().is_none());
            let mut prepared = 0;
            for entry in page.entries() {
                if let positron_backup::ListEntry::Object(object) = entry {
                    let part = runtime.block_on(
                        repository.read_range(positron_backup::ObjectRange::new(*object, 0, 8)?),
                    )?;
                    if part.bytes() == b"POSBKE01" {
                        prepared += 1;
                    }
                }
            }
            assert_eq!(prepared, 1);
        }
    }
    let after = initialized.resource_governor().inspect()?;
    assert_eq!(
        after.outstanding_reservations(),
        before.outstanding_reservations()
    );
    assert_eq!(after.usage(memory), before.usage(memory));
    {
        let _gate = services.catalog_operation()?;
        let catalog = open_catalog(&initialized)?;
        let restored = positron_kernel::MaintenanceCoordinator::restore_from_catalog(&catalog)
            .map_err(|failure| format!("cold coordinator: {failure:?}"))?;
        let cold = restored
            .status(task)
            .map_err(|failure| format!("task status: {failure:?}"))?;
        assert_eq!(cold.phase(), MaintenanceTaskPhase::Queued);
        assert_eq!(cold.task(), queued.task());
        assert_eq!(cold.checkpoint(), queued.checkpoint());
    }
    drop(stop);
    drop(runtime);
    drop(services);
    drop(initialized);
    let loopback = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let host = NativeHost::new(NativeBindings::new(
        fixture.control_socket_path(),
        loopback,
        loopback,
        loopback,
        loopback,
        loopback,
    )?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(fixture.paths()?, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let services = process.services().ok_or("cold services")?;
    let endpoint = process
        .bound_endpoints()
        .into_iter()
        .find(|endpoint| endpoint.role() == crate::ListenerRole::Api)
        .and_then(|endpoint| endpoint.socket_address())
        .ok_or("cold API endpoint")?;
    let client = BackupServiceClient::new(BackupTransport::PlaintextOptOut { endpoint })?;
    let completed = finish(&client, &services, &administrator, &accepted.operation.id)
        .map_err(|failure| format!("cold backup completion: {failure}"))?;
    assert_eq!(completed.operation.status, "succeeded");
    assert!(!completed.cleanup_pending);
    let listing = positron_api::backup::BackupListRequest {
        repository_id: "5b5b5b5b-5b5b-5b5b-5b5b-5b5b5b5b5b5b".into(),
        limit: 1,
        cursor: None,
    };
    {
        let amounts =
            |memory| positron_kernel::ResourceAmounts::new([memory, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut requested = u64::MAX;
        let mut blocker = None;
        // Global, recovery occupancy and class headroom impose nested ceilings.
        // Every refusal supplies the next strictly smaller admitted candidate.
        for _ in 0..4 {
            match services.instance.resource_governor().reserve(
                positron_kernel::WorkClaim::backup_repository_read(amounts(requested))?,
            ) {
                Ok(reservation) => {
                    blocker = Some(reservation);
                    break;
                },
                Err(refusal) => {
                    let next = refusal
                        .allowed()
                        .checked_sub(refusal.in_use())
                        .and_then(|n| n.checked_sub(1_048_576))
                        .ok_or("ordinary read headroom")?;
                    if next >= requested {
                        return Err(format!("read admission did not narrow: {refusal:?}").into());
                    }
                    requested = next;
                },
            }
        }
        let blocker = blocker.ok_or("bounded ordinary read ceilings")?;
        let request = listing.encode()?;
        let offline = OfflineRepository::new(&repository_path)?;
        let refusal = services.list_backups(&administrator, &request);
        offline.restore()?;
        assert_eq!(refusal, Err(MaintenanceServiceFailure::CapacityUnavailable));
        drop(blocker);
        assert_eq!(
            services
                .list_backups(&administrator, &listing.encode()?)
                .map_err(|failure| format!(
                    "direct signed listing after capacity release: {failure:?}"
                ))?
                .entries
                .len(),
            1
        );
        assert_eq!(
            client
                .list(&administrator, &listing)
                .map_err(|failure| format!("signed listing after capacity release: {failure:?}"))?
                .entries
                .len(),
            1
        );
    }
    drop(services);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful
    );
    fs::remove_dir_all(repository_path)?;
    Ok(())
}

// The local capture estimate cannot know this other owner's signed key inventory.
// Keep its reservation live so the worker must retain those references alongside
// its own candidate; no signal-data objects need to be uploaded for this seed.
fn seed_remote_registry(
    services: &ServiceHandle,
    runtime: &tokio::runtime::Runtime,
    path: &std::path::Path,
    identity: &RepositoryIdentity,
) -> Result<(), Box<dyn std::error::Error>> {
    use positron_backup::{
        BackupCatalogIdentity, BackupKeyEnvelope, BackupManifest, BackupObject, BackupPublisher,
        BackupRetention,
    };
    let resources = backup_read_resources(services)?;
    let signer = {
        let _gate = services.catalog_operation()?;
        let catalog = open_catalog(&services.instance)?;
        let basis = catalog.pin()?;
        let (_, governance) = basis.governance_object()?;
        services.instance.key.backup_control_signer(
            services.instance.instance,
            governance.protected_integrity_key(),
        )?
    };
    let keys = (1u128..=512)
        .map(|tenant| BackupKeyEnvelope::new(tenant.to_be_bytes(), 1, [93; 32], vec![94; 64]))
        .collect::<Result<Vec<_>, _>>()?;
    let manifest = BackupManifest::new(
        [92; 16],
        identity.clone(),
        BackupCatalogIdentity::new(1, [95; 32], 2, 1, [96; 32])?,
        BackupRetention::new(1, 2)?,
        BackupPublisher::key_context(&keys)?,
        vec![BackupObject::new([96; 32], 1, 0, [97; 32], 1)?],
    )?;
    let external = u64::try_from(keys.capacity())?
        .checked_mul(std::mem::size_of::<BackupKeyEnvelope>() as u64)
        .and_then(|headers| {
            keys.iter().try_fold(headers, |bytes, key| {
                bytes.checked_add(key.retained_memory_bytes())
            })
        })
        .ok_or("seed retained key capacity")?;
    runtime.block_on(async {
        let repository = LocalRepository::attach(path, identity).await?;
        let publisher = BackupPublisher::new(&repository, identity, &signer)
            .with_control_resources(&resources, external)?;
        publisher.reserve(&manifest, &keys).await?;
        assert_eq!(
            publisher
                .cancellation_candidate([92; 16])
                .await?
                .ok_or("foreign reservation")?
                .snapshot_id(),
            [92; 16]
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

struct OfflineRepository {
    original: std::path::PathBuf,
    offline: Option<std::path::PathBuf>,
}
impl OfflineRepository {
    fn new(original: &std::path::Path) -> std::io::Result<Self> {
        let offline = original.with_extension("offline");
        fs::rename(original, &offline)?;
        Ok(Self {
            original: original.to_owned(),
            offline: Some(offline),
        })
    }
    fn restore(mut self) -> std::io::Result<()> {
        if let Some(offline) = &self.offline {
            fs::rename(offline, &self.original)?;
        }
        self.offline = None;
        Ok(())
    }
}
impl Drop for OfflineRepository {
    fn drop(&mut self) {
        if let Some(offline) = &self.offline
            && let Err(error) = fs::rename(offline, &self.original)
        {
            eprintln!("cannot restore offline test Repository: {error}");
        }
    }
}
