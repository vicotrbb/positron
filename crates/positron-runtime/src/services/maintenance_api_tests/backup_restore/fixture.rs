//! Source snapshot, independent recovery material and native provider fixtures.
use super::*;

pub(super) struct RestoreTestFixture {
    pub(super) initialized: Arc<crate::InitializedInstance>,
    pub(super) services: ServiceHandle,
    pub(super) repository_path: std::path::PathBuf,
    pub(super) runtime: tokio::runtime::Runtime,
    pub(super) target: std::path::PathBuf,
    pub(super) paths: crate::BootstrapPaths,
    pub(super) configuration: positron_config::EffectiveConfiguration,
    pub(super) restore: crate::BackupRestoreRequest,
    pub(super) unlock: age::x25519::Identity,
    pub(super) query: String,
    pub(super) pin: positron_kernel::RecoveryIdentity,
    pub(super) provider: Option<RestoreProviderFixture>,
    pub(super) _fixture: Fixture,
}
impl RestoreTestFixture {
    pub(super) fn prepare(case: RestoreCase) -> Result<Self, Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let (initialized, ingest, query, administrator) = fixture.initialized_with_admin()?;
        let export = fixture.recovery_export_directory()?;
        let repository_path = export.join("repository");
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
        drop(runtime.block_on(LocalRepository::initialize(&repository_path, identity))?);
        let mut services = ServiceHandle::new(Arc::clone(&initialized))?;
        services.ingest_otlp_logs(&ingest, request("restored telemetry").encode_to_vec())?;
        let unlock = age::x25519::Identity::generate();
        let mut bundle = export.join("restore.age");
        initialized.create_recovery_bundle(
            &bundle,
            &positron_kernel::RecoveryRecipients::parse(&[unlock.to_public().to_string()])?,
        )?;
        initialized
            .verify_recovery_bundle(&bundle, positron_kernel::RecoveryUnlock::Identity(&unlock))?;
        let mut pin = initialized.recovery_identity()?;
        let created = services
            .manage_backup(
                &administrator,
                &create(
                    &services,
                    &repository_path,
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                )?
                .encode()?,
            )
            .map_err(|failure| format!("backup acceptance: {failure:?}"))?;
        let cancellation = crate::TaskCancellation::new();
        let worker_services = services.clone();
        let worker_cancel = cancellation.clone();
        let worker =
            std::thread::spawn(move || worker_services.run_maintenance_worker(&worker_cancel));
        let published = retention::finish_direct(&services, &administrator, &created.operation.id);
        cancellation.cancel();
        worker.join().map_err(|_| "worker panic")??;
        let published = published?;
        let snapshot =
            crate::services::maintenance_verification::decode_fixed_hex(&created.operation.id)
                .ok_or("snapshot")?;
        let source = {
            let catalog = open_catalog(&initialized)?;
            let operation = positron_governance::DurableOperationAdministration::inspect(
                &catalog,
                positron_governance::OperationId::from_bytes(snapshot)?,
            )?
            .ok_or("backup operation")?;
            let binding = operation.backup_parameters().ok_or("backup intent")?;
            positron_governance::BackupVerificationParameters::new(
                binding.repository(),
                binding.registration_identity(),
                snapshot,
                crate::services::maintenance_verification::decode_fixed_hex(
                    &published.receipt.ok_or("receipt")?.manifest_checksum,
                )
                .ok_or("manifest")?,
            )?
        };
        if case.purged() || case == RestoreCase::MissingLive {
            let catalog = open_catalog(&initialized)?;
            let basis = catalog.pin()?;
            let (_, governance) = basis.governance_object()?;
            let signer = initialized.key.backup_control_signer(
                initialized.instance,
                governance.protected_integrity_key(),
            )?;
            let identity = RepositoryIdentity::local(
                [91; 16],
                initialized.instance.to_bytes(),
                initialized.integrity_key_fingerprint(),
                &repository_path,
            )?;
            let repository =
                runtime.block_on(LocalRepository::attach(&repository_path, &identity))?;
            let resources = backup_read_resources(&services)?;
            let publisher = positron_backup::BackupPublisher::new(&repository, &identity, &signer)
                .with_control_resources(&resources, 0)?;
            let proof = backup_inspection_proof(&runtime, &publisher, [0x72; 16])?;
            let publisher = publisher.with_registry_verification(&proof)?;
            let missing_key = if matches!(
                case,
                RestoreCase::MissingExcluded
                    | RestoreCase::MissingLive
                    | RestoreCase::RemovedReference
            ) {
                let state = runtime.block_on(
                    publisher.begin_snapshot_verification(snapshot, [0x74; 16], [0x75; 32]),
                )?;
                let key = runtime.block_on(publisher.read_verification_key(&state, 0))?;
                let mut bytes = b"POSBKE01".to_vec();
                bytes.extend_from_slice(&key.tenant());
                bytes.extend_from_slice(&key.epoch().to_be_bytes());
                bytes.extend_from_slice(&key.fingerprint());
                bytes.extend_from_slice(&(key.protected().len() as u32).to_be_bytes());
                bytes.extend_from_slice(key.protected());
                Some(positron_backup::ImmutableObject::new(bytes)?.id())
            } else {
                None
            };
            if case.purged() {
                runtime.block_on(
                    publisher.record_purge_tombstone(&positron_backup::BackupPurgeTombstone::new(
                        governance.tenant().to_bytes(),
                        governance.tenant_slug().as_str(),
                        [0x73; 16],
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)?
                            .as_secs(),
                    )?),
                )?;
            }
            if let Some(key) = missing_key {
                assert_eq!(
                    runtime.block_on(positron_backup::Repository::delete(&repository, key))?,
                    positron_backup::DeleteOutcome::Deleted
                );
                if case == RestoreCase::RemovedReference {
                    runtime.block_on(remove_registry_key_references(&repository, &signer))?;
                }
            }
        }
        if case == RestoreCase::RetiredLocal {
            let migration = fixture.migration_configuration()?;
            for (index, action) in ["prepare", "activate", "verify", "retire"]
                .into_iter()
                .enumerate()
            {
                let status = services
                    .manage_provider_migration(&administrator, br#"{"action":"status"}"#)
                    .map_err(|error| format!("retired source status: {error:?}"))?;
                let input = positron_api::provider_migration::ProviderMigrationRequest {
                    action: action.into(),
                    expected_catalog_generation: Some(status.catalog_generation),
                    idempotency_key: Some(format!("dddddddd-dddd-4ddd-8ddd-{:012}", index + 1)),
                    configuration_reference: Some(migration.to_string_lossy().into_owned()),
                    operation_id: None,
                }
                .encode()?;
                let accepted = services
                    .manage_provider_migration(&administrator, &input)
                    .map_err(|error| format!("retired source {action}: {error:?}"))?;
                let operation = accepted.operation.ok_or("root operation")?.id;
                let completed = super::envelope_migration::finish_root(
                    &mut services,
                    &administrator,
                    &operation,
                )?;
                assert_eq!(
                    completed
                        .operation
                        .as_ref()
                        .map(|operation| operation.status.as_str()),
                    Some("succeeded"),
                    "{action}: {completed:?}"
                );
                if action == "activate" {
                    let successor = export.join("successor.age");
                    initialized.create_recovery_bundle(
                        &successor,
                        &positron_kernel::RecoveryRecipients::parse(&[unlock
                            .to_public()
                            .to_string()])?,
                    )?;
                    initialized.verify_recovery_bundle(
                        &successor,
                        positron_kernel::RecoveryUnlock::Identity(&unlock),
                    )?;
                    initialized.retire_recovery_predecessor()?;
                    assert!(!bundle.exists(), "retired original bundle must be absent");
                    bundle = successor;
                }
                if action == "retire" {
                    assert_eq!(completed.predecessor_epoch, None);
                    assert!(
                        !export
                            .parent()
                            .ok_or("source root")?
                            .join("secrets/local-root-key.v1")
                            .exists()
                    );
                }
            }
            pin = initialized.recovery_identity()?;
        }
        let provider = if case == RestoreCase::Provider {
            let provider = RestoreProviderFixture::new(
                &initialized,
                &services,
                &repository_path,
                &export,
                source,
            )?;
            pin = initialized.recovery_identity()?;
            fs::remove_file(&bundle)?;
            Some(provider)
        } else {
            None
        };
        let target = export.join("fresh");
        fs::create_dir(&target)?;
        for name in ["data", "secrets"] {
            fs::create_dir(target.join(name))?;
            fs::set_permissions(target.join(name), fs::Permissions::from_mode(0o700))?;
        }
        let configuration_path = target.join("positron.toml");
        fs::write(
            &configuration_path,
            format!(
                "schema_version = 1\n[storage]\ndata_directory = {:?}\nsecrets_directory = {:?}\n",
                target.join("data"),
                target.join("secrets")
            ),
        )?;
        let configuration = positron_config::resolve(
            positron_config::ConfigurationInputs::try_from_sources(
                Some(&configuration_path),
                [] as [(&str, &str); 0],
                [] as [(&str, &str); 0],
            )
            .map_err(|failure| format!("configuration inputs: {failure:?}"))?,
        )?;
        let paths = crate::BootstrapPaths::new(
            &target.join("data"),
            &target.join("secrets"),
            positron_kernel::MountQualification::LocalHost,
        )?;
        let key = positron_governance::AdministrativeIdempotencyKey::new([0x77; 16])?;
        let restore = match &provider {
            Some(_) => crate::BackupRestoreRequest::provider(
                source,
                pin,
                initialized.key.bootstrap_identity(),
                2,
                key,
            )?,
            None => crate::BackupRestoreRequest::new(source, pin, bundle, key)?,
        };
        Ok(Self {
            initialized,
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
            _fixture: fixture,
        })
    }
}

pub(super) struct RestoreProviderFixture {
    pub(super) _runtime: tokio::runtime::Runtime,
    pub(super) server: tokio::task::JoinHandle<Vec<zeroize::Zeroizing<Vec<u8>>>>,
    pub(super) identity: positron_kernel::key_provider::ProviderKeyUri,
    pub(super) credentials: std::path::PathBuf,
}
impl RestoreProviderFixture {
    pub(super) fn configuration(
        &self,
    ) -> Result<positron_kernel::key_provider::NativeRootConfiguration, Box<dyn std::error::Error>>
    {
        use crate::instance_bootstrap::tests::provider_migration::fixtures;
        Ok(
            positron_kernel::key_provider::NativeRootConfiguration::Kmip {
                identity: self.identity.clone(),
                credentials: fixtures::model(&self.credentials)?,
            },
        )
    }
    fn new(
        initialized: &crate::InitializedInstance,
        services: &ServiceHandle,
        repository_path: &std::path::Path,
        export: &std::path::Path,
        source: positron_governance::BackupVerificationParameters,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        use crate::instance_bootstrap::tests::provider_migration::fixtures;
        use positron_kernel::key_provider::{ProviderFamily, ProviderKeyUri};
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let (port, server) = runtime.block_on(fixtures::transcript_transport(
            |port| fixtures::migration_replies(initialized, port, "immutable-id", 20),
            &[&rustls::version::TLS13],
        ))?;
        let credentials = export.join("provider-credentials");
        fs::create_dir(&credentials)?;
        fs::set_permissions(&credentials, fs::Permissions::from_mode(0o700))?;
        let fixture = Self {
            _runtime: runtime,
            server,
            identity: ProviderKeyUri::new(
                ProviderFamily::Kmip21,
                &format!("kmip://localhost:{port}/objects/immutable-id"),
                fixtures::PIN,
            )?,
            credentials,
        };
        initialized
            .begin_key_provider_migration(fixture.configuration()?)
            .map_err(|error| format!("provider source begin: {error:?}"))?;
        initialized
            .activate_key_provider_migration(fixture.configuration()?)
            .map_err(|error| format!("provider source activate: {error:?}"))?;
        // Registered backups require the owning migration worker for retirement;
        // this fixture retains the legitimate active provider and publishes its route.
        let (old, new) = initialized.backup_migration_envelopes()?;
        let catalog = open_catalog(initialized)?;
        let basis = catalog.pin()?;
        let signer = initialized.key.backup_control_signer(
            initialized.instance,
            basis.governance_object()?.1.protected_integrity_key(),
        )?;
        let identity = RepositoryIdentity::local(
            [91; 16],
            initialized.instance.to_bytes(),
            initialized.integrity_key_fingerprint(),
            repository_path,
        )?;
        let repository = fixture
            ._runtime
            .block_on(LocalRepository::attach(repository_path, &identity))?;
        let resources = backup_read_resources(services)?;
        let publisher = positron_backup::BackupPublisher::new(&repository, &identity, &signer)
            .with_control_resources(&resources, 0)?;
        let proof = backup_inspection_proof(&fixture._runtime, &publisher, [0x7b; 16])?;
        let publisher = publisher.with_registry_verification(&proof)?;
        let manifest = fixture
            ._runtime
            .block_on(publisher.verify(source.snapshot_id()))?;
        fixture
            ._runtime
            .block_on(publisher.publish_envelope_overlay(
                &positron_backup::BackupEnvelopeOverlay::new(
                    source.snapshot_id(),
                    positron_backup::ObjectId::from_checksum(source.manifest_checksum()),
                    manifest.key_context(),
                    [0x7c; 16],
                    old,
                    new,
                )?,
            ))?;
        Ok(fixture)
    }
}
impl Drop for RestoreProviderFixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
