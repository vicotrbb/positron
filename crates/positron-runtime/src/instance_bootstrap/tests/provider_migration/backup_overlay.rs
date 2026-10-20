//! Native provider recovery and immutable Backup Registry compose without changing tenant keys.
use super::*;
use positron_backup::*;
use positron_kernel::{Catalog, NativeAwsResources, ResourceAmounts, RootRewrapSession, WorkClaim};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_cutover_overlay_recovers_original_backup_tenant_key_after_cold_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|e| format!("paths {e:?}"))?;
    let instance = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let parent = roots.data.parent().ok_or("fixture parent")?;
    let credentials = parent.join("credentials");
    let repository_path = parent.join("backup-overlay-repository");
    for directory in [&credentials, &repository_path] {
        std::fs::create_dir(directory)?;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    }
    let tenant = instance.default_tenant_id();
    let (original_key, signer) = {
        let session = RootRewrapSession::admit(&instance._authority)?;
        let catalog = Catalog::open(
            &instance._authority,
            instance.instance,
            session.rotation_catalog_secret(&instance.key, instance.instance)?,
        )?;
        let basis = catalog.pin()?;
        let identity = positron_governance::Identity::open(&basis)?;
        let envelope = identity.tenant_key_envelope(tenant)?;
        let (epoch, fingerprint) =
            instance
                .key
                .backup_tenant_key_identity(instance.instance, tenant, envelope)?;
        (
            BackupKeyEnvelope::new(tenant.to_bytes(), epoch, fingerprint, envelope.to_vec())?,
            instance.key.backup_control_signer(
                instance.instance,
                basis.governance_object()?.1.protected_integrity_key(),
            )?,
        )
    };
    let identity = RepositoryIdentity::local(
        [91; 16],
        instance.instance.to_bytes(),
        signer.identity().fingerprint(),
        &repository_path,
    )?;
    let repository = LocalRepository::initialize(&repository_path, identity.clone()).await?;
    let grant = NativeAwsResources::new(
        instance
            .resource_governor()
            .reserve(WorkClaim::backup_repository_read(ResourceAmounts::new([
                32 * 1024 * 1024,
                1,
                1,
                0,
                1,
                0,
                1,
                1,
                1,
                4,
                16_384,
            ]))?)?
            .transfer(),
    );
    let publisher =
        BackupPublisher::new(&repository, &identity, &signer).with_control_resources(&grant, 0)?;
    let object = ImmutableObject::new(instance.key.protect(
        instance.instance,
        positron_kernel::BootstrapObjectPurpose::Initialized,
        b"retained encrypted backup fixture",
    )?)?;
    let manifest = BackupManifest::new(
        [92; 16],
        identity.clone(),
        BackupCatalogIdentity::new(1, [6; 32], 2, 1, [7; 32])?,
        BackupRetention::new(1, 2)?,
        BackupPublisher::key_context(std::slice::from_ref(&original_key))?,
        vec![BackupObject::new(
            [7; 32],
            object.bytes().len() as u64,
            0,
            object.id().checksum(),
            object.bytes().len() as u64,
        )?],
    )?;
    repository.put_if_absent(object).await?;
    publisher
        .reserve(&manifest, std::slice::from_ref(&original_key))
        .await?;
    let publication = publisher
        .publish(&manifest, std::slice::from_ref(&original_key))
        .await?;
    let (port, server) = transcript_transport(
        |port| migration_replies(&instance, port, "immutable-id", 5),
        &[&rustls::version::TLS13],
    )
    .await?;
    let target = ProviderKeyUri::new(
        ProviderFamily::Kmip21,
        &format!("kmip://localhost:{port}/objects/immutable-id"),
        PIN,
    )?;
    let configuration = || -> Result<_, Box<dyn std::error::Error>> {
        Ok(NativeRootConfiguration::Kmip {
            identity: target.clone(),
            credentials: model(&credentials)?,
        })
    };
    instance.begin_key_provider_migration(configuration()?)?;
    instance.activate_key_provider_migration(configuration()?)?;
    instance.verify_key_provider_migration(configuration()?)?;
    let (source, destination) = instance.backup_migration_envelopes(None)?;
    assert_eq!(source.identity().family(), ProviderFamily::LocalFile);
    assert_eq!(destination.identity(), &target);
    let overlay = BackupEnvelopeOverlay::new(
        manifest.snapshot_id(),
        publication.manifest(),
        manifest.key_context(),
        [93; 16],
        source.clone(),
        destination.clone(),
    )?;
    let generation = publisher.publish_envelope_overlay(&overlay).await?;
    assert_eq!(
        publisher
            .read_envelope_overlay(manifest.snapshot_id(), &target)
            .await?,
        Some(overlay.clone())
    );
    assert_eq!(publisher.verify(manifest.snapshot_id()).await?, manifest);
    drop(publisher);
    drop(grant);
    drop(instance);
    let reopened = InstanceBootstrap::reopen_with_provider(&paths, configuration()?)?;
    assert_eq!(
        reopened.key.backup_tenant_key_identity(
            reopened.instance,
            tenant,
            original_key.protected()
        )?,
        (original_key.epoch(), original_key.fingerprint())
    );
    {
        let session = RootRewrapSession::admit_provider(&reopened._authority)?;
        session.verify_backup_provider_root_envelope(
            configuration()?,
            &reopened.key,
            reopened.instance,
            reopened.local_key_rotation_status()?.active_epoch(),
            &overlay.target().encode(),
        )?;
    }
    let (cold_source, cold_target) = reopened.backup_migration_envelopes(None)?;
    assert_eq!(cold_source, source);
    assert_eq!(cold_target, destination);
    let grant = NativeAwsResources::new(
        reopened
            .resource_governor()
            .reserve(WorkClaim::backup_repository_read(ResourceAmounts::new([
                32 * 1024 * 1024,
                1,
                1,
                0,
                1,
                0,
                1,
                1,
                1,
                4,
                16_384,
            ]))?)?
            .transfer(),
    );
    let publisher = BackupPublisher::new(&repository, &identity, &signer)
        .with_control_resources(&grant, 0)?
        .with_trusted_generation(generation)?;
    let check = publisher
        .begin_snapshot_verification(manifest.snapshot_id(), [94; 16], [95; 32])
        .await?;
    let retained = publisher.read_verification_key(&check, 0).await?;
    assert_eq!(retained, original_key);
    assert_eq!(
        reopened
            .key
            .backup_tenant_key_identity(reopened.instance, tenant, retained.protected())?,
        (original_key.epoch(), original_key.fingerprint())
    );
    assert_eq!(
        publisher
            .read_envelope_overlay(manifest.snapshot_id(), &target)
            .await?,
        Some(overlay)
    );
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(10), server)
            .await??
            .len(),
        30
    );
    Ok(())
}
