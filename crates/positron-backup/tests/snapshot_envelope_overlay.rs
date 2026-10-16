#![cfg(feature = "test-support")]
#[path = "support/snapshot_resources.rs"]
mod resources;
use positron_backup::*;
use positron_kernel::key_provider::{
    EnvelopeContext, KeyEnvelope, KeyScope, ProviderFamily, ProviderKeyUri, WrappingAlgorithm,
};
use positron_kernel::{BootstrapKeyCustody, BootstrapObjectPurpose, InstanceId};
fn envelope(version: &str) -> Result<KeyEnvelope, Box<dyn std::error::Error>> {
    Ok(KeyEnvelope::from_provider_response(
        ProviderKeyUri::new(ProviderFamily::LocalFile, "root", version)?,
        EnvelopeContext::new([2; 16], KeyScope::System, [4; 32], 1, 1)?,
        WrappingAlgorithm::Aes256Kwp,
        vec![8; 40],
    )?)
}
#[tokio::test]
async fn overlay_is_append_only_idempotent_and_bound_to_published_snapshot()
-> Result<(), Box<dyn std::error::Error>> {
    resources::admitted(96 * 1024 * 1024, |resources| async move {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let secrets = dir.path().join("secrets");
        let path = dir.path().join("repo");
        for p in [&secrets, &path] {
            std::fs::create_dir(p)?;
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))?;
        }
        let custody = BootstrapKeyCustody::initialize(&secrets)?;
        let instance = InstanceId::new([2; 16])?;
        let protected = custody.protect(instance, BootstrapObjectPurpose::Initialized, &[7; 32])?;
        let signer = custody.backup_control_signer(instance, &protected)?;
        let identity =
            RepositoryIdentity::local([1; 16], [2; 16], signer.identity().fingerprint(), &path)?;
        let repository = LocalRepository::initialize(&path, identity.clone()).await?;
        let publisher = BackupPublisher::new(&repository, &identity, &signer)
            .with_control_resources(&resources, 64 * 1024)?;
        let keys = vec![BackupKeyEnvelope::new([3; 16], 1, [4; 32], vec![5; 64])?];
        let object = ImmutableObject::new(vec![6; 64])?;
        let manifest = BackupManifest::new(
            [5; 16],
            identity.clone(),
            BackupCatalogIdentity::new(1, [6; 32], 2, 1, [7; 32])?,
            BackupRetention::new(1, 2)?,
            BackupPublisher::key_context(&keys)?,
            vec![BackupObject::new(
                [7; 32],
                64,
                0,
                object.id().checksum(),
                64,
            )?],
        )?;
        repository.put_if_absent(object).await?;
        publisher.reserve(&manifest, &keys).await?;
        let publication = publisher.publish(&manifest, &keys).await?;
        let overlay = BackupEnvelopeOverlay::new(
            manifest.snapshot_id(),
            publication.manifest(),
            manifest.key_context(),
            [9; 16],
            envelope("one")?,
            envelope("two")?,
        )?;
        let signed = overlay.signed_bytes(&identity, &signer)?;
        assert_eq!(
            BackupEnvelopeOverlay::verify(&vec![0; 18_401], &identity, signer.identity()),
            Err(RepositoryFailure::LimitExceeded)
        );
        assert_eq!(
            BackupEnvelopeOverlay::verify(&signed, &identity, signer.identity())?,
            overlay
        );
        let mut corrupt = signed.clone();
        *corrupt.last_mut().ok_or("signature")? ^= 1;
        assert!(BackupEnvelopeOverlay::verify(&corrupt, &identity, signer.identity()).is_err());
        use sha2::Digest;
        let payload = signed.get(..signed.len() - 64).ok_or("overlay payload")?;
        for (offset, value) in [(0, 0xff), (212, 0xff), (216, 0xff)] {
            let mut malformed = payload.to_vec();
            *malformed.get_mut(offset).ok_or("overlay field")? = value;
            let signature = signer.sign(&sha2::Sha256::digest(&malformed))?;
            malformed.extend_from_slice(&signature.bytes());
            assert!(
                BackupEnvelopeOverlay::verify(&malformed, &identity, signer.identity()).is_err()
            );
        }
        let generation = publisher.publish_envelope_overlay(&overlay).await?;
        assert_ne!(generation, publication.registry_generation());
        assert_eq!(
            publisher.publish_envelope_overlay(&overlay).await?,
            generation
        );
        assert_eq!(
            publisher
                .read_envelope_overlay(manifest.snapshot_id(), overlay.target().identity())
                .await?,
            Some(overlay.clone())
        );
        assert_eq!(publisher.verify(manifest.snapshot_id()).await?, manifest);
        assert_eq!(
            publisher
                .read_envelope_overlay(manifest.snapshot_id(), overlay.source().identity())
                .await?,
            None
        );
        let conflict = BackupEnvelopeOverlay::new(
            manifest.snapshot_id(),
            publication.manifest(),
            manifest.key_context(),
            [10; 16],
            envelope("one")?,
            envelope("two")?,
        )?;
        assert_eq!(
            publisher.publish_envelope_overlay(&conflict).await,
            Err(RepositoryFailure::PreconditionFailed)
        );
        let wrong_context = BackupEnvelopeOverlay::new(
            manifest.snapshot_id(),
            publication.manifest(),
            [10; 32],
            [9; 16],
            envelope("one")?,
            envelope("two")?,
        )?;
        assert_eq!(
            publisher.publish_envelope_overlay(&wrong_context).await,
            Err(RepositoryFailure::IdentityMismatch)
        );
        let reopened = LocalRepository::attach(&path, &identity).await?;
        let cold = BackupPublisher::new(&reopened, &identity, &signer)
            .with_trusted_generation(generation)?
            .with_control_resources(&resources, 64 * 1024)?;
        assert_eq!(
            cold.read_envelope_overlay(manifest.snapshot_id(), overlay.target().identity())
                .await?,
            Some(overlay.clone())
        );
        assert_eq!(cold.publish_envelope_overlay(&overlay).await?, generation);
        assert_eq!(
            cold.read_envelope_overlay([99; 16], overlay.target().identity())
                .await,
            Err(RepositoryFailure::NotFound)
        );
        let wrong_repository =
            RepositoryIdentity::local([99; 16], [2; 16], signer.identity().fingerprint(), &path)?;
        assert!(
            BackupEnvelopeOverlay::verify(&signed, &wrong_repository, signer.identity()).is_err()
        );

        let wrong = BackupEnvelopeOverlay::new(
            manifest.snapshot_id(),
            ObjectId::from_checksum([8; 32]),
            manifest.key_context(),
            [9; 16],
            envelope("one")?,
            envelope("two")?,
        )?;
        assert_eq!(
            publisher.publish_envelope_overlay(&wrong).await,
            Err(RepositoryFailure::IdentityMismatch)
        );
        let next = BackupEnvelopeOverlay::new(
            manifest.snapshot_id(),
            publication.manifest(),
            manifest.key_context(),
            [11; 16],
            envelope("two")?,
            envelope("three")?,
        )?;
        assert_ne!(cold.publish_envelope_overlay(&next).await?, generation);
        assert_eq!(
            publisher.publish_envelope_overlay(&overlay).await,
            Err(RepositoryFailure::PreconditionFailed)
        );
        Ok(())
    })
    .await
}
#[test]
fn overlay_rejects_unrelated_system_key_context() -> Result<(), Box<dyn std::error::Error>> {
    let target = KeyEnvelope::from_provider_response(
        ProviderKeyUri::new(ProviderFamily::LocalFile, "root", "two")?,
        EnvelopeContext::new([2; 16], KeyScope::System, [99; 32], 1, 1)?,
        WrappingAlgorithm::Aes256Kwp,
        vec![8; 40],
    )?;
    assert_eq!(
        BackupEnvelopeOverlay::new(
            [5; 16],
            ObjectId::from_checksum([6; 32]),
            [7; 32],
            [8; 16],
            envelope("one")?,
            target
        ),
        Err(RepositoryFailure::IdentityMismatch)
    );
    Ok(())
}
#[test]
fn overlay_admission_counts_retained_envelope_capacity() -> Result<(), Box<dyn std::error::Error>> {
    let mut ciphertext = Vec::with_capacity(1024 * 1024);
    ciphertext.extend_from_slice(&[8; 40]);
    let target = KeyEnvelope::from_provider_response(
        ProviderKeyUri::new(ProviderFamily::LocalFile, "root", "two")?,
        EnvelopeContext::new([2; 16], KeyScope::System, [4; 32], 1, 1)?,
        WrappingAlgorithm::Aes256Kwp,
        ciphertext,
    )?;
    let overlay = BackupEnvelopeOverlay::new(
        [5; 16],
        ObjectId::from_checksum([6; 32]),
        [7; 32],
        [8; 16],
        envelope("one")?,
        target,
    )?;
    assert!(overlay.retained_memory_bytes() >= 1024 * 1024);
    Ok(())
}
#[test]
fn overlay_rejects_invalid_snapshot_bindings_and_unchanged_provider()
-> Result<(), Box<dyn std::error::Error>> {
    for (snapshot, manifest, context, operation) in [
        ([0; 16], [6; 32], [7; 32], [8; 16]),
        ([5; 16], [0; 32], [7; 32], [8; 16]),
        ([5; 16], [6; 32], [0; 32], [8; 16]),
        ([5; 16], [6; 32], [7; 32], [0; 16]),
    ] {
        assert_eq!(
            BackupEnvelopeOverlay::new(
                snapshot,
                ObjectId::from_checksum(manifest),
                context,
                operation,
                envelope("one")?,
                envelope("two")?
            ),
            Err(RepositoryFailure::InvalidInput)
        );
    }
    assert_eq!(
        BackupEnvelopeOverlay::new(
            [5; 16],
            ObjectId::from_checksum([6; 32]),
            [7; 32],
            [8; 16],
            envelope("one")?,
            envelope("one")?
        ),
        Err(RepositoryFailure::IdentityMismatch)
    );
    Ok(())
}

#[cfg(feature = "test-support")]
#[tokio::test]
async fn overlay_cas_failure_preserves_recovery_and_lost_ack_reconciles_without_duplicate_route()
-> Result<(), Box<dyn std::error::Error>> {
    resources::admitted(96 * 1024 * 1024, |resources| async move {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let secrets = dir.path().join("secrets");
        let path = dir.path().join("repo");
        for p in [&secrets, &path] {
            std::fs::create_dir(p)?;
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))?;
        }
        let custody = BootstrapKeyCustody::initialize(&secrets)?;
        let instance = InstanceId::new([2; 16])?;
        let protected = custody.protect(instance, BootstrapObjectPurpose::Initialized, &[7; 32])?;
        let signer = custody.backup_control_signer(instance, &protected)?;
        let identity =
            RepositoryIdentity::local([1; 16], [2; 16], signer.identity().fingerprint(), &path)?;
        let repository = LocalRepository::initialize(&path, identity.clone()).await?;
        let publisher = BackupPublisher::new(&repository, &identity, &signer)
            .with_control_resources(&resources, 64 * 1024)?;
        let keys = vec![BackupKeyEnvelope::new([3; 16], 1, [4; 32], vec![5; 64])?];
        let object = ImmutableObject::new(vec![6; 64])?;
        let manifest = BackupManifest::new(
            [5; 16],
            identity.clone(),
            BackupCatalogIdentity::new(1, [6; 32], 2, 1, [7; 32])?,
            BackupRetention::new(1, 2)?,
            BackupPublisher::key_context(&keys)?,
            vec![BackupObject::new(
                [7; 32],
                64,
                0,
                object.id().checksum(),
                64,
            )?],
        )?;
        repository.put_if_absent(object).await?;
        publisher.reserve(&manifest, &keys).await?;
        let publication = publisher.publish(&manifest, &keys).await?;
        let overlay = BackupEnvelopeOverlay::new(
            manifest.snapshot_id(),
            publication.manifest(),
            manifest.key_context(),
            [9; 16],
            envelope("one")?,
            envelope("two")?,
        )?;

        let first = publisher.publish_envelope_overlay(&overlay).await?;
        let original_head = repository.registry_head_at(HeadSlot::registry()).await?;
        drop(publisher);
        let next = BackupEnvelopeOverlay::new(
            manifest.snapshot_id(),
            publication.manifest(),
            manifest.key_context(),
            [10; 16],
            envelope("two")?,
            envelope("three")?,
        )?;
        let interrupted = LocalRepository::attach(&path, &identity)
            .await?
            .with_faults(vec![LocalFault::new(
                LocalFaultPoint::BeforeRegistryPublication,
                LocalFaultEffect::Interrupted,
                0,
            )])?;
        let publisher = BackupPublisher::new(&interrupted, &identity, &signer)
            .with_control_resources(&resources, 64 * 1024)?
            .with_trusted_generation(first)?;
        assert_eq!(
            publisher.publish_envelope_overlay(&next).await,
            Err(RepositoryFailure::Interrupted)
        );
        assert_eq!(
            repository.registry_head_at(HeadSlot::registry()).await?,
            original_head
        );
        assert_eq!(
            publisher
                .read_envelope_overlay(manifest.snapshot_id(), overlay.target().identity())
                .await?,
            Some(overlay.clone())
        );
        assert_eq!(
            publisher
                .read_envelope_overlay(manifest.snapshot_id(), next.target().identity())
                .await?,
            None
        );
        assert_eq!(publisher.verify(manifest.snapshot_id()).await?, manifest);
        drop(publisher);
        let uncertain = LocalRepository::attach(&path, &identity)
            .await?
            .with_faults(vec![LocalFault::new(
                LocalFaultPoint::AfterRegistryPublication,
                LocalFaultEffect::OutcomeUnknown,
                0,
            )])?;
        let publisher = BackupPublisher::new(&uncertain, &identity, &signer)
            .with_control_resources(&resources, 64 * 1024)?
            .with_trusted_generation(first)?;
        let reconciled = publisher.publish_envelope_overlay(&next).await?;
        assert_ne!(reconciled, first);
        assert_eq!(publisher.publish_envelope_overlay(&next).await?, reconciled);
        assert_eq!(
            publisher
                .read_envelope_overlay(manifest.snapshot_id(), overlay.target().identity())
                .await?,
            Some(overlay.clone())
        );
        assert_eq!(
            publisher
                .read_envelope_overlay(manifest.snapshot_id(), next.target().identity())
                .await?,
            Some(next.clone())
        );
        let state = publisher
            .begin_snapshot_verification(manifest.snapshot_id(), [11; 16], [12; 32])
            .await?;
        assert_eq!(
            publisher.read_verification_key(&state, 0).await?,
            *keys.first().ok_or("original key")?
        );
        assert_eq!(publisher.verify(manifest.snapshot_id()).await?, manifest);
        drop(publisher);
        let cold = LocalRepository::attach(&path, &identity).await?;
        let publisher = BackupPublisher::new(&cold, &identity, &signer)
            .with_control_resources(&resources, 64 * 1024)?
            .with_trusted_generation(reconciled)?;
        assert_eq!(publisher.publish_envelope_overlay(&next).await?, reconciled);
        assert_eq!(
            publisher
                .read_envelope_overlay(manifest.snapshot_id(), next.target().identity())
                .await?,
            Some(next)
        );
        assert_eq!(
            publisher
                .read_envelope_overlay(manifest.snapshot_id(), overlay.target().identity())
                .await?,
            Some(overlay)
        );
        Ok(())
    })
    .await
}
