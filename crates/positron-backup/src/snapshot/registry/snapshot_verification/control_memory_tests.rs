use super::*;

#[test]
fn canonical_key_object_maximum_preserves_codec_limits() -> Result<(), Box<dyn std::error::Error>> {
    let envelope = BackupKeyEnvelope::new([1; 16], 1, [2; 32], vec![3; MAX_KEY_PROTECTED_BYTES])?;
    let object = envelope.object()?;
    assert_eq!(object.bytes().len() as u64, MAX_KEY_OBJECT_BYTES);
    assert_eq!(BackupKeyEnvelope::decode_object(object.bytes())?, envelope);
    assert!(matches!(
        BackupKeyEnvelope::new([1; 16], 1, [2; 32], vec![3; MAX_KEY_PROTECTED_BYTES + 1]),
        Err(RepositoryFailure::InvalidInput)
    ));
    let mut oversized = object.bytes().to_vec();
    oversized[64..68].copy_from_slice(&((MAX_KEY_PROTECTED_BYTES + 1) as u32).to_be_bytes());
    oversized.push(3);
    assert!(matches!(
        BackupKeyEnvelope::decode_object(&oversized),
        Err(RepositoryFailure::CorruptState)
    ));
    Ok(())
}

#[tokio::test]
async fn control_admission_prices_registry_or_sequential_key_peak_without_reading()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::{BootstrapKeyCustody, BootstrapObjectPurpose, InstanceId};
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let custody = BootstrapKeyCustody::initialize(directory.path())?;
    let instance = InstanceId::new([2; 16])?;
    let protected = custody.protect(instance, BootstrapObjectPurpose::Initialized, &[7; 32])?;
    let signer = custody.backup_control_signer(instance, &protected)?;
    let path = directory.path().join("repository");
    std::fs::create_dir(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local(
        [1; 16],
        instance.to_bytes(),
        signer.identity().fingerprint(),
        &path,
    )?;
    let repository = crate::LocalRepository::initialize(&path, identity.clone()).await?;
    let manifest = BackupManifest::new(
        [3; 16],
        identity.clone(),
        super::super::super::BackupCatalogIdentity::new(1, [4; 32], 2, 0, [5; 32])?,
        super::super::super::BackupRetention::new(1, 2)?,
        [6; 32],
        vec![BackupObject::new([5; 32], 1, 0, [7; 32], 1)?],
    )?;
    let check =
        BackupPublicationCheck::start([8; 32], ObjectVersion::from_checksum([9; 32]), 1, vec![]);
    let mut state =
        BackupSnapshotVerification::start([10; 16], [11; 32], manifest, [12; 32], 492, check);
    let publisher = || BackupPublisher::new(&repository, &identity, &signer);
    let required = |extent| {
        Err(RepositoryFailure::ControlMemoryRequired {
            memory_bytes: MAX_CONTROL_BYTES + 8 * extent,
        })
    };
    assert_eq!(
        publisher().admit_snapshot_verification_controls(&state),
        required(492)
    );
    let reference = KeyReference {
        context: [6; 32],
        tenant: [13; 16],
        epoch: 1,
        fingerprint: [14; 32],
        object: crate::ObjectId::from_checksum([15; 32]),
    };
    state.check.keys.push(reference);
    assert_eq!(
        publisher().admit_snapshot_verification_controls(&state),
        required(MAX_KEY_OBJECT_BYTES)
    );
    state.check.keys.push(reference);
    assert_eq!(
        publisher().admit_snapshot_verification_controls(&state),
        required(MAX_KEY_OBJECT_BYTES)
    );
    state.registry_control_extent = MAX_KEY_OBJECT_BYTES + 1;
    assert_eq!(
        publisher().admit_snapshot_verification_controls(&state),
        required(MAX_KEY_OBJECT_BYTES + 1)
    );
    Ok(())
}
