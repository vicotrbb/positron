use super::*;
use crate::data_protection::local_key::test_support::SecurityRoot;

#[test]
fn backup_local_root_routes_independently_recover_the_stable_system_key()
-> Result<(), Box<dyn std::error::Error>> {
    let data = SecurityRoot::create()?;
    let secrets = SecurityRoot::create()?;
    let storage = crate::InstanceBootstrapStorage::new(
        &data.path,
        &secrets.path,
        crate::MountQualification::LocalHost,
    )
    .map_err(|_| "bootstrap roots")?;
    let (_lease, access) = storage.acquire().map_err(|_| "bootstrap access")?;
    let authority = crate::data_protection::recovery_tests::authority()?;
    let session = RootRewrapSession::admit(&authority)?;
    let instance = InstanceId::new([0x75; 16])?;
    let original = session.lease_system(
        access.initialize_key()?,
        instance,
        crate::key_provider::KeyCacheLease::default(),
    )?;
    let successor = session.prepare_successor(&access, 2)?;
    let old = session.wrap_system(&original, &original, instance, 1)?;
    let new = session.wrap_system(&original, &successor, instance, 2)?;
    session
        .prepare_activation(&original, successor, instance, 2, &new)?
        .activate(&original)?;
    session.verify_local_backup_root_envelope(&access, &original, instance, 1, &old)?;
    session.verify_local_backup_root_envelope(&access, &original, instance, 2, &new)?;
    let independently_opened = session.open_successor(&access, 2)?;
    let context = session.system_context(instance, original.bootstrap_identity())?;
    let provider = LocalKeyProvider::identity_for_custody(&independently_opened, 2)?;
    let different = SecretKek::from_owned(Box::new([0x99; 32]));
    let payload = SecretWrappedKeyPayload::encode(&different, context, &provider)?;
    let wrong_system =
        LocalKeyProvider::wrap_for_epoch(&independently_opened, 2, payload, context)?.encode();
    assert_eq!(
        session.verify_local_backup_root_envelope(&access, &original, instance, 2, &wrong_system),
        Err(BootstrapKeyFailure::Authentication)
    );
    assert!(
        session
            .verify_local_backup_root_envelope(&access, &original, instance, 1, &new)
            .is_err()
    );
    assert!(
        session
            .verify_local_backup_root_envelope(
                &access,
                &original,
                InstanceId::new([0x76; 16])?,
                2,
                &new
            )
            .is_err()
    );
    let mut corrupt = new.clone();
    *corrupt.last_mut().ok_or("envelope")? ^= 1;
    assert!(
        session
            .verify_local_backup_root_envelope(&access, &original, instance, 2, &corrupt)
            .is_err()
    );
    assert!(
        session
            .verify_local_backup_root_envelope(&access, &original, instance, 3, &new)
            .is_err()
    );
    Ok(())
}
