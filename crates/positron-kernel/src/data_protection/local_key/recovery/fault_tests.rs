use super::super::initialization_io::{InitializationFault, with_initialization_fault};
use super::super::test_support::SecurityRoot;
use super::*;
use crate::{InstanceBootstrapStorage, MountQualification};

#[test]
fn recovered_root_publication_resumes_only_authenticated_complete_staging()
-> Result<(), Box<dyn std::error::Error>> {
    for fault in [
        InitializationFault::SynchronizeKeyFile,
        InitializationFault::SynchronizeSecurityDirectory,
        InitializationFault::PartialWrite(17),
    ] {
        let source = SecurityRoot::create()?;
        let data = SecurityRoot::create()?;
        let target = SecurityRoot::create()?;
        let custody = BootstrapKeyCustody::initialize(&source.path)?;
        let instance = InstanceId::new([0x11; 16])?;
        let protected = custody.protect_instance_integrity_key(instance, &[0x12; 32])?;
        let pin = RecoveryIdentity::new(
            instance,
            custody.identity(),
            custody.integrity_identity(&[0x12; 32])?,
        )?;
        let recipient = age::x25519::Identity::generate();
        let authority = crate::data_protection::recovery_tests::authority()?;
        let session = RecoverySession::admit(&authority, RecoveryProtection::Recipients)?;
        let bundle = session.create(
            &custody,
            pin,
            &protected,
            &RecoveryRecipients::parse(&[recipient.to_public().to_string()])?,
            456,
        )?;
        let storage =
            InstanceBootstrapStorage::new(&data.path, &target.path, MountQualification::LocalHost)
                .map_err(|_| "fixture storage unavailable")?;
        let access = storage
            .inspect()
            .map_err(|_| "fixture access unavailable")?;
        let result = with_initialization_fault(fault, || {
            session.import(
                &bundle,
                RecoveryUnlock::Identity(&recipient),
                pin,
                &access,
                |_| Ok(()),
            )
        });
        assert!(result.is_err());
        match fault {
            InitializationFault::SynchronizeSecurityDirectory => {
                assert_eq!(access.open_key()?.identity(), pin.root())
            },
            InitializationFault::SynchronizeKeyFile => {
                assert!(access.open_key().is_err());
                let repeated =
                    with_initialization_fault(InitializationFault::SynchronizeKeyFile, || {
                        session.import(
                            &bundle,
                            RecoveryUnlock::Identity(&recipient),
                            pin,
                            &access,
                            |_| Ok(()),
                        )
                    });
                assert!(
                    repeated.is_err(),
                    "resumed staging must be synchronized before publication"
                );
                assert!(access.open_key().is_err());
                session.import(
                    &bundle,
                    RecoveryUnlock::Identity(&recipient),
                    pin,
                    &access,
                    |_| Ok(()),
                )?;
                assert_eq!(access.open_key()?.identity(), pin.root());
            },
            InitializationFault::PartialWrite(_) => {
                assert!(access.open_key().is_err());
                assert!(
                    session
                        .import(
                            &bundle,
                            RecoveryUnlock::Identity(&recipient),
                            pin,
                            &access,
                            |_| Ok(())
                        )
                        .is_err()
                );
                assert!(access.open_key().is_err());
            },
            _ => return Err("unexpected fixture fault".into()),
        }
    }
    Ok(())
}

#[test]
fn authenticated_inspection_releases_recovered_root_temporary_after_zeroization()
-> Result<(), Box<dyn std::error::Error>> {
    let source = SecurityRoot::create()?;
    let custody = BootstrapKeyCustody::initialize(&source.path)?;
    let instance = InstanceId::new([0x15; 16])?;
    let protected = custody.protect_instance_integrity_key(instance, &[0x16; 32])?;
    let pin = RecoveryIdentity::new(
        instance,
        custody.identity(),
        custody.integrity_identity(&[0x16; 32])?,
    )?;
    let recipient = age::x25519::Identity::generate();
    let authority = crate::data_protection::recovery_tests::authority()?;
    let session = RecoverySession::admit(&authority, RecoveryProtection::Recipients)?;
    let bundle = session.create(
        &custody,
        pin,
        &protected,
        &RecoveryRecipients::parse(&[recipient.to_public().to_string()])?,
        456,
    )?;
    let observed = std::rc::Rc::new(std::cell::Cell::new(false));
    let metadata =
        super::super::codec::with_secret_release_observer(std::rc::Rc::clone(&observed), || {
            session.inspect(&bundle, RecoveryUnlock::Identity(&recipient), pin)
        })?;
    assert_eq!(metadata.identity(), pin);
    assert!(
        observed.get(),
        "recovered root temporary must be zeroized before release"
    );
    Ok(())
}

#[test]
fn bounded_recovery_mutation_oracle_exercises_raw_signed_and_canonical_payloads()
-> Result<(), RecoveryFailure> {
    for program in [
        &[][..],
        &[1][..],
        &[2][..],
        &[1, 0, 0, 0xff][..],
        &[2, 0, 20, 1][..],
        &[0, 0xff][..],
    ] {
        super::fuzzing::exercise(program)?;
    }
    Ok(())
}

#[test]
fn signed_recovery_payload_rejects_noncanonical_recipient_order()
-> Result<(), Box<dyn std::error::Error>> {
    let source = SecurityRoot::create()?;
    let custody = BootstrapKeyCustody::initialize(&source.path)?;
    let seed = Zeroizing::new([0x44; 32]);
    let pin = RecoveryIdentity::new(
        InstanceId::new([0x45; 16])?,
        custody.identity(),
        custody.integrity_identity(&seed)?,
    )?;
    let first = age::x25519::Identity::generate();
    let second = age::x25519::Identity::generate();
    let mut recipients = vec![
        first.to_public().to_string(),
        second.to_public().to_string(),
    ];
    recipients.sort();
    recipients.reverse();
    let metadata = RecoveryMetadata {
        identity: pin,
        created: 123,
        recipients,
    };
    let plaintext = signed(
        &encode(&metadata, custody.key.root_key.0.expose_to_backend()),
        &seed,
    )?;
    let authority = crate::data_protection::recovery_tests::authority()?;
    let session = RecoverySession::admit(&authority, RecoveryProtection::Recipients)?;
    let cipher = RustCryptoBackend
        .seal_recovery(
            RecoveryCryptoPurpose::LocalRootPayloadV1,
            RecoveryEncryption::Recipients(&[first.to_public().to_string()]),
            &plaintext,
        )
        .map_err(|_| RecoveryFailure::Authentication)?;
    assert_eq!(
        session.inspect(&cipher, RecoveryUnlock::Identity(&first), pin),
        Err(RecoveryFailure::Authentication)
    );
    Ok(())
}

#[test]
fn absent_retired_bundle_requires_durable_parent_confirmation()
-> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let path = root.path.join("retired.age");
    let authority = crate::data_protection::recovery_tests::authority()?;
    let session = RecoverySession::admit(&authority, RecoveryProtection::Recipients)?;
    let bytes = b"encrypted fixture";
    session.write_new(&path, bytes)?;
    let digest = crate::data_protection::DataProtection::hash(bytes)?;
    let unlink =
        with_initialization_fault(InitializationFault::SynchronizeSecurityDirectory, || {
            session.retire(&path, digest)
        });
    assert_eq!(unlink, Err(RecoveryFailure::Storage));
    assert!(!path.exists());
    let retry =
        with_initialization_fault(InitializationFault::SynchronizeSecurityDirectory, || {
            session.retire(&path, digest)
        });
    assert_eq!(retry, Err(RecoveryFailure::Storage));
    assert_eq!(session.retire(&path, digest), Err(RecoveryFailure::Missing));
    Ok(())
}

#[test]
fn recovery_payload_requires_its_signature_purpose() -> Result<(), Box<dyn std::error::Error>> {
    use crate::data_protection::key_envelope::encode_bytes_field;
    let source = SecurityRoot::create()?;
    let custody = BootstrapKeyCustody::initialize(&source.path)?;
    let seed = Zeroizing::new([0x48; 32]);
    let pin = RecoveryIdentity::new(
        InstanceId::new([0x49; 16])?,
        custody.identity(),
        custody.integrity_identity(&seed)?,
    )?;
    let identity = age::x25519::Identity::generate();
    let recipients = vec![identity.to_public().to_string()];
    let metadata = RecoveryMetadata {
        identity: pin,
        created: 123,
        recipients: recipients.clone(),
    };
    let payload = encode(&metadata, custody.key.root_key.0.expose_to_backend());
    // An independent reference signature is valid Ed25519, but for a different purpose.
    let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(seed.as_slice())
        .map_err(|_| "fixture signature unavailable")?;
    let signature = pair.sign(&payload);
    let mut envelope = Zeroizing::new(Vec::new());
    encode_bytes_field(1, &payload, &mut envelope);
    encode_bytes_field(2, signature.as_ref(), &mut envelope);
    let cipher = RustCryptoBackend
        .seal_recovery(
            RecoveryCryptoPurpose::LocalRootPayloadV1,
            RecoveryEncryption::Recipients(&recipients),
            &envelope,
        )
        .map_err(|_| RecoveryFailure::Authentication)?;
    let authority = crate::data_protection::recovery_tests::authority()?;
    let session = RecoverySession::admit(&authority, RecoveryProtection::Recipients)?;
    assert_eq!(
        session.inspect(&cipher, RecoveryUnlock::Identity(&identity), pin),
        Err(RecoveryFailure::Authentication)
    );
    Ok(())
}
