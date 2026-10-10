use crate::data_protection::local_key::test_support::SecurityRoot;
use crate::*;

pub(crate) fn authority() -> Result<StorageKernelResourceAuthority, Box<dyn std::error::Error>> {
    let amounts = ResourceAmounts::new([
        400_000_000,
        32,
        32,
        400_000_000,
        100,
        32,
        32,
        32,
        100,
        32,
        400_000_000,
    ]);
    let cardinality = InventoryCardinalityLimits::new(1, 16)?;
    let overhead = cardinality.governor_bootstrap_overhead(1)?;
    let raw =
        ResourceAmounts::new(ResourceDimension::ALL.map(|d| amounts.get(d) + overhead.get(d)));
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(raw)?,
        OperatorLimits::new(raw)?,
        RecoveryReserve::new(ResourceAmounts::new([10; 11]))?,
        cardinality,
        DiskPressureThresholds::new(10, 11, 12, 400_000_000)?,
        DiskObservation::new(400_000_000),
    )?;
    let lane = ResourceAmounts::new([
        350_000_000,
        4,
        4,
        350_000_000,
        32,
        4,
        4,
        4,
        50,
        8,
        350_000_000,
    ]);
    let small = ResourceAmounts::new([1; 11]);
    let policy = GovernorPolicy::system_only(OrdinaryPoolPolicy::new(
        lane,
        ResourceAmounts::new([2; 11]),
        small,
        small,
    )?);
    let dual = ResourceAmounts::new([2; 11]);
    Ok(StorageKernelResourceAuthority::establish_for_test(
        inventory,
        policy,
        RecoveryPoolCapacities::new(dual, small, dual, small, dual, small, small)?,
    )?)
}

#[test]
fn recovery_bundle_is_age_v1_and_authenticates_each_authorized_recipient()
-> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let custody = BootstrapKeyCustody::initialize(&root.path)?;
    let instance = InstanceId::new([0x41; 16])?;
    let protected = custody.protect_instance_integrity_key(instance, &[0x51; 32])?;
    let integrity = custody.integrity_identity(&[0x51; 32])?;
    let pin = RecoveryIdentity::new(instance, custody.identity(), integrity)?;
    let first = age::x25519::Identity::generate();
    let second = age::x25519::Identity::generate();
    let recipients = RecoveryRecipients::parse(&[
        first.to_public().to_string(),
        second.to_public().to_string(),
    ])?;
    let authority = authority()?;
    let session = RecoverySession::admit(&authority, RecoveryProtection::Recipients)?;
    let bundle = session.create(&custody, pin, &protected, &recipients, 123)?;
    assert!(bundle.starts_with(b"age-encryption.org/v1\n"));
    assert_ne!(
        bundle,
        session.create(&custody, pin, &protected, &recipients, 123)?,
        "age must use fresh per-container randomness"
    );
    for identity in [&first, &second] {
        let inspected = session.inspect(&bundle, RecoveryUnlock::Identity(identity), pin)?;
        assert_eq!(inspected.identity(), pin);
        assert_eq!(inspected.created_at_unix_seconds(), 123);
        assert_eq!(inspected.recipients().len(), 2);
    }
    Ok(())
}

#[test]
fn recovery_export_is_owner_only_exclusive_and_wrong_recipient_cannot_inspect()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let root = SecurityRoot::create()?;
    let export = SecurityRoot::create()?;
    let custody = BootstrapKeyCustody::initialize(&root.path)?;
    let instance = InstanceId::new([0x61; 16])?;
    let protected = custody.protect_instance_integrity_key(instance, &[0x71; 32])?;
    let pin = RecoveryIdentity::new(
        instance,
        custody.identity(),
        custody.integrity_identity(&[0x71; 32])?,
    )?;
    let identity = age::x25519::Identity::generate();
    let recipients = RecoveryRecipients::parse(&[identity.to_public().to_string()])?;
    let authority = authority()?;
    let session = RecoverySession::admit(&authority, RecoveryProtection::Recipients)?;
    let bundle = session.create(&custody, pin, &protected, &recipients, 456)?;
    let path = export.path.join("recovery.age");
    session.write_new(&path, &bundle)?;
    assert_eq!(
        std::fs::metadata(&path)?.permissions().mode() & 0o7777,
        0o600
    );
    assert_eq!(session.read(&path)?, bundle);
    assert_eq!(
        session.write_new(&path, &bundle),
        Err(RecoveryFailure::AlreadyExists)
    );
    let wrong = age::x25519::Identity::generate();
    assert_eq!(
        session.inspect(&bundle, RecoveryUnlock::Identity(&wrong), pin),
        Err(RecoveryFailure::Authentication)
    );
    let other = RecoveryIdentity::new(InstanceId::new([0x62; 16])?, pin.root(), pin.integrity())?;
    assert_eq!(
        session.inspect(&bundle, RecoveryUnlock::Identity(&identity), other),
        Err(RecoveryFailure::Authentication)
    );
    let mut corrupt = bundle.clone();
    if let Some(last) = corrupt.last_mut() {
        *last ^= 1;
    }
    assert_eq!(
        session.inspect(&corrupt, RecoveryUnlock::Identity(&identity), pin),
        Err(RecoveryFailure::Authentication)
    );
    let link = export.path.join("alias.age");
    symlink(&path, &link)?;
    assert_eq!(session.read(&link), Err(RecoveryFailure::Storage));
    Ok(())
}

#[test]
fn interactive_passphrase_bundle_roundtrips_and_rejects_wrong_secret_and_work_factor()
-> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let custody = BootstrapKeyCustody::initialize(&root.path)?;
    let instance = InstanceId::new([0x31; 16])?;
    let protected = custody.protect_instance_integrity_key(instance, &[0x21; 32])?;
    let pin = RecoveryIdentity::new(
        instance,
        custody.identity(),
        custody.integrity_identity(&[0x21; 32])?,
    )?;
    let passphrase =
        RecoveryPassphrase::from_interactive("recovery test fixture passphrase".to_owned())?;
    let wrong =
        RecoveryPassphrase::from_interactive("different recovery fixture phrase".to_owned())?;
    let authority = authority()?;
    let session = RecoverySession::admit(&authority, RecoveryProtection::Passphrase)?;
    let bundle = session.create_passphrase(&custody, pin, &protected, &passphrase, 789)?;
    let inspected = session.verify(
        &custody,
        &bundle,
        RecoveryUnlock::Passphrase(&passphrase),
        pin,
    )?;
    assert_eq!(inspected.recipients(), &["scrypt"]);
    assert_eq!(
        session.inspect(&bundle, RecoveryUnlock::Passphrase(&wrong), pin),
        Err(RecoveryFailure::Authentication)
    );
    let mut excessive = bundle.clone();
    let header = excessive
        .windows(4)
        .position(|window| window == b" 18\n")
        .ok_or("missing native scrypt work factor")?;
    let digit = excessive
        .get_mut(header + 2)
        .ok_or("missing work factor digit")?;
    *digit = b'9';
    assert_eq!(
        session.inspect(&excessive, RecoveryUnlock::Passphrase(&passphrase), pin),
        Err(RecoveryFailure::Authentication)
    );
    assert!(RecoveryPassphrase::from_interactive("short".to_owned()).is_err());
    assert!(RecoveryPassphrase::from_interactive("x".repeat(1025)).is_err());
    Ok(())
}

#[test]
fn published_age_v1_x25519_and_scrypt_known_answers_match_on_this_target()
-> Result<(), Box<dyn std::error::Error>> {
    use super::backend::{
        CryptoBackend, RecoveryCryptoPurpose, RecoveryDecryption, RustCryptoBackend,
    };
    for (cipher, metadata) in [
        (
            &include_bytes!("../../tests/testdata/recovery-age-v1/x25519.age")[..],
            include_str!("../../tests/testdata/recovery-age-v1/x25519.txt"),
        ),
        (
            &include_bytes!("../../tests/testdata/recovery-age-v1/scrypt.age")[..],
            include_str!("../../tests/testdata/recovery-age-v1/scrypt.txt"),
        ),
    ] {
        let field = |name: &str| metadata.lines().find_map(|line| line.strip_prefix(name));
        let plaintext = if let Some(phrase) = field("passphrase: ") {
            RustCryptoBackend.open_recovery(
                RecoveryCryptoPurpose::LocalRootPayloadV1,
                RecoveryDecryption::Passphrase(&mut || {
                    Ok(age::secrecy::SecretString::from(phrase.to_owned()))
                }),
                cipher,
            )
        } else {
            let identity: age::x25519::Identity = field("identity: ")
                .ok_or("missing public fixture credential")?
                .parse()
                .map_err(|_| "invalid public fixture credential")?;
            RustCryptoBackend.open_recovery(
                RecoveryCryptoPurpose::LocalRootPayloadV1,
                RecoveryDecryption::Identity(&identity),
                cipher,
            )
        }
        .map_err(|_| "published recovery vector failed")?;
        let digest = RustCryptoBackend
            .sha256(&plaintext)
            .map_err(|_| "fixture digest unavailable")?
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(Some(digest.as_str()), field("payload: "));
    }
    Ok(())
}
