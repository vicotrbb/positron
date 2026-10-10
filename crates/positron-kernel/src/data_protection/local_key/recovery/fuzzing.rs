//! Bounded mutation oracle for the production signed Protobuf recovery boundary.
use super::super::codec::{SecretRootKey, encode_file_v1, parse_file_v1};
use super::super::{LocalKeyCreationTime, LocalKeyId};
use super::*;

pub(crate) fn exercise(data: &[u8]) -> Result<(), RecoveryFailure> {
    if data.len() > 4096 {
        return Ok(());
    }
    let encoded = encode_file_v1(
        LocalKeyId::new([0x81; 16]).map_err(|_| RecoveryFailure::InvalidInput)?,
        LocalKeyCreationTime::from_unix_seconds(42),
        SecretRootKey::from_owned(Box::new([0x82; 32])),
    )
    .map_err(|_| RecoveryFailure::Custody)?;
    let custody = BootstrapKeyCustody::from_verified(
        parse_file_v1(encoded).map_err(|_| RecoveryFailure::Custody)?,
    );
    let seed = Zeroizing::new([0x83; 32]);
    let pin = RecoveryIdentity::new(
        InstanceId::new([0x84; 16]).map_err(|_| RecoveryFailure::InvalidInput)?,
        custody.identity(),
        custody
            .integrity_identity(&seed)
            .map_err(|_| RecoveryFailure::Custody)?,
    )?;
    let metadata = RecoveryMetadata {
        payload_version: 1,
        identity: pin,
        created: 43,
        recipients: vec!["scrypt".to_owned()],
    };
    let (kind, commands) = data
        .split_first()
        .map_or((0, &[][..]), |(&kind, tail)| (kind, tail));
    let system = if kind % 8 >= 4 {
        Some(
            super::super::root_rewrap::wrap_system(&custody, pin.instance())
                .map_err(|_| RecoveryFailure::Authentication)?,
        )
    } else {
        None
    };
    let mut candidate = custody
        .with_root_key(|root| {
            encode_with_system(
                &metadata,
                root.expose_to_backend(),
                system
                    .as_deref()
                    .map(|envelope| (custody.bootstrap_identity(), 1, envelope)),
            )
        })
        .map_err(|_| RecoveryFailure::Custody)?;
    if kind % 4 == 3 {
        let identity: age::x25519::Identity =
            include_str!("../../../../tests/testdata/recovery-age-v1/x25519.txt")
                .lines()
                .find_map(|line| line.strip_prefix("identity: "))
                .ok_or(RecoveryFailure::InvalidInput)?
                .parse()
                .map_err(|_| RecoveryFailure::InvalidInput)?;
        drop(RustCryptoBackend.open_recovery(
            RecoveryCryptoPurpose::LocalRootPayloadV1,
            RecoveryDecryption::Identity(&identity),
            commands,
        ));
    } else if kind % 4 == 0 {
        if let Ok(payload) = verify_signed(commands, pin.integrity()) {
            drop(decode(payload, pin));
        }
    } else {
        for command in commands.chunks_exact(3) {
            let [high, low, value]: [u8; 3] = command
                .try_into()
                .map_err(|_| RecoveryFailure::InvalidInput)?;
            let offset = usize::from(u16::from_be_bytes([high, low]));
            if let Some(byte) = candidate.get_mut(offset) {
                *byte ^= value;
            }
        }
        if kind % 4 == 1 {
            drop(decode(&candidate, pin));
        } else {
            let envelope = signed(&candidate, &seed)?;
            let payload = verify_signed(&envelope, pin.integrity())?;
            drop(decode(payload, pin));
        }
    }
    Ok(())
}
