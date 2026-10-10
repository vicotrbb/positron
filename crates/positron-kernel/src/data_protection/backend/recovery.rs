//! Release recovery cryptography: signed payload v1 inside native age v1.
use super::CryptoBackendFailure;
use age::secrecy::SecretString;
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use std::io::{Read, Write};
use zeroize::Zeroizing;

pub(in crate::data_protection) enum RecoveryCryptoPurpose {
    LocalRootPayloadV1,
}
pub(in crate::data_protection) enum RecoveryEncryption<'a> {
    Recipients(&'a [String]),
    Passphrase(&'a SecretString),
}
pub(in crate::data_protection) enum RecoveryDecryption<'a> {
    Identity(&'a age::x25519::Identity),
    Passphrase(&'a mut dyn FnMut() -> Result<SecretString, CryptoBackendFailure>),
}
const MAX_PAYLOAD: usize = 4096;
const MAX_BUNDLE: usize = 8192;
const WORK_FACTOR: u8 = 18;
fn message(purpose: RecoveryCryptoPurpose, payload: &[u8]) -> Zeroizing<Vec<u8>> {
    let domain = match purpose {
        RecoveryCryptoPurpose::LocalRootPayloadV1 => b"positron-local-root-recovery-payload-v1\0",
    };
    let mut message = Zeroizing::new(Vec::with_capacity(domain.len() + payload.len()));
    message.extend_from_slice(domain);
    message.extend_from_slice(payload);
    message
}
pub(super) fn sign(
    purpose: RecoveryCryptoPurpose,
    seed: &[u8; 32],
    payload: &[u8],
) -> Result<[u8; 64], CryptoBackendFailure> {
    if payload.len() > MAX_PAYLOAD {
        return Err(CryptoBackendFailure::RecoveryLimitExceeded);
    }
    let pair = Ed25519KeyPair::from_seed_unchecked(seed)
        .map_err(|_| CryptoBackendFailure::SignatureFailed)?;
    pair.sign(&message(purpose, payload))
        .as_ref()
        .try_into()
        .map_err(|_| CryptoBackendFailure::SignatureFailed)
}
pub(super) fn verify(
    purpose: RecoveryCryptoPurpose,
    public_key: [u8; 32],
    payload: &[u8],
    signature: &[u8],
) -> Result<(), CryptoBackendFailure> {
    if payload.len() > MAX_PAYLOAD || signature.len() != 64 {
        return Err(CryptoBackendFailure::AuthenticationFailed);
    }
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&message(purpose, payload), signature)
        .map_err(|_| CryptoBackendFailure::AuthenticationFailed)
}
pub(super) fn seal(
    _purpose: RecoveryCryptoPurpose,
    protection: RecoveryEncryption<'_>,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoBackendFailure> {
    if plaintext.len() > MAX_PAYLOAD {
        return Err(CryptoBackendFailure::RecoveryLimitExceeded);
    }
    let encryptor = match protection {
        RecoveryEncryption::Recipients(values) => {
            if values.is_empty() || values.len() > 16 {
                return Err(CryptoBackendFailure::InvalidKey);
            }
            let recipients = values
                .iter()
                .map(|v| {
                    v.parse::<age::x25519::Recipient>()
                        .map_err(|_| CryptoBackendFailure::InvalidKey)
                })
                .collect::<Result<Vec<_>, _>>()?;
            age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
        },
        RecoveryEncryption::Passphrase(passphrase) => {
            let mut recipient = age::scrypt::Recipient::new(passphrase.clone());
            recipient.set_work_factor(WORK_FACTOR);
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
        },
    }
    .map_err(|_| CryptoBackendFailure::SealFailed)?;
    let mut ciphertext = Vec::with_capacity(MAX_BUNDLE);
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|_| CryptoBackendFailure::SealFailed)?;
    writer
        .write_all(plaintext)
        .map_err(|_| CryptoBackendFailure::SealFailed)?;
    writer
        .finish()
        .map_err(|_| CryptoBackendFailure::SealFailed)?;
    if ciphertext.len() > MAX_BUNDLE {
        return Err(CryptoBackendFailure::RecoveryLimitExceeded);
    }
    Ok(ciphertext)
}
pub(super) fn open(
    _purpose: RecoveryCryptoPurpose,
    unlock: RecoveryDecryption<'_>,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoBackendFailure> {
    if ciphertext.is_empty() || ciphertext.len() > MAX_BUNDLE {
        return Err(CryptoBackendFailure::RecoveryLimitExceeded);
    }
    let decryptor =
        age::Decryptor::new(ciphertext).map_err(|_| CryptoBackendFailure::AuthenticationFailed)?;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(MAX_PAYLOAD + 1));
    match unlock {
        RecoveryDecryption::Identity(identity) if !decryptor.is_scrypt() => {
            decryptor
                .decrypt(std::iter::once(identity as &dyn age::Identity))
                .map_err(|_| CryptoBackendFailure::AuthenticationFailed)?
                .take((MAX_PAYLOAD + 1) as u64)
                .read_to_end(&mut plaintext)
                .map_err(|_| CryptoBackendFailure::AuthenticationFailed)?;
        },
        RecoveryDecryption::Passphrase(read) if decryptor.is_scrypt() => {
            let mut identity = age::scrypt::Identity::new(read()?);
            identity.set_max_work_factor(WORK_FACTOR);
            decryptor
                .decrypt(std::iter::once(&identity as &dyn age::Identity))
                .map_err(|_| CryptoBackendFailure::AuthenticationFailed)?
                .take((MAX_PAYLOAD + 1) as u64)
                .read_to_end(&mut plaintext)
                .map_err(|_| CryptoBackendFailure::AuthenticationFailed)?;
        },
        _ => return Err(CryptoBackendFailure::InvalidKey),
    }
    if plaintext.len() > MAX_PAYLOAD {
        return Err(CryptoBackendFailure::RecoveryLimitExceeded);
    }
    Ok(plaintext)
}
