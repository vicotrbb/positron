mod recovery;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_kw::{KeyInit as KeyWrapInit, KwpAes256};
use hmac::{Hmac, Mac};
pub(super) use recovery::{RecoveryCryptoPurpose, RecoveryDecryption, RecoveryEncryption};
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use std::fmt::Formatter;

use super::{DataProtection, FrameFailure, FrameObjectContext};

#[cfg(test)]
use std::cell::Cell;
#[cfg(test)]
use std::rc::Rc;

pub(crate) struct SecretKeyBytes {
    bytes: Box<[u8; 32]>,
    #[cfg(test)]
    zeroized_before_release: Option<Rc<Cell<bool>>>,
}

impl SecretKeyBytes {
    pub(crate) fn from_owned(bytes: Box<[u8; 32]>) -> Self {
        Self {
            bytes,
            #[cfg(test)]
            zeroized_before_release: None,
        }
    }

    #[cfg(test)]
    pub(super) fn from_owned_with_observer(
        bytes: Box<[u8; 32]>,
        zeroized_before_release: Rc<Cell<bool>>,
    ) -> Self {
        Self {
            bytes,
            zeroized_before_release: Some(zeroized_before_release),
        }
    }

    pub(crate) fn expose_to_backend(&self) -> &[u8; 32] {
        self.bytes.as_ref()
    }

    pub(crate) fn expose_to_backend_mut(&mut self) -> &mut [u8; 32] {
        self.bytes.as_mut()
    }
}

impl Drop for SecretKeyBytes {
    fn drop(&mut self) {
        self.bytes.zeroize();
        #[cfg(test)]
        if let Some(observer) = &self.zeroized_before_release {
            observer.set(self.bytes.iter().all(|byte| *byte == 0));
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CryptoBackendFailure {
    InvalidKey,
    SealFailed,
    AuthenticationFailed,
    EntropyUnavailable,
    HashFailed,
    OpenFailed,
    WrapFailed,
    UnwrapFailed,
    SignatureFailed,
    RecoveryLimitExceeded,
}

pub(super) trait CryptoBackend {
    /// AWS protocol authentication uses the reviewed, pinned native signer.
    /// No AWS credential or authorization value is exposed to diagnostics.
    fn aws_kms_request_headers(
        &self,
        credentials: &aws_credential_types::Credentials,
        endpoint: &str,
        region: &str,
        target: &str,
        body: &[u8],
    ) -> Result<Vec<(&'static str, Zeroizing<String>)>, CryptoBackendFailure> {
        use aws_sigv4::http_request::{SignableBody, SignableRequest, SigningSettings, sign};
        let identity = credentials.clone().into();
        let parameters = aws_sigv4::sign::v4::SigningParams::builder()
            .identity(&identity)
            .region(region)
            .name("kms")
            .time(std::time::SystemTime::now())
            .settings(SigningSettings::default())
            .build()
            .map_err(|_| CryptoBackendFailure::SignatureFailed)?
            .into();
        use std::fmt::Write;
        let mut body_hash = String::with_capacity(64);
        for byte in self.sha256(body)? {
            write!(&mut body_hash, "{byte:02x}").map_err(|_| CryptoBackendFailure::HashFailed)?;
        }
        let request = SignableRequest::new(
            "POST",
            endpoint,
            [
                ("content-type", "application/x-amz-json-1.1"),
                ("x-amz-target", target),
            ]
            .into_iter(),
            SignableBody::Precomputed(body_hash),
        )
        .map_err(|_| CryptoBackendFailure::SignatureFailed)?;
        let (instructions, _) =
            tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
                sign(request, &parameters)
            })
            .map_err(|_| CryptoBackendFailure::SignatureFailed)?
            .into_parts();
        let (headers, query) = instructions.into_parts();
        if !query.is_empty() {
            return Err(CryptoBackendFailure::SignatureFailed);
        }
        Ok(headers
            .into_iter()
            .map(|header| (header.name(), Zeroizing::new(header.value().to_owned())))
            .collect())
    }
    fn sign_recovery(
        &self,
        purpose: RecoveryCryptoPurpose,
        seed: &[u8; 32],
        payload: &[u8],
    ) -> Result<[u8; 64], CryptoBackendFailure> {
        recovery::sign(purpose, seed, payload)
    }
    fn verify_recovery(
        &self,
        purpose: RecoveryCryptoPurpose,
        public_key: [u8; 32],
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoBackendFailure> {
        recovery::verify(purpose, public_key, payload, signature)
    }
    fn seal_recovery(
        &self,
        purpose: RecoveryCryptoPurpose,
        protection: RecoveryEncryption<'_>,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoBackendFailure> {
        recovery::seal(purpose, protection, plaintext)
    }
    fn open_recovery(
        &self,
        purpose: RecoveryCryptoPurpose,
        unlock: RecoveryDecryption<'_>,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoBackendFailure> {
        recovery::open(purpose, unlock, ciphertext)
    }

    fn seal_aes_256_gcm(
        &self,
        key: &SecretKeyBytes,
        nonce: [u8; 12],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoBackendFailure>;

    fn open_aes_256_gcm(
        &self,
        key: &SecretKeyBytes,
        nonce: [u8; 12],
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<SecretPlaintext, CryptoBackendFailure>;

    fn sha256(&self, bytes: &[u8]) -> Result<[u8; 32], CryptoBackendFailure>;

    fn begin_sha256(&self) -> Result<Sha256Digest, CryptoBackendFailure> {
        Err(CryptoBackendFailure::HashFailed)
    }

    fn fill_random(&self, destination: &mut [u8]) -> Result<(), CryptoBackendFailure>;

    fn hmac_sha256(
        &self,
        key: &SecretKeyBytes,
        bytes: &[u8],
    ) -> Result<[u8; 32], CryptoBackendFailure> {
        RustCryptoBackend.hmac_sha256(key, bytes)
    }

    fn verify_hmac_sha256(
        &self,
        key: &SecretKeyBytes,
        bytes: &[u8],
        expected: &[u8; 32],
    ) -> Result<(), CryptoBackendFailure> {
        RustCryptoBackend.verify_hmac_sha256(key, bytes, expected)
    }

    fn wrap_key_aes_256_kwp(
        &self,
        key: &SecretKeyBytes,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoBackendFailure> {
        RustCryptoBackend.wrap_key_aes_256_kwp(key, plaintext)
    }

    fn unwrap_key_aes_256_kwp(
        &self,
        key: &SecretKeyBytes,
        wrapped: &[u8],
    ) -> Result<SecretPlaintext, CryptoBackendFailure> {
        RustCryptoBackend.unwrap_key_aes_256_kwp(key, wrapped)
    }

    fn ed25519_public_key(
        &self,
        private_seed: &SecretKeyBytes,
    ) -> Result<[u8; 32], CryptoBackendFailure> {
        RustCryptoBackend.ed25519_public_key(private_seed)
    }
}

pub(super) struct RustCryptoBackend;

/// Fixed-size backend state; the pinned sha2 context zeroizes on drop.
pub(crate) struct Sha256Digest(Sha256);
impl Sha256Digest {
    pub(crate) fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
    pub(crate) fn finalize(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

impl CryptoBackend for RustCryptoBackend {
    fn begin_sha256(&self) -> Result<Sha256Digest, CryptoBackendFailure> {
        Ok(Sha256Digest(Sha256::new()))
    }
    fn seal_aes_256_gcm(
        &self,
        key: &SecretKeyBytes,
        nonce: [u8; 12],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoBackendFailure> {
        let cipher = Aes256Gcm::new_from_slice(key.expose_to_backend())
            .map_err(|_| CryptoBackendFailure::InvalidKey)?;
        cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoBackendFailure::SealFailed)
    }

    fn sha256(&self, bytes: &[u8]) -> Result<[u8; 32], CryptoBackendFailure> {
        // The pinned sha2 `zeroize` feature makes the concrete SHA-256
        // context zeroize its internal state, length, and private block-buffer
        // bytes and position on drop. This does not make a claim about caller
        // input custody or copies outside that reviewed context.
        Ok(Sha256::digest(bytes).into())
    }

    fn open_aes_256_gcm(
        &self,
        key: &SecretKeyBytes,
        nonce: [u8; 12],
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<SecretPlaintext, CryptoBackendFailure> {
        let cipher = Aes256Gcm::new_from_slice(key.expose_to_backend())
            .map_err(|_| CryptoBackendFailure::InvalidKey)?;
        cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: associated_data,
                },
            )
            .map(SecretPlaintext::new)
            .map_err(|_| CryptoBackendFailure::AuthenticationFailed)
    }

    fn fill_random(&self, destination: &mut [u8]) -> Result<(), CryptoBackendFailure> {
        getrandom::fill(destination).map_err(|_| CryptoBackendFailure::EntropyUnavailable)
    }

    fn hmac_sha256(
        &self,
        key: &SecretKeyBytes,
        bytes: &[u8],
    ) -> Result<[u8; 32], CryptoBackendFailure> {
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key.expose_to_backend())
            .map_err(|_| CryptoBackendFailure::InvalidKey)?;
        mac.update(bytes);
        Ok(mac.finalize().into_bytes().into())
    }

    fn verify_hmac_sha256(
        &self,
        key: &SecretKeyBytes,
        bytes: &[u8],
        expected: &[u8; 32],
    ) -> Result<(), CryptoBackendFailure> {
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key.expose_to_backend())
            .map_err(|_| CryptoBackendFailure::InvalidKey)?;
        mac.update(bytes);
        mac.verify_slice(expected)
            .map_err(|_| CryptoBackendFailure::AuthenticationFailed)
    }

    fn wrap_key_aes_256_kwp(
        &self,
        key: &SecretKeyBytes,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoBackendFailure> {
        aes_kwp_wrap(key, plaintext)
    }

    fn unwrap_key_aes_256_kwp(
        &self,
        key: &SecretKeyBytes,
        wrapped: &[u8],
    ) -> Result<SecretPlaintext, CryptoBackendFailure> {
        aes_kwp_unwrap(key, wrapped)
    }

    fn ed25519_public_key(
        &self,
        private_seed: &SecretKeyBytes,
    ) -> Result<[u8; 32], CryptoBackendFailure> {
        Ed25519KeyPair::from_seed_unchecked(private_seed.expose_to_backend())
            .map_err(|_| CryptoBackendFailure::SignatureFailed)?
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| CryptoBackendFailure::SignatureFailed)
    }
}

const MAX_KWP_PLAINTEXT_BYTES: usize = 4_096;

fn aes_kwp_wrap(
    wrapping_key: &SecretKeyBytes,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoBackendFailure> {
    if plaintext.is_empty() || plaintext.len() > MAX_KWP_PLAINTEXT_BYTES {
        return Err(CryptoBackendFailure::WrapFailed);
    }
    let wrapped_bytes = plaintext
        .len()
        .div_ceil(aes_kw::IV_LEN)
        .checked_add(1)
        .and_then(|blocks| blocks.checked_mul(aes_kw::IV_LEN))
        .ok_or(CryptoBackendFailure::WrapFailed)?;
    let wrapper = KwpAes256::new_from_slice(wrapping_key.expose_to_backend())
        .map_err(|_| CryptoBackendFailure::InvalidKey)?;
    let mut wrapped = vec![0_u8; wrapped_bytes];
    wrapper
        .wrap_key(plaintext, &mut wrapped)
        .map_err(|_| CryptoBackendFailure::WrapFailed)?;
    Ok(wrapped)
}

fn aes_kwp_unwrap(
    wrapping_key: &SecretKeyBytes,
    wrapped: &[u8],
) -> Result<SecretPlaintext, CryptoBackendFailure> {
    if wrapped.len() < 16
        || !wrapped.len().is_multiple_of(8)
        || wrapped.len() > MAX_KWP_PLAINTEXT_BYTES + 8
    {
        return Err(CryptoBackendFailure::UnwrapFailed);
    }
    let wrapper = KwpAes256::new_from_slice(wrapping_key.expose_to_backend())
        .map_err(|_| CryptoBackendFailure::InvalidKey)?;
    let plaintext_capacity = wrapped
        .len()
        .checked_sub(aes_kw::IV_LEN)
        .ok_or(CryptoBackendFailure::UnwrapFailed)?;
    let mut plaintext = Zeroizing::new(vec![0_u8; plaintext_capacity]);
    let plaintext_bytes = wrapper
        .unwrap_key(wrapped, &mut plaintext)
        .map_err(|_| CryptoBackendFailure::UnwrapFailed)?
        .len();
    plaintext.truncate(plaintext_bytes);
    Ok(SecretPlaintext::new(std::mem::take(&mut plaintext)))
}

/// An explicitly secret 256-bit input transferred into an object data key.
///
/// This type intentionally implements neither `Clone`, `Debug`, nor `Display`
/// and exposes no byte accessor. Its memory is zeroized when custody ends.
pub(crate) struct SecretKeyInput(pub(super) SecretKeyBytes);

impl SecretKeyInput {
    /// Takes ownership of exactly one AES-256 key buffer.
    ///
    /// Positron zeroizes this owned buffer before releasing it. This makes no
    /// claim about copies created before ownership transfer.
    #[must_use]
    pub(crate) fn from_owned(bytes: Box<[u8; 32]>) -> Self {
        Self(SecretKeyBytes::from_owned(bytes))
    }

    #[cfg(test)]
    pub(super) fn from_test_bytes(bytes: [u8; 32]) -> Self {
        Self::from_owned(Box::new(bytes))
    }

    #[cfg(test)]
    pub(super) fn from_owned_for_test(
        bytes: Box<[u8; 32]>,
        zeroized_before_release: Rc<Cell<bool>>,
    ) -> Self {
        Self(SecretKeyBytes::from_owned_with_observer(
            bytes,
            zeroized_before_release,
        ))
    }
}

/// A per-object data key bound to its authoritative identity and epochs.
pub(crate) struct ObjectDataKey {
    pub(super) key: SecretKeyBytes,
    pub(crate) object: FrameObjectContext,
}

impl ObjectDataKey {
    /// Imports an already recovered per-object data key without exposing it.
    #[must_use]
    pub fn import(input: SecretKeyInput, object: FrameObjectContext) -> Self {
        DataProtection::release().import_object_key(input, object)
    }

    /// Generates a fresh random per-object data key through the Crypto Backend.
    pub fn generate(object: FrameObjectContext) -> Result<Self, FrameFailure> {
        DataProtection::release().generate_object_key(object)
    }
}

impl std::fmt::Debug for ObjectDataKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ObjectDataKey { <redacted> }")
    }
}

pub(super) struct SecretPlaintext {
    pub(super) bytes: Vec<u8>,
    #[cfg(test)]
    zeroized_before_release: Option<Rc<Cell<bool>>>,
}

impl SecretPlaintext {
    pub(super) fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            #[cfg(test)]
            zeroized_before_release: None,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.bytes.len()
    }

    #[cfg(test)]
    pub(super) fn new_for_test(bytes: Vec<u8>, zeroized_before_release: Rc<Cell<bool>>) -> Self {
        Self {
            bytes,
            zeroized_before_release: Some(zeroized_before_release),
        }
    }
}

impl Drop for SecretPlaintext {
    fn drop(&mut self) {
        self.bytes.zeroize();
        #[cfg(test)]
        if let Some(observer) = &self.zeroized_before_release {
            observer.set(self.bytes.iter().all(|byte| *byte == 0));
        }
    }
}
