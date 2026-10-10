use super::{KeyProviderFailure, ProviderFamily, ProviderKeyUri};
use crate::data_protection::{DataProtection, SecretKeyBytes, SecretPlaintext};
use positron_domain::identity::TenantId;
use subtle::ConstantTimeEq;

/// Only root-wrapped KEKs enter the provider port; segment DEKs stay local.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyScope {
    System,
    Tenant(TenantId),
}

/// Authoritative identity supplied by Data Protection, never by envelope routing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvelopeContext {
    pub(crate) instance: [u8; 16],
    pub(crate) scope: KeyScope,
    pub(crate) key_id: [u8; 32],
    pub(crate) epoch: u64,
    pub(crate) format: u32,
}

impl EnvelopeContext {
    pub fn new(
        instance: [u8; 16],
        scope: KeyScope,
        key_id: [u8; 32],
        epoch: u64,
        format: u32,
    ) -> Result<Self, KeyProviderFailure> {
        if instance == [0; 16] || key_id == [0; 32] || epoch == 0 || format == 0 {
            return Err(KeyProviderFailure::InvalidConfiguration);
        }
        Ok(Self {
            instance,
            scope,
            key_id,
            epoch,
            format,
        })
    }
    pub(crate) fn encode(self, provider: &ProviderKeyUri) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(800);
        bytes.extend_from_slice(b"positron-provider-envelope-context-v1\0");
        bytes.extend_from_slice(&self.instance);
        match self.scope {
            KeyScope::System => bytes.extend_from_slice(&[0; 17]),
            KeyScope::Tenant(tenant) => {
                bytes.push(1);
                bytes.extend_from_slice(&tenant.to_bytes());
            },
        }
        bytes.extend_from_slice(&self.key_id);
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.format.to_be_bytes());
        // The purpose is fixed: root wrapping of system/Tenant KEKs.
        bytes.extend_from_slice(b"root-wrap-kek\0");
        bytes.push(provider.family as u8);
        bytes.extend_from_slice(&(provider.locator.len() as u16).to_be_bytes());
        bytes.extend_from_slice(provider.locator.as_bytes());
        bytes.extend_from_slice(&(provider.version.len() as u16).to_be_bytes());
        bytes.extend_from_slice(provider.version.as_bytes());
        bytes
    }
    pub fn digest(self, provider: &ProviderKeyUri) -> Result<[u8; 32], KeyProviderFailure> {
        DataProtection::hash(&self.encode(provider))
            .map_err(|_| KeyProviderFailure::ContextMismatch)
    }
}

/// Move-only zeroizing KEK. Application callers cannot read its bytes.
pub struct SecretKek(pub(crate) SecretKeyBytes);
impl SecretKek {
    #[must_use]
    pub fn from_owned(bytes: Box<[u8; 32]>) -> Self {
        Self(SecretKeyBytes::from_owned(bytes))
    }
    pub fn generate() -> Result<Self, KeyProviderFailure> {
        use crate::data_protection::{CryptoBackend, RustCryptoBackend};
        let mut key = Self::from_owned(Box::new([0; 32]));
        RustCryptoBackend
            .fill_random(key.0.expose_to_backend_mut())
            .map_err(|_| KeyProviderFailure::Unavailable)?;
        Ok(key)
    }
}

/// Temporary deterministic Protobuf plaintext, owned solely by SDK adapters.
/// It has no Clone, Debug or Display implementation and zeroizes on drop.
pub struct SecretWrappedKeyPayload(pub(in crate::data_protection) SecretPlaintext);
impl SecretWrappedKeyPayload {
    /// SDK-only byte view, required for native wrap/encrypt requests.
    #[must_use]
    pub(in crate::data_protection::key_provider) fn as_provider_plaintext(&self) -> &[u8] {
        &self.0.bytes
    }
    /// Transfers a bounded SDK response; the original buffer is zeroized on all paths.
    pub fn from_provider_plaintext(bytes: Vec<u8>) -> Result<Self, KeyProviderFailure> {
        let value = Self(SecretPlaintext::new(bytes));
        if value.0.len() > 1024 {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        Ok(value)
    }
    pub(crate) fn encode(
        key: &SecretKek,
        context: EnvelopeContext,
        provider: &ProviderKeyUri,
    ) -> Result<Self, KeyProviderFailure> {
        use crate::data_protection::key_envelope::{encode_bytes_field, encode_varint_field};
        let mut payload = SecretPlaintext::new(Vec::with_capacity(192));
        let bytes = &mut payload.bytes;
        encode_varint_field(1, 1, bytes);
        encode_bytes_field(2, key.0.expose_to_backend(), bytes);
        encode_bytes_field(3, &context.instance, bytes);
        encode_varint_field(
            4,
            match context.scope {
                KeyScope::System => 1,
                KeyScope::Tenant(_) => 2,
            },
            bytes,
        );
        encode_bytes_field(5, &context.key_id, bytes);
        encode_varint_field(6, context.epoch, bytes);
        encode_varint_field(
            7,
            match context.scope {
                KeyScope::System => 1,
                KeyScope::Tenant(_) => 2,
            },
            bytes,
        );
        encode_bytes_field(8, &context.digest(provider)?, bytes);
        if let KeyScope::Tenant(tenant) = context.scope {
            encode_bytes_field(9, &tenant.to_bytes(), bytes);
        }
        encode_varint_field(10, u64::from(context.format), bytes);
        Ok(Self(payload))
    }
    pub(crate) fn verify(
        self,
        context: EnvelopeContext,
        provider: &ProviderKeyUri,
    ) -> Result<SecretKek, KeyProviderFailure> {
        let mut key = SecretKek::from_owned(Box::new([0; 32]));
        key.0.expose_to_backend_mut().copy_from_slice(
            self.0
                .bytes
                .get(4..36)
                .ok_or(KeyProviderFailure::ContextMismatch)?,
        );
        let expected = Self::encode(&key, context, provider)?;
        if self.0.bytes.ct_eq(&expected.0.bytes).into() {
            Ok(key)
        } else {
            Err(KeyProviderFailure::ContextMismatch)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WrappingAlgorithm {
    Aes256Kwp,
    Aes256Gcm,
    RsaOaepSha256,
    AwsKmsSymmetricDefault,
    GoogleSymmetricEncryption,
}

/// Untrusted routing plus opaque ciphertext. Authority comes only from unwrap.
#[derive(Clone, Eq, PartialEq)]
pub struct KeyEnvelope {
    pub(crate) provider: ProviderKeyUri,
    pub(crate) context: EnvelopeContext,
    pub(crate) digest: [u8; 32],
    pub(crate) algorithm: WrappingAlgorithm,
    pub(crate) ciphertext: Vec<u8>,
}
impl std::fmt::Debug for KeyEnvelope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("KeyEnvelope { opaque ciphertext }")
    }
}
impl KeyEnvelope {
    pub fn from_provider_response(
        provider: ProviderKeyUri,
        context: EnvelopeContext,
        algorithm: WrappingAlgorithm,
        ciphertext: Vec<u8>,
    ) -> Result<Self, KeyProviderFailure> {
        if ciphertext.is_empty()
            || ciphertext.len() > 8192
            || (provider.family == ProviderFamily::LocalFile
                && algorithm != WrappingAlgorithm::Aes256Kwp)
        {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        let digest = context.digest(&provider)?;
        Ok(Self {
            provider,
            context,
            digest,
            algorithm,
            ciphertext,
        })
    }
    #[must_use]
    pub fn identity(&self) -> &ProviderKeyUri {
        &self.provider
    }
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    pub(crate) fn check(
        &self,
        provider: &ProviderKeyUri,
        context: EnvelopeContext,
    ) -> Result<(), KeyProviderFailure> {
        if &self.provider != provider {
            return Err(KeyProviderFailure::WrongKey);
        }
        if self.context != context || self.digest != context.digest(provider)? {
            return Err(KeyProviderFailure::ContextMismatch);
        }
        Ok(())
    }
}
