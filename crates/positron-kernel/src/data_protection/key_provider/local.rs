use super::*;
use crate::data_protection::{
    BootstrapKeyCustody, CryptoBackend, RustCryptoBackend, SecretKeyBytes,
};

/// The real protected local-file adapter, using existing verified root custody.
pub struct LocalKeyProvider {
    root: SecretKeyBytes,
    identity: ProviderKeyUri,
}
impl LocalKeyProvider {
    pub(in crate::data_protection) fn root(&self) -> &SecretKeyBytes {
        &self.root
    }

    /// Creates a new context-bound KEK envelope without returning plaintext key material.
    pub async fn create_envelope(
        &self,
        context: EnvelopeContext,
    ) -> Result<KeyEnvelope, KeyProviderFailure> {
        let session = KeyProviderSession::new(self);
        session.verify_live(context).await?;
        session.wrap(SecretKek::generate()?, context).await
    }
    /// Startup/restore verification returns only authenticated success or failure.
    pub async fn verify_envelope(
        &self,
        envelope: &KeyEnvelope,
        context: EnvelopeContext,
    ) -> Result<(), KeyProviderFailure> {
        let session = KeyProviderSession::new(self);
        session.verify_live(context).await?;
        session.verify(envelope, context).await
    }
    pub fn from_custody(custody: BootstrapKeyCustody) -> Result<Self, KeyProviderFailure> {
        let identity = Self::identity_for_custody(
            &custody,
            custody
                .active_root_epoch()
                .map_err(|_| KeyProviderFailure::Unavailable)?,
        )?;
        Ok(Self {
            identity,
            root: custody.into_provider_root()?,
        })
    }
    pub(crate) fn wrap_for_epoch(
        custody: &BootstrapKeyCustody,
        epoch: u64,
        payload: SecretWrappedKeyPayload,
        context: EnvelopeContext,
    ) -> Result<KeyEnvelope, KeyProviderFailure> {
        let identity = Self::identity_for_custody(custody, epoch)?;
        let ciphertext = custody.provider_wrap(payload.as_provider_plaintext())?;
        KeyEnvelope::from_provider_response(
            identity,
            context,
            WrappingAlgorithm::Aes256Kwp,
            ciphertext,
        )
    }
    pub(crate) fn identity_for_custody(
        custody: &BootstrapKeyCustody,
        epoch: u64,
    ) -> Result<ProviderKeyUri, KeyProviderFailure> {
        if epoch == 0 {
            return Err(KeyProviderFailure::InvalidConfiguration);
        }
        let active = custody
            .active_root_identity()
            .map_err(|_| KeyProviderFailure::Unavailable)?;
        let mut locator = String::from("local-root/");
        for byte in active.key_id() {
            use std::fmt::Write;
            write!(&mut locator, "{byte:02x}")
                .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
        }
        // Fingerprint pins key bytes even if an operator substitutes a file with the same ID.
        let mut version = String::new();
        for byte in active.fingerprint() {
            use std::fmt::Write;
            write!(&mut version, "{byte:02x}")
                .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
        }
        if epoch != 1 {
            use std::fmt::Write;
            write!(&mut version, ".{epoch}")
                .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
        }
        ProviderKeyUri::new(ProviderFamily::LocalFile, &locator, &version)
    }
}
impl KeyProvider for LocalKeyProvider {
    fn credential_model(&self) -> &ProviderCredentialModel {
        &ProviderCredentialModel::LocalFile
    }
    fn identity(&self) -> &ProviderKeyUri {
        &self.identity
    }
    async fn probe(
        &self,
        _context: EnvelopeContext,
    ) -> Result<ProviderCapabilities, KeyProviderFailure> {
        Ok(ProviderCapabilities {
            interface_version: 1,
            identity: self.identity.clone(),
            verified_tls: false,
            can_wrap: true,
            can_unwrap: true,
        })
    }
    async fn wrap(
        &self,
        payload: SecretWrappedKeyPayload,
        context: EnvelopeContext,
    ) -> Result<KeyEnvelope, KeyProviderFailure> {
        let ciphertext = RustCryptoBackend
            .wrap_key_aes_256_kwp(&self.root, payload.as_provider_plaintext())
            .map_err(|_| KeyProviderFailure::ContextMismatch)?;
        KeyEnvelope::from_provider_response(
            self.identity.clone(),
            context,
            WrappingAlgorithm::Aes256Kwp,
            ciphertext,
        )
    }
    async fn unwrap(
        &self,
        envelope: &KeyEnvelope,
        context: EnvelopeContext,
    ) -> Result<SecretWrappedKeyPayload, KeyProviderFailure> {
        envelope.check(&self.identity, context)?;
        RustCryptoBackend
            .unwrap_key_aes_256_kwp(&self.root, envelope.ciphertext())
            .map(SecretWrappedKeyPayload)
            .map_err(|_| KeyProviderFailure::ContextMismatch)
    }
}
