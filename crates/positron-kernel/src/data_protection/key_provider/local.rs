use super::*;
use crate::data_protection::BootstrapKeyCustody;

/// The real protected local-file adapter, using existing verified root custody.
pub struct LocalKeyProvider {
    custody: BootstrapKeyCustody,
    identity: ProviderKeyUri,
}
impl LocalKeyProvider {
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
        let mut locator = String::from("local-root/");
        for byte in custody.identity().key_id() {
            use std::fmt::Write;
            write!(&mut locator, "{byte:02x}")
                .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
        }
        // Fingerprint pins key bytes even if an operator substitutes a file with the same ID.
        let mut version = String::new();
        for byte in custody.identity().fingerprint() {
            use std::fmt::Write;
            write!(&mut version, "{byte:02x}")
                .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
        }
        Ok(Self {
            identity: ProviderKeyUri::new(ProviderFamily::LocalFile, &locator, &version)?,
            custody,
        })
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
        let ciphertext = self
            .custody
            .provider_wrap(payload.as_provider_plaintext())?;
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
        self.custody
            .provider_unwrap(envelope.ciphertext())
            .map(SecretWrappedKeyPayload)
    }
}
