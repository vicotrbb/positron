//! OpenBao 2.7.1 Transit v1, independently pinned to a5db72ce.
use super::*;
use crate::{ResourceAmounts, ResourceReservation};

/// Native OpenBao target with verified TLS and renewable machine credentials.
/// Shared Transit operations are verified against the pinned OpenBao sources;
/// Vault conformance does not establish OpenBao conformance.
pub struct OpenBaoTransitKeyProvider(pub(super) VaultTransitKeyProvider);

impl OpenBaoTransitKeyProvider {
    #[must_use]
    pub fn identity(&self) -> &ProviderKeyUri {
        self.0.identity()
    }
    #[must_use]
    pub const fn required_resources() -> ResourceAmounts {
        VaultTransitKeyProvider::required_resources()
    }
    /// Consumes admission before credential or CA reads. Auth mount is empty
    /// for a protected token file and explicit for Kubernetes/JWT login.
    pub fn from_native(
        identity: ProviderKeyUri,
        authentication: TransitAuthentication,
        authentication_mount: &str,
        trust_roots: Option<&CredentialFileReference>,
        reservation: ResourceReservation<'_>,
    ) -> Result<Self, KeyProviderFailure> {
        VaultTransitKeyProvider::from_native_target(
            identity,
            authentication,
            authentication_mount,
            trust_roots,
            reservation,
            ProviderFamily::OpenBaoTransit,
        )
        .map(Self)
    }
    pub async fn create_envelope(
        &self,
        context: EnvelopeContext,
    ) -> Result<KeyEnvelope, KeyProviderFailure> {
        KeyProviderSession::new(self)
            .wrap(SecretKek::generate()?, context)
            .await
    }
    pub async fn verify_envelope(
        &self,
        envelope: &KeyEnvelope,
        context: EnvelopeContext,
    ) -> Result<(), KeyProviderFailure> {
        KeyProviderSession::new(self)
            .verify(envelope, context)
            .await
    }
}
impl KeyProvider for OpenBaoTransitKeyProvider {
    fn identity(&self) -> &ProviderKeyUri {
        self.identity()
    }
    fn credential_model(&self) -> &ProviderCredentialModel {
        self.0.credential_model()
    }
    async fn probe(
        &self,
        context: EnvelopeContext,
    ) -> Result<ProviderCapabilities, KeyProviderFailure> {
        self.0.probe(context).await
    }
    async fn wrap(
        &self,
        payload: SecretWrappedKeyPayload,
        context: EnvelopeContext,
    ) -> Result<KeyEnvelope, KeyProviderFailure> {
        self.0.wrap(payload, context).await
    }
    async fn unwrap(
        &self,
        envelope: &KeyEnvelope,
        context: EnvelopeContext,
    ) -> Result<SecretWrappedKeyPayload, KeyProviderFailure> {
        self.0.unwrap(envelope, context).await
    }
}
