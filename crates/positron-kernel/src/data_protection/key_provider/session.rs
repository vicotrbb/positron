use super::*;
use subtle::ConstantTimeEq;

/// Verified provider operations; routing fields alone never establish authority.
pub struct KeyProviderSession<'provider, P> {
    pub(crate) provider: &'provider P,
    identity: ProviderKeyUri,
}
impl<'provider, P: KeyProvider> KeyProviderSession<'provider, P> {
    pub fn new(provider: &'provider P) -> Self {
        Self {
            provider,
            identity: provider.identity().clone(),
        }
    }
    pub async fn verify_live(&self, context: EnvelopeContext) -> Result<(), KeyProviderFailure> {
        self.check_capabilities(context).await?;
        let key = SecretKek::generate()?;
        let payload = SecretWrappedKeyPayload::encode(&key, context, &self.identity)?;
        let envelope = self.provider.wrap(payload, context).await?;
        let recovered = self.unwrap(&envelope, context).await?;
        if key
            .0
            .expose_to_backend()
            .ct_eq(recovered.0.expose_to_backend())
            .into()
        {
            Ok(())
        } else {
            Err(KeyProviderFailure::WrongKey)
        }
    }
    async fn check_capabilities(&self, context: EnvelopeContext) -> Result<(), KeyProviderFailure> {
        self.provider
            .credential_model()
            .validate(self.identity.family)?;
        let capabilities = self.provider.probe(context).await?;
        if capabilities.identity != self.identity || self.provider.identity() != &self.identity {
            return Err(KeyProviderFailure::WrongKey);
        }
        if capabilities.interface_version != 1
            || !capabilities.can_wrap
            || !capabilities.can_unwrap
            || (self.identity.family != ProviderFamily::LocalFile && !capabilities.verified_tls)
        {
            return Err(KeyProviderFailure::PermissionDenied);
        }
        Ok(())
    }
    pub async fn wrap(
        &self,
        key: SecretKek,
        context: EnvelopeContext,
    ) -> Result<KeyEnvelope, KeyProviderFailure> {
        self.check_capabilities(context).await?;
        let payload = SecretWrappedKeyPayload::encode(&key, context, &self.identity)?;
        let envelope = self.provider.wrap(payload, context).await?;
        envelope.check(&self.identity, context)?;
        Ok(envelope)
    }
    pub async fn verify(
        &self,
        envelope: &KeyEnvelope,
        context: EnvelopeContext,
    ) -> Result<(), KeyProviderFailure> {
        self.unwrap(envelope, context).await.map(drop)
    }
    /// Produces a separately verified new envelope without altering the source.
    pub async fn rewrap<Q: KeyProvider>(
        &self,
        envelope: &KeyEnvelope,
        context: EnvelopeContext,
        destination: &KeyProviderSession<'_, Q>,
    ) -> Result<KeyEnvelope, KeyProviderFailure> {
        let key = self.unwrap(envelope, context).await?;
        destination.check_capabilities(context).await?;
        let payload = SecretWrappedKeyPayload::encode(&key, context, &destination.identity)?;
        let replacement = destination.provider.wrap(payload, context).await?;
        let recovered = destination.unwrap(&replacement, context).await?;
        if !bool::from(
            key.0
                .expose_to_backend()
                .ct_eq(recovered.0.expose_to_backend()),
        ) {
            return Err(KeyProviderFailure::WrongKey);
        }
        Ok(replacement)
    }
    pub(crate) async fn unwrap(
        &self,
        envelope: &KeyEnvelope,
        context: EnvelopeContext,
    ) -> Result<SecretKek, KeyProviderFailure> {
        if self.provider.identity() != &self.identity {
            return Err(KeyProviderFailure::WrongKey);
        }
        envelope.check(&self.identity, context)?;
        self.check_capabilities(context).await?;
        let payload = self.provider.unwrap(envelope, context).await?;
        payload.verify(context, &self.identity)
    }
}
