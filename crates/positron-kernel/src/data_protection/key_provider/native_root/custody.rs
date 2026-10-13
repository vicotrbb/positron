//! Closed local/native dispatch used only by the runtime's synchronous custody seam.
use super::*;
pub(in crate::data_protection) enum CustodyKeyProvider {
    Local(LocalKeyProvider),
    Native(NativeRootProvider),
}
impl CustodyKeyProvider {
    // This closed dispatch completes synchronously: native I/O is driven by
    // its retained worker runtime, and local operations have no pending I/O.
    pub(in crate::data_protection) fn verified_unwrap_blocking(
        &self,
        envelope: &KeyEnvelope,
        context: EnvelopeContext,
    ) -> Result<SecretKek, KeyProviderFailure> {
        let session = KeyProviderSession::new(self);
        complete(std::pin::pin!(session.unwrap(envelope, context)))
    }
    pub(in crate::data_protection) fn verified_wrap_blocking(
        &self,
        key: SecretKek,
        context: EnvelopeContext,
    ) -> Result<KeyEnvelope, KeyProviderFailure> {
        let session = KeyProviderSession::new(self);
        complete(std::pin::pin!(session.wrap(key, context)))
    }
    pub(in crate::data_protection) fn local_root(
        &self,
    ) -> Result<&crate::data_protection::SecretKeyBytes, KeyProviderFailure> {
        match self {
            Self::Local(provider) => Ok(provider.root()),
            Self::Native(_) => Err(KeyProviderFailure::InvalidConfiguration),
        }
    }
}
impl KeyProvider for CustodyKeyProvider {
    fn identity(&self) -> &ProviderKeyUri {
        match self {
            Self::Local(provider) => provider.identity(),
            Self::Native(provider) => provider.identity(),
        }
    }
    fn credential_model(&self) -> &ProviderCredentialModel {
        match self {
            Self::Local(provider) => provider.credential_model(),
            Self::Native(provider) => provider.credential_model(),
        }
    }
    async fn probe(
        &self,
        context: EnvelopeContext,
    ) -> Result<ProviderCapabilities, KeyProviderFailure> {
        match self {
            Self::Local(provider) => provider.probe(context).await,
            Self::Native(provider) => provider.probe_blocking(context),
        }
    }
    async fn wrap(
        &self,
        payload: SecretWrappedKeyPayload,
        context: EnvelopeContext,
    ) -> Result<KeyEnvelope, KeyProviderFailure> {
        match self {
            Self::Local(provider) => provider.wrap(payload, context).await,
            Self::Native(provider) => match provider.call(Operation::Wrap(
                context,
                Zeroizing::new(payload.as_provider_plaintext().to_vec()),
            ))? {
                Response::Envelope(envelope) => Ok(envelope),
                _ => Err(KeyProviderFailure::Unavailable),
            },
        }
    }
    async fn unwrap(
        &self,
        envelope: &KeyEnvelope,
        context: EnvelopeContext,
    ) -> Result<SecretWrappedKeyPayload, KeyProviderFailure> {
        match self {
            Self::Local(provider) => provider.unwrap(envelope, context).await,
            Self::Native(provider) => match provider
                .call(Operation::Unwrap(context, envelope.clone()))?
            {
                Response::Payload(mut payload) => {
                    SecretWrappedKeyPayload::from_provider_plaintext(std::mem::take(&mut *payload))
                },
                _ => Err(KeyProviderFailure::Unavailable),
            },
        }
    }
}

fn complete<T>(
    mut operation: std::pin::Pin<
        &mut impl std::future::Future<Output = Result<T, KeyProviderFailure>>,
    >,
) -> Result<T, KeyProviderFailure> {
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match operation.as_mut().poll(&mut context) {
        std::task::Poll::Ready(outcome) => outcome,
        std::task::Poll::Pending => Err(KeyProviderFailure::Unavailable),
    }
}
