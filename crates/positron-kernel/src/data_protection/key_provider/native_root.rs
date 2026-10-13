//! Admitted native I/O for the synchronous runtime's object-key admission seam.
use super::*;
use crate::{ResourceAmounts, ResourceDimension, ResourceReservation};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;
use zeroize::Zeroizing;
mod configuration;
mod worker;
pub use configuration::{NativeAzureAuthentication, NativeRootConfiguration};
mod custody;
pub(in crate::data_protection) use custody::CustodyKeyProvider;

/// Closed set of shipped native adapters. External root material never enters this owner.
pub enum NativeRootKey {
    Aws(AwsKmsKeyProvider),
    Google(GoogleCloudKmsKeyProvider),
    AzureKeyVault(AzureKeyVaultKeyProvider),
    AzureManagedHsm(AzureManagedHsmKeyProvider),
    Vault(VaultTransitKeyProvider),
    OpenBao(OpenBaoTransitKeyProvider),
    Kmip(Kmip21KeyProvider),
}
macro_rules! dispatch {
    ($value:expr, $provider:ident => $body:expr) => {
        match $value {
            NativeRootKey::Aws($provider) => $body,
            NativeRootKey::Google($provider) => $body,
            NativeRootKey::AzureKeyVault($provider) => $body,
            NativeRootKey::AzureManagedHsm($provider) => $body,
            NativeRootKey::Vault($provider) => $body,
            NativeRootKey::OpenBao($provider) => $body,
            NativeRootKey::Kmip($provider) => $body,
        }
    };
}
pub(super) use dispatch;
enum Operation {
    Probe(EnvelopeContext),
    Wrap(EnvelopeContext, Zeroizing<Vec<u8>>),
    Unwrap(EnvelopeContext, KeyEnvelope),
}
enum Response {
    Capabilities(ProviderCapabilities),
    Envelope(KeyEnvelope),
    Payload(Zeroizing<Vec<u8>>),
}
struct Request {
    operation: Operation,
    response: ResponseChannel,
}
enum ResponseChannel {
    Blocking(mpsc::SyncSender<Result<Response, KeyProviderFailure>>),
    Async(tokio::sync::oneshot::Sender<Result<Response, KeyProviderFailure>>),
}
struct Worker {
    requests: Option<mpsc::SyncSender<Request>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Worker {
    fn drop(&mut self) {
        drop(self.requests.take());
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            tracing::error!("native key provider worker failed during shutdown");
        }
    }
}
/// Synchronous dispatch retains the existing verified session and KEK cache authority.
/// Callers release Catalog/custody locks before waiting for provider I/O.
#[derive(Clone)]
pub struct NativeRootProvider {
    identity: ProviderKeyUri,
    credentials: ProviderCredentialModel,
    worker: Arc<Mutex<Worker>>,
}
impl NativeRootProvider {
    pub const fn required_resources() -> ResourceAmounts {
        ResourceAmounts::new([2_097_152, 1, 1, 0, 1, 0, 0, 1, 1, 4, 0])
    }
    pub fn new(
        key: NativeRootKey,
        reservation: ResourceReservation<'_>,
    ) -> Result<Self, KeyProviderFailure> {
        if !reservation.is_active()
            || ResourceDimension::ALL.iter().any(|dimension| {
                reservation.granted().get(*dimension) < Self::required_resources().get(*dimension)
            })
        {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        let identity = dispatch!(&key, provider => provider.identity().clone());
        let credentials = dispatch!(&key, provider => provider.credential_model().clone());
        let worker = worker::start(key, reservation.transfer())?;
        Ok(Self {
            identity,
            credentials,
            worker: Arc::new(Mutex::new(worker)),
        })
    }
    pub fn kmip(
        key: Kmip21KeyProvider,
        reservation: ResourceReservation<'_>,
    ) -> Result<Self, KeyProviderFailure> {
        Self::new(NativeRootKey::Kmip(key), reservation)
    }
    fn call(&self, operation: Operation) -> Result<Response, KeyProviderFailure> {
        let (response, result) = mpsc::sync_channel(1);
        {
            let worker = self
                .worker
                .lock()
                .map_err(|_| KeyProviderFailure::Unavailable)?;
            worker
                .requests
                .as_ref()
                .ok_or(KeyProviderFailure::Unavailable)?
                .try_send(Request {
                    operation,
                    response: ResponseChannel::Blocking(response),
                })
                .map_err(|failure| match failure {
                    mpsc::TrySendError::Full(_) => KeyProviderFailure::LimitExceeded,
                    mpsc::TrySendError::Disconnected(_) => KeyProviderFailure::Unavailable,
                })?;
        }
        result
            .recv_timeout(Duration::from_secs(20))
            .map_err(|_| KeyProviderFailure::Unavailable)?
    }
    async fn call_async(&self, operation: Operation) -> Result<Response, KeyProviderFailure> {
        let (response, result) = tokio::sync::oneshot::channel();
        {
            let worker = self
                .worker
                .lock()
                .map_err(|_| KeyProviderFailure::Unavailable)?;
            worker
                .requests
                .as_ref()
                .ok_or(KeyProviderFailure::Unavailable)?
                .try_send(Request {
                    operation,
                    response: ResponseChannel::Async(response),
                })
                .map_err(|failure| match failure {
                    mpsc::TrySendError::Full(_) => KeyProviderFailure::LimitExceeded,
                    mpsc::TrySendError::Disconnected(_) => KeyProviderFailure::Unavailable,
                })?;
        }
        result.await.map_err(|_| KeyProviderFailure::Unavailable)?
    }
    pub fn probe_blocking(
        &self,
        context: EnvelopeContext,
    ) -> Result<ProviderCapabilities, KeyProviderFailure> {
        match self.call(Operation::Probe(context))? {
            Response::Capabilities(capabilities) => Ok(capabilities),
            _ => Err(KeyProviderFailure::Unavailable),
        }
    }
}
impl KeyProvider for NativeRootProvider {
    fn identity(&self) -> &ProviderKeyUri {
        &self.identity
    }
    fn credential_model(&self) -> &ProviderCredentialModel {
        &self.credentials
    }
    async fn probe(
        &self,
        context: EnvelopeContext,
    ) -> Result<ProviderCapabilities, KeyProviderFailure> {
        match self.call_async(Operation::Probe(context)).await? {
            Response::Capabilities(capabilities) => Ok(capabilities),
            _ => Err(KeyProviderFailure::Unavailable),
        }
    }
    async fn wrap(
        &self,
        payload: SecretWrappedKeyPayload,
        context: EnvelopeContext,
    ) -> Result<KeyEnvelope, KeyProviderFailure> {
        match self
            .call_async(Operation::Wrap(
                context,
                Zeroizing::new(payload.as_provider_plaintext().to_vec()),
            ))
            .await?
        {
            Response::Envelope(envelope) => Ok(envelope),
            _ => Err(KeyProviderFailure::Unavailable),
        }
    }
    async fn unwrap(
        &self,
        envelope: &KeyEnvelope,
        context: EnvelopeContext,
    ) -> Result<SecretWrappedKeyPayload, KeyProviderFailure> {
        match self
            .call_async(Operation::Unwrap(context, envelope.clone()))
            .await?
        {
            Response::Payload(mut payload) => {
                SecretWrappedKeyPayload::from_provider_plaintext(std::mem::take(&mut *payload))
            },
            _ => Err(KeyProviderFailure::Unavailable),
        }
    }
}
