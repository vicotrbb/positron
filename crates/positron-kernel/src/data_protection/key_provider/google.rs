//! Google Cloud KMS v1, pinned pre-provisioned symmetric versions.
use super::*;
use crate::{ResourceAmounts, ResourceDimension, ResourceReservation};
use google_cloud_auth::{
    credentials::{CacheableResource, Credentials},
    native::Runtime,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tracing::instrument::WithSubscriber;
use zeroize::Zeroizing;
mod native;
mod protocol;
#[cfg(test)]
mod tests;

const DEADLINE: Duration = Duration::from_secs(15);

/// Google Cloud KMS v1 under immutable, pre-provisioned version custody.
pub struct GoogleCloudKmsKeyProvider {
    identity: ProviderKeyUri,
    credentials: Credentials,
    runtime: Arc<dyn Runtime>,
    active: AtomicBool,
}

impl GoogleCloudKmsKeyProvider {
    #[must_use]
    pub const fn required_resources() -> ResourceAmounts {
        ResourceAmounts::new([64 * 1024 * 1024, 16, 16, 0, 0, 1, 10, 16, 1, 16, 0])
    }

    pub async fn from_application_default(
        identity: ProviderKeyUri,
        reservation: ResourceReservation<'_>,
    ) -> Result<Self, KeyProviderFailure> {
        if identity.family() != ProviderFamily::GoogleCloudKms {
            return Err(KeyProviderFailure::InvalidConfiguration);
        }
        let required = Self::required_resources();
        if !reservation.is_active()
            || ResourceDimension::ALL
                .iter()
                .any(|dimension| reservation.granted().get(*dimension) < required.get(*dimension))
        {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        tokio::runtime::Handle::try_current()
            .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
        let runtime = native::NativeRuntime::new(reservation.transfer())?;
        let credentials =
            tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
                google_cloud_auth::credentials::Builder::default()
                    .with_native_runtime(runtime.clone())
                    .with_scopes(["https://www.googleapis.com/auth/cloudkms"])
                    .build()
            })
            .map_err(|error| {
                source_failure(&error).unwrap_or(KeyProviderFailure::InvalidConfiguration)
            })?;
        Ok(Self {
            identity,
            credentials,
            runtime,
            active: AtomicBool::new(false),
        })
    }
}

struct ActiveOperation<'a>(&'a AtomicBool);
impl Drop for ActiveOperation<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
fn native_failure(error: google_cloud_auth::native::Error) -> KeyProviderFailure {
    match error {
        google_cloud_auth::native::Error::LimitExceeded => KeyProviderFailure::LimitExceeded,
        google_cloud_auth::native::Error::PermissionDenied => KeyProviderFailure::PermissionDenied,
        google_cloud_auth::native::Error::InvalidConfiguration
        | google_cloud_auth::native::Error::NotFound => KeyProviderFailure::InvalidConfiguration,
        google_cloud_auth::native::Error::Unavailable => KeyProviderFailure::Unavailable,
    }
}
fn credential_failure(error: google_cloud_auth::errors::CredentialsError) -> KeyProviderFailure {
    source_failure(&error).unwrap_or_else(|| {
        if error.is_transient() {
            KeyProviderFailure::Unavailable
        } else {
            KeyProviderFailure::InvalidConfiguration
        }
    })
}
fn source_failure(error: &(dyn std::error::Error + 'static)) -> Option<KeyProviderFailure> {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = source {
        if let Some(native) = current.downcast_ref::<google_cloud_auth::native::Error>() {
            return Some(native_failure(*native));
        }
        source = current.source();
    }
    None
}
impl GoogleCloudKmsKeyProvider {
    fn begin(&self) -> Result<ActiveOperation<'_>, KeyProviderFailure> {
        self.active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| KeyProviderFailure::LimitExceeded)?;
        Ok(ActiveOperation(&self.active))
    }
    async fn request(
        &self,
        operation: protocol::Operation,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>, KeyProviderFailure> {
        tokio::runtime::Handle::try_current()
            .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
        let endpoint = operation.endpoint(&self.identity)?;
        let mut submitted = false;
        let request = async {
            let headers = self
                .credentials
                .headers(http::Extensions::new())
                .with_subscriber(tracing::subscriber::NoSubscriber::default())
                .await
                .map_err(credential_failure)?;
            let CacheableResource::New {
                data: mut headers, ..
            } = headers
            else {
                return Err(KeyProviderFailure::Unavailable);
            };
            headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            );
            let total = headers
                .iter()
                .try_fold(0usize, |sum, (name, value)| {
                    sum.checked_add(name.as_str().len())?
                        .checked_add(value.as_bytes().len())
                })
                .ok_or(KeyProviderFailure::LimitExceeded)?;
            if total > 131_072 {
                return Err(KeyProviderFailure::LimitExceeded);
            }
            for value in headers.values_mut() {
                value.set_sensitive(true);
            }
            for attempt in 0..2 {
                submitted = true;
                let reply = self
                    .runtime
                    .http(google_cloud_auth::native::Request {
                        method: if matches!(operation, protocol::Operation::Metadata) {
                            http::Method::GET
                        } else {
                            http::Method::POST
                        },
                        url: endpoint.clone(),
                        headers: headers.clone(),
                        body: Zeroizing::new(body.to_vec()),
                    })
                    .with_subscriber(tracing::subscriber::NoSubscriber::default())
                    .await
                    .map_err(|error| {
                        if error == google_cloud_auth::native::Error::Unavailable {
                            operation.transport_failure()
                        } else {
                            native_failure(error)
                        }
                    })?;
                if reply.status.is_success() {
                    return Ok(reply.body);
                }
                let failure = protocol::classify(operation, reply.status.as_u16(), &reply.body);
                if failure == KeyProviderFailure::Unavailable && attempt == 0 {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                } else {
                    return Err(failure);
                }
            }
            Err(KeyProviderFailure::Unavailable)
        };
        tokio::time::timeout(DEADLINE, request).await.map_err(|_| {
            if submitted {
                operation.transport_failure()
            } else {
                KeyProviderFailure::Unavailable
            }
        })?
    }
    pub async fn create_envelope(
        &self,
        context: EnvelopeContext,
    ) -> Result<KeyEnvelope, KeyProviderFailure> {
        let session = KeyProviderSession::new(self);
        session.verify_live(context).await?;
        session.wrap(SecretKek::generate()?, context).await
    }
    pub async fn verify_envelope(
        &self,
        envelope: &KeyEnvelope,
        context: EnvelopeContext,
    ) -> Result<(), KeyProviderFailure> {
        envelope.check(&self.identity, context)?;
        let session = KeyProviderSession::new(self);
        session.verify_live(context).await?;
        session.verify(envelope, context).await
    }
    pub async fn rewrap_envelope(
        &self,
        envelope: &KeyEnvelope,
        context: EnvelopeContext,
        destination: &Self,
    ) -> Result<KeyEnvelope, KeyProviderFailure> {
        KeyProviderSession::new(self)
            .rewrap(envelope, context, &KeyProviderSession::new(destination))
            .await
    }
}
impl KeyProvider for GoogleCloudKmsKeyProvider {
    fn identity(&self) -> &ProviderKeyUri {
        &self.identity
    }
    fn credential_model(&self) -> &ProviderCredentialModel {
        &ProviderCredentialModel::GoogleApplicationDefault
    }
    async fn probe(&self, _: EnvelopeContext) -> Result<ProviderCapabilities, KeyProviderFailure> {
        let _active = self.begin()?;
        let response = self
            .request(protocol::Operation::Metadata, Zeroizing::new(Vec::new()))
            .await?;
        protocol::verify_metadata(&response, &self.identity)?;
        Ok(ProviderCapabilities {
            interface_version: 1,
            identity: self.identity.clone(),
            verified_tls: true,
            can_wrap: true,
            can_unwrap: true,
        })
    }
    async fn wrap(
        &self,
        payload: SecretWrappedKeyPayload,
        context: EnvelopeContext,
    ) -> Result<KeyEnvelope, KeyProviderFailure> {
        let _active = self.begin()?;
        let verified = payload.verify(context, &self.identity)?;
        let payload = SecretWrappedKeyPayload::encode(&verified, context, &self.identity)?;
        let request =
            protocol::encrypt_request(&self.identity, context, payload.as_provider_plaintext())?;
        drop(payload);
        drop(verified);
        let response = self.request(protocol::Operation::Encrypt, request).await?;
        KeyEnvelope::from_provider_response(
            self.identity.clone(),
            context,
            WrappingAlgorithm::GoogleSymmetricEncryption,
            protocol::wrapped_response(&response, &self.identity)?,
        )
    }
    async fn unwrap(
        &self,
        envelope: &KeyEnvelope,
        context: EnvelopeContext,
    ) -> Result<SecretWrappedKeyPayload, KeyProviderFailure> {
        envelope.check(&self.identity, context)?;
        if envelope.algorithm != WrappingAlgorithm::GoogleSymmetricEncryption {
            return Err(KeyProviderFailure::ContextMismatch);
        }
        let _active = self.begin()?;
        let request = protocol::decrypt_request(&self.identity, context, envelope.ciphertext())?;
        let response = self.request(protocol::Operation::Decrypt, request).await?;
        let payload = protocol::plaintext_response(&response)?;
        let key = payload.verify(context, &self.identity)?;
        SecretWrappedKeyPayload::encode(&key, context, &self.identity)
    }
}

#[cfg(fuzzing)]
pub(super) fn fuzz_wire(data: &[u8]) {
    let identity = ProviderKeyUri::new(ProviderFamily::GoogleCloudKms, "projects/project-1/locations/us-central1/keyRings/ring/cryptoKeys/root/cryptoKeyVersions/7", "7").expect("published Google resource fixture");
    let _ = protocol::verify_metadata(data, &identity);
    drop(protocol::wrapped_response(data, &identity));
    if let Ok(payload) = protocol::plaintext_response(data) {
        let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)
            .expect("bounded context fixture");
        drop(payload.verify(context, &identity));
    }
    for operation in [
        protocol::Operation::Metadata,
        protocol::Operation::Encrypt,
        protocol::Operation::Decrypt,
    ] {
        let code = 400 + u16::from(data.first().copied().unwrap_or_default());
        let _ = protocol::classify(operation, code, data);
    }
    if let Ok(resource) = std::str::from_utf8(data) {
        let version = resource.rsplit('/').next().unwrap_or_default();
        drop(ProviderKeyUri::new(
            ProviderFamily::GoogleCloudKms,
            resource,
            version,
        ));
    }
}
