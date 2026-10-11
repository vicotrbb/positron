//! Positron's bounded KMIP 2.1 remote AES-256-GCM subset.
use super::*;
use crate::{ResourceAmounts, ResourceDimension, ResourceReservation};
use std::sync::Arc;
mod native;
mod protocol;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;
type Connection = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;
#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod tests;

pub struct Kmip21KeyProvider {
    identity: ProviderKeyUri,
    credential_model: ProviderCredentialModel,
    runtime: Arc<super::google::native::NativeRuntime>,
    active: AtomicBool,
}
impl Kmip21KeyProvider {
    #[must_use]
    pub const fn required_resources() -> ResourceAmounts {
        GoogleCloudKmsKeyProvider::required_resources()
    }
    pub fn from_native(
        identity: ProviderKeyUri,
        credential_model: ProviderCredentialModel,
        reservation: ResourceReservation<'_>,
    ) -> Result<Self, KeyProviderFailure> {
        if identity.family() != ProviderFamily::Kmip21 {
            return Err(KeyProviderFailure::InvalidConfiguration);
        }
        credential_model.validate(ProviderFamily::Kmip21)?;
        if !reservation.is_active()
            || ResourceDimension::ALL
                .iter()
                .any(|d| reservation.granted().get(*d) < Self::required_resources().get(*d))
        {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        tokio::runtime::Handle::try_current()
            .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
        let runtime = super::google::native::NativeRuntime::new(reservation.transfer())?;
        drop(native::identity(&runtime, &credential_model)?);
        Ok(Self {
            identity,
            credential_model,
            runtime,
            active: AtomicBool::new(false),
        })
    }
    #[must_use]
    pub fn identity(&self) -> &ProviderKeyUri {
        &self.identity
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
    fn begin(&self) -> Result<super::vault::ActiveOperation<'_>, KeyProviderFailure> {
        self.active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| KeyProviderFailure::LimitExceeded)?;
        Ok(super::vault::ActiveOperation {
            active: &self.active,
            deadline: tokio::time::Instant::now() + Duration::from_secs(15),
        })
    }
    async fn connect(&self) -> Result<Connection, KeyProviderFailure> {
        let url = reqwest::Url::parse(self.identity.locator())
            .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
        let host = url
            .host_str()
            .ok_or(KeyProviderFailure::InvalidConfiguration)?
            .trim_matches(['[', ']']);
        let port = url.port().unwrap_or(5696);
        let name = rustls_pki_types::ServerName::try_from(host.to_owned())
            .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
        let config = native::identity(&self.runtime, &self.credential_model)?;
        let addresses = match host.parse::<std::net::IpAddr>() {
            Ok(ip) => vec![std::net::SocketAddr::new(ip, port)],
            Err(_) => self.runtime.native_addresses(host).await?,
        };
        let address = addresses.first().ok_or(KeyProviderFailure::Unavailable)?;
        let socket = tokio::net::TcpStream::connect(std::net::SocketAddr::new(address.ip(), port))
            .await
            .map_err(|_| KeyProviderFailure::Unavailable)?;
        tokio_rustls::TlsConnector::from(config)
            .connect(name, socket)
            .await
            .map_err(|_| KeyProviderFailure::PermissionDenied)
    }
    async fn exchange(
        &self,
        socket: &mut Connection,
        operation: protocol::Operation,
        payload: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyProviderFailure> {
        let request = protocol::request(operation, payload)?;
        socket
            .write_all(&request)
            .await
            .map_err(|_| operation.transport_failure())?;
        socket
            .flush()
            .await
            .map_err(|_| operation.transport_failure())?;
        let mut header = [0; 8];
        socket
            .read_exact(&mut header)
            .await
            .map_err(|_| operation.transport_failure())?;
        let length = protocol::frame_length(&header)?;
        let mut reply = Zeroizing::new(Vec::with_capacity(length + 8));
        reply.extend_from_slice(&header);
        reply.resize(length + 8, 0);
        socket
            .read_exact(
                reply
                    .get_mut(8..)
                    .ok_or(KeyProviderFailure::ContextMismatch)?,
            )
            .await
            .map_err(|_| operation.transport_failure())?;
        protocol::response(&reply, operation)?;
        Ok(reply)
    }
    async fn verified_connection(&self, wrapping: bool) -> Result<Connection, KeyProviderFailure> {
        let mut socket = self.connect().await?;
        let reply = self
            .exchange(
                &mut socket,
                protocol::Operation::DiscoverVersions,
                &protocol::version()?,
            )
            .await?;
        protocol::verify_version(protocol::response(
            &reply,
            protocol::Operation::DiscoverVersions,
        )?)?;
        let payload = protocol::metadata_request(&self.identity)?;
        let reply = self
            .exchange(&mut socket, protocol::Operation::GetAttributes, &payload)
            .await?;
        protocol::verify_metadata(
            protocol::response(&reply, protocol::Operation::GetAttributes)?,
            &self.identity,
            wrapping,
        )?;
        Ok(socket)
    }
}
#[cfg(fuzzing)]
pub(super) fn fuzz_wire(bytes: &[u8]) {
    if let Some(header) = bytes.get(..8).and_then(|h| h.try_into().ok()) {
        let _ = protocol::frame_length(header);
    }
    let bounded = bytes.get(..bytes.len().min(8193)).unwrap_or_default();
    let identity = ProviderKeyUri::new(
        ProviderFamily::Kmip21,
        "kmip://example.test/objects/fuzz-key",
        "sha256:0606060606060606060606060606060606060606060606060606060606060606",
    )
    .expect("fixed public KMIP identity");
    let context =
        EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1).expect("fixed context");
    for operation in [
        protocol::Operation::DiscoverVersions,
        protocol::Operation::GetAttributes,
        protocol::Operation::Encrypt,
        protocol::Operation::Decrypt,
    ] {
        let _ = protocol::response(bounded, operation);
    }
    let _ = protocol::verify_version(bounded);
    let _ = protocol::verify_metadata(bounded, &identity, true);
    let _ = protocol::encrypted_response(bounded, &identity);
    if let Ok(payload) = protocol::decrypted_response(bounded, &identity) {
        drop(payload.verify(context, &identity));
    }
    drop(protocol::decrypt_request(bounded, context, &identity));
}
impl KeyProvider for Kmip21KeyProvider {
    fn identity(&self) -> &ProviderKeyUri {
        &self.identity
    }
    fn credential_model(&self) -> &ProviderCredentialModel {
        &self.credential_model
    }
    async fn probe(&self, _: EnvelopeContext) -> Result<ProviderCapabilities, KeyProviderFailure> {
        let operation = self.begin()?;
        tokio::time::timeout_at(operation.deadline, self.verified_connection(true))
            .await
            .map_err(|_| KeyProviderFailure::Unavailable)??;
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
        let operation = self.begin()?;
        let key = payload.verify(context, &self.identity)?;
        let payload = SecretWrappedKeyPayload::encode(&key, context, &self.identity)?;
        drop(key);
        let plaintext_length = payload.as_provider_plaintext().len();
        let mut submitted = false;
        let work = async {
            let mut socket = self.verified_connection(true).await?;
            let request = protocol::encrypt_request(
                payload.as_provider_plaintext(),
                context,
                &self.identity,
            )?;
            drop(payload);
            submitted = true;
            let reply = self
                .exchange(&mut socket, protocol::Operation::Encrypt, &request)
                .await?;
            let ciphertext = protocol::encrypted_response(
                protocol::response(&reply, protocol::Operation::Encrypt)?,
                &self.identity,
            )?;
            if ciphertext.len() != 29 + plaintext_length {
                return Err(KeyProviderFailure::ContextMismatch);
            }
            KeyEnvelope::from_provider_response(
                self.identity.clone(),
                context,
                WrappingAlgorithm::Aes256Gcm,
                ciphertext,
            )
        };
        tokio::time::timeout_at(operation.deadline, work)
            .await
            .map_err(|_| {
                if submitted {
                    KeyProviderFailure::Ambiguous
                } else {
                    KeyProviderFailure::Unavailable
                }
            })?
    }
    async fn unwrap(
        &self,
        envelope: &KeyEnvelope,
        context: EnvelopeContext,
    ) -> Result<SecretWrappedKeyPayload, KeyProviderFailure> {
        let operation = self.begin()?;
        envelope.check(&self.identity, context)?;
        if envelope.algorithm != WrappingAlgorithm::Aes256Gcm {
            return Err(KeyProviderFailure::ContextMismatch);
        }
        let request = protocol::decrypt_request(envelope.ciphertext(), context, &self.identity)?;
        tokio::time::timeout_at(operation.deadline, async {
            let mut socket = self.verified_connection(false).await?;
            let reply = self
                .exchange(&mut socket, protocol::Operation::Decrypt, &request)
                .await?;
            let payload = protocol::decrypted_response(
                protocol::response(&reply, protocol::Operation::Decrypt)?,
                &self.identity,
            )?;
            let key = payload.verify(context, &self.identity)?;
            SecretWrappedKeyPayload::encode(&key, context, &self.identity)
        })
        .await
        .map_err(|_| KeyProviderFailure::Unavailable)?
    }
}
