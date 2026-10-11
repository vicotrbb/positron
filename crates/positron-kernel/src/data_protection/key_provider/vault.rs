//! HashiCorp Vault 2.1.2 Transit v1 native renewable machine authentication.
use super::*;
use crate::{ResourceAmounts, ResourceDimension, ResourceReservation};
use google_cloud_auth::native::{Request, Runtime};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use zeroize::Zeroizing;
mod authentication;
mod protocol;
#[cfg(test)]
mod tests;

/// Pre-provisioned, derived AES-256-GCM Transit key; no key administration API.
pub struct VaultTransitKeyProvider {
    identity: ProviderKeyUri,
    credential_model: ProviderCredentialModel,
    authentication_mount: String,
    runtime: Arc<dyn Runtime>,
    token: Mutex<Option<authentication::Token>>,
    active: AtomicBool,
}
impl VaultTransitKeyProvider {
    #[must_use]
    pub fn identity(&self) -> &ProviderKeyUri {
        &self.identity
    }
    #[must_use]
    pub const fn required_resources() -> ResourceAmounts {
        GoogleCloudKmsKeyProvider::required_resources()
    }
    /// `authentication_mount` is the configured native auth mount (for example
    /// `kubernetes` or `jwt`); it must be empty for a protected token file.
    /// Construction checks admitted file custody without contacting Vault.
    pub fn from_native(
        identity: ProviderKeyUri,
        authentication: TransitAuthentication,
        authentication_mount: &str,
        trust_roots: Option<&CredentialFileReference>,
        reservation: ResourceReservation<'_>,
    ) -> Result<Self, KeyProviderFailure> {
        Self::from_native_target(
            identity,
            authentication,
            authentication_mount,
            trust_roots,
            reservation,
            ProviderFamily::VaultTransit,
        )
    }
    // The shared operations are separately verified against each pinned native
    // source. Public constructors cannot select a different provider family.
    pub(super) fn from_native_target(
        identity: ProviderKeyUri,
        authentication: TransitAuthentication,
        authentication_mount: &str,
        trust_roots: Option<&CredentialFileReference>,
        reservation: ResourceReservation<'_>,
        family: ProviderFamily,
    ) -> Result<Self, KeyProviderFailure> {
        if identity.family() != family {
            return Err(KeyProviderFailure::InvalidConfiguration);
        }
        let required = Self::required_resources();
        if !reservation.is_active()
            || ResourceDimension::ALL
                .iter()
                .any(|d| reservation.granted().get(*d) < required.get(*d))
        {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        tokio::runtime::Handle::try_current()
            .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
        let mut runtime = super::google::native::NativeRuntime::new(reservation.transfer())?;
        if let Some(reference) = trust_roots {
            let pem = runtime.read_trust_roots(reference.path())?;
            Arc::get_mut(&mut runtime)
                .ok_or(KeyProviderFailure::InvalidConfiguration)?
                .add_trust_roots(&pem)?;
        }
        let credential_model = ProviderCredentialModel::Transit(authentication);
        credential_model.validate(family)?;
        authentication::validate_mount(&credential_model, authentication_mount)?;
        drop(authentication::read_credential(&credential_model)?);
        Ok(Self {
            identity,
            credential_model,
            authentication_mount: authentication_mount.to_owned(),
            runtime,
            token: Mutex::new(None),
            active: AtomicBool::new(false),
        })
    }
    fn begin(&self) -> Result<ActiveOperation<'_>, KeyProviderFailure> {
        self.active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| KeyProviderFailure::LimitExceeded)?;
        Ok(ActiveOperation {
            active: &self.active,
            deadline: tokio::time::Instant::now() + Duration::from_secs(15),
        })
    }
    async fn request(
        &self,
        operation: protocol::Operation,
        token: Option<&str>,
        body: Zeroizing<Vec<u8>>,
        deadline: tokio::time::Instant,
    ) -> Result<Zeroizing<Vec<u8>>, KeyProviderFailure> {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        if let Some(token) = token {
            let mut value = http::HeaderValue::from_str(token)
                .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
            value.set_sensitive(true);
            headers.insert("x-vault-token", value);
        }
        let mut submitted = false;
        let future = async {
            for attempt in 0..2 {
                submitted = true;
                let reply = self
                    .runtime
                    .http(Request {
                        method: operation.method(),
                        url: operation.endpoint(&self.identity, &self.authentication_mount)?,
                        headers: headers.clone(),
                        body: Zeroizing::new(body.to_vec()),
                    })
                    .await
                    .map_err(|e| {
                        if e == google_cloud_auth::native::Error::Unavailable {
                            operation.transport_failure()
                        } else {
                            super::google::native_failure(e)
                        }
                    })?;
                if reply.status == http::StatusCode::OK {
                    return Ok(reply.body);
                }
                let failure = operation.classify(reply.status.as_u16());
                // Only explicit throttling is replayed; unknown encrypt/login/renew
                // outcomes never trigger a second submission.
                if reply.status == http::StatusCode::TOO_MANY_REQUESTS && attempt == 0 {
                    tokio::time::sleep(protocol::retry_delay(&reply.headers)?).await;
                } else {
                    return Err(failure);
                }
            }
            Err(KeyProviderFailure::Unavailable)
        };
        tokio::time::timeout_at(deadline, future)
            .await
            .map_err(|_| {
                if submitted {
                    operation.transport_failure()
                } else {
                    KeyProviderFailure::Unavailable
                }
            })?
    }
    async fn verify_target(
        &self,
        token: &str,
        deadline: tokio::time::Instant,
        wrapping: bool,
    ) -> Result<(), KeyProviderFailure> {
        let health = self
            .request(
                protocol::Operation::Health,
                None,
                Zeroizing::new(Vec::new()),
                deadline,
            )
            .await?;
        protocol::verify_health(&health, self.identity.family())?;
        let metadata = self
            .request(
                protocol::Operation::Metadata,
                Some(token),
                Zeroizing::new(Vec::new()),
                deadline,
            )
            .await?;
        protocol::verify_metadata(&metadata, &self.identity, wrapping)
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
pub(super) struct ActiveOperation<'a> {
    pub(super) active: &'a AtomicBool,
    pub(super) deadline: tokio::time::Instant,
}
impl Drop for ActiveOperation<'_> {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}
impl KeyProvider for VaultTransitKeyProvider {
    fn identity(&self) -> &ProviderKeyUri {
        &self.identity
    }
    fn credential_model(&self) -> &ProviderCredentialModel {
        &self.credential_model
    }
    async fn probe(&self, _: EnvelopeContext) -> Result<ProviderCapabilities, KeyProviderFailure> {
        let operation = self.begin()?;
        let token = self.authenticate(operation.deadline).await?;
        self.verify_target(&token, operation.deadline, false)
            .await?;
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
        let token = self.authenticate(operation.deadline).await?;
        self.verify_target(&token, operation.deadline, true).await?;
        let request =
            protocol::encrypt_request(payload.as_provider_plaintext(), context, &self.identity)?;
        drop(payload);
        let response = self
            .request(
                protocol::Operation::Encrypt,
                Some(&token),
                request,
                operation.deadline,
            )
            .await?;
        let ciphertext = protocol::encrypted_response(&response, &self.identity)?;
        KeyEnvelope::from_provider_response(
            self.identity.clone(),
            context,
            WrappingAlgorithm::Aes256Gcm,
            ciphertext,
        )
    }
    async fn unwrap(
        &self,
        envelope: &KeyEnvelope,
        context: EnvelopeContext,
    ) -> Result<SecretWrappedKeyPayload, KeyProviderFailure> {
        envelope.check(&self.identity, context)?;
        if envelope.algorithm != WrappingAlgorithm::Aes256Gcm {
            return Err(KeyProviderFailure::ContextMismatch);
        }
        protocol::verify_ciphertext(envelope.ciphertext(), &self.identity)?;
        let operation = self.begin()?;
        let token = self.authenticate(operation.deadline).await?;
        self.verify_target(&token, operation.deadline, false)
            .await?;
        let request = protocol::decrypt_request(envelope.ciphertext(), context, &self.identity)?;
        let response = self
            .request(
                protocol::Operation::Decrypt,
                Some(&token),
                request,
                operation.deadline,
            )
            .await?;
        let payload = protocol::decrypted_response(&response)?;
        let key = payload.verify(context, &self.identity)?;
        SecretWrappedKeyPayload::encode(&key, context, &self.identity)
    }
}

#[cfg(fuzzing)]
pub(super) fn fuzz_wire(bytes: &[u8]) {
    for family in [ProviderFamily::VaultTransit, ProviderFamily::OpenBaoTransit] {
        let identity = ProviderKeyUri::new(
            family,
            "https://transit.example:8200/v1/transit/keys/root",
            "1",
        )
        .expect("fixed Transit wire identity");
        let _ = protocol::verify_health(bytes, family);
        let _ = protocol::verify_metadata(bytes, &identity, false);
        let _ = protocol::verify_metadata(bytes, &identity, true);
        let _ = protocol::verify_ciphertext(bytes, &identity);
        drop(protocol::encrypted_response(bytes, &identity));
    }
    drop(protocol::decrypted_response(bytes));
    let now = tokio::time::Instant::now();
    drop(protocol::authentication_response(bytes, now));
    drop(protocol::lookup_response(
        bytes,
        Zeroizing::new("fictional-fuzz-token".to_owned()),
        now,
    ));
}
