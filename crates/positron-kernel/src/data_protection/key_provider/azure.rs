//! Azure Key Vault REST 7.6 with native managed/projected workload identity.
use super::*;
use crate::{ResourceAmounts, ResourceDimension, ResourceReservation};
use azure_core::credentials::TokenCredential;
use google_cloud_auth::native::{Request, Runtime};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tracing::instrument::WithSubscriber;
use zeroize::Zeroizing;
mod identity;
mod local_endpoint;
mod protocol;
mod request;
use request::credential_failure;
#[cfg(test)]
mod tests;
pub use azure_identity::UserAssignedId as AzureManagedIdentityId;

/// Non-secret optional selectors; absent fields use the SDK's native environment.
#[derive(Default)]
pub struct AzureWorkloadIdentity {
    pub tenant_id: Option<String>,
    pub client_id: Option<String>,
    pub token_file: Option<CredentialFileReference>,
}

/// One immutable pre-provisioned RSA/RSA-HSM version in Azure Key Vault.
pub struct AzureKeyVaultKeyProvider {
    identity: ProviderKeyUri,
    credentials: Arc<dyn TokenCredential>,
    credential_model: ProviderCredentialModel,
    runtime: Arc<dyn Runtime>,
    active: AtomicBool,
}
impl AzureKeyVaultKeyProvider {
    #[must_use]
    pub const fn required_resources() -> ResourceAmounts {
        GoogleCloudKmsKeyProvider::required_resources()
    }
    fn runtime(
        identity: &ProviderKeyUri,
        reservation: ResourceReservation<'_>,
    ) -> Result<Arc<identity::IdentityRuntime>, KeyProviderFailure> {
        if identity.family() != ProviderFamily::AzureKeyVault {
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
        Ok(Arc::new(identity::IdentityRuntime(
            super::google::native::NativeRuntime::new(reservation.transfer())?,
            std::sync::OnceLock::new(),
            protocol::scope(identity)
                .strip_suffix("/.default")
                .ok_or(KeyProviderFailure::InvalidConfiguration)?,
        )))
    }
    pub async fn from_managed_identity(
        identity: ProviderKeyUri,
        user_assigned_id: Option<AzureManagedIdentityId>,
        reservation: ResourceReservation<'_>,
    ) -> Result<Self, KeyProviderFailure> {
        let runtime = Self::runtime(&identity, reservation)?;
        let valid_id = match &user_assigned_id {
            None => true,
            Some(
                AzureManagedIdentityId::ClientId(id)
                | AzureManagedIdentityId::ObjectId(id)
                | AzureManagedIdentityId::ResourceId(id),
            ) => !id.is_empty() && id.len() <= 8192,
            Some(_) => false,
        };
        if !valid_id {
            return Err(KeyProviderFailure::InvalidConfiguration);
        }
        let credentials =
            tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
                azure_identity::ManagedIdentityCredential::new(Some(
                    azure_identity::ManagedIdentityCredentialOptions {
                        user_assigned_id,
                        native_runtime: Some(runtime.clone()),
                        client_options: runtime.client_options(&identity),
                    },
                ))
            })
            .map_err(credential_failure)?;
        Ok(Self {
            identity,
            credentials,
            credential_model: ProviderCredentialModel::AzureManagedIdentity,
            runtime: runtime.0.clone(),
            active: AtomicBool::new(false),
        })
    }
    pub async fn from_workload_identity(
        identity: ProviderKeyUri,
        selectors: AzureWorkloadIdentity,
        reservation: ResourceReservation<'_>,
    ) -> Result<Self, KeyProviderFailure> {
        let runtime = Self::runtime(&identity, reservation)?;
        if selectors.tenant_id.as_ref().is_some_and(|s| s.len() > 8192)
            || selectors.client_id.as_ref().is_some_and(|s| s.len() > 8192)
        {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        let credentials =
            tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
                azure_identity::WorkloadIdentityCredential::new(Some(
                    azure_identity::WorkloadIdentityCredentialOptions {
                        tenant_id: selectors.tenant_id,
                        client_id: selectors.client_id,
                        token_file_path: selectors.token_file.map(|p| p.path().to_owned()),
                        native_runtime: Some(runtime.clone()),
                        credential_options: azure_identity::ClientAssertionCredentialOptions {
                            client_options: runtime.client_options(&identity),
                        },
                    },
                ))
            })
            .map_err(credential_failure)?;
        Ok(Self {
            identity,
            credentials,
            credential_model: ProviderCredentialModel::AzureWorkloadIdentity,
            runtime: runtime.0.clone(),
            active: AtomicBool::new(false),
        })
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
impl KeyProvider for AzureKeyVaultKeyProvider {
    fn identity(&self) -> &ProviderKeyUri {
        &self.identity
    }
    fn credential_model(&self) -> &ProviderCredentialModel {
        &self.credential_model
    }
    async fn probe(&self, _: EnvelopeContext) -> Result<ProviderCapabilities, KeyProviderFailure> {
        let _active = self.begin()?;
        self.metadata(_active.deadline).await?;
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
        let modulus = self.metadata(_active.deadline).await?;
        let request = protocol::request(payload.as_provider_plaintext(), modulus - 66)?;
        drop(payload);
        drop(verified);
        let bytes = self
            .request(protocol::Operation::Wrap, request, _active.deadline)
            .await?;
        let mut ciphertext = protocol::response(&bytes, &self.identity, modulus)?;
        if ciphertext.len() != modulus {
            return Err(KeyProviderFailure::ContextMismatch);
        }
        KeyEnvelope::from_provider_response(
            self.identity.clone(),
            context,
            WrappingAlgorithm::RsaOaepSha256,
            std::mem::take(&mut *ciphertext),
        )
    }
    async fn unwrap(
        &self,
        envelope: &KeyEnvelope,
        context: EnvelopeContext,
    ) -> Result<SecretWrappedKeyPayload, KeyProviderFailure> {
        envelope.check(&self.identity, context)?;
        if envelope.algorithm != WrappingAlgorithm::RsaOaepSha256 {
            return Err(KeyProviderFailure::ContextMismatch);
        }
        let _active = self.begin()?;
        let modulus = self.metadata(_active.deadline).await?;
        if envelope.ciphertext().len() != modulus {
            return Err(KeyProviderFailure::ContextMismatch);
        }
        let request = protocol::request(envelope.ciphertext(), modulus)?;
        let bytes = self
            .request(protocol::Operation::Unwrap, request, _active.deadline)
            .await?;
        let mut plaintext = protocol::response(&bytes, &self.identity, modulus - 66)?;
        let payload =
            SecretWrappedKeyPayload::from_provider_plaintext(std::mem::take(&mut *plaintext))?;
        let verified = payload.verify(context, &self.identity)?;
        SecretWrappedKeyPayload::encode(&verified, context, &self.identity)
    }
}

#[cfg(fuzzing)]
pub(super) fn fuzz_wire(data: &[u8]) {
    let identity = ProviderKeyUri::new(
        ProviderFamily::AzureKeyVault,
        "https://fixture.vault.azure.net/keys/root/0123456789abcdef0123456789abcdef",
        "0123456789abcdef0123456789abcdef",
    )
    .expect("published Azure URI shape");
    let _ = protocol::verify_metadata(data, &identity);
    drop(protocol::response(data, &identity, 512));
    drop(protocol::response(data, &identity, 190));
    let context =
        EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1).expect("fixed context");
    if let Ok(mut plain) = protocol::response(data, &identity, 446) {
        if let Ok(payload) =
            SecretWrappedKeyPayload::from_provider_plaintext(std::mem::take(&mut *plain))
        {
            drop(payload.verify(context, &identity));
        }
    }
    if let Ok(locator) = std::str::from_utf8(data) {
        if locator.len() <= 4096 {
            if let Ok(endpoint) = azure_core::http::Url::parse(locator) {
                if let Ok(capability) =
                    local_endpoint::LocalEndpoint::new(&endpoint, None, "https://vault.azure.net")
                {
                    drop(capability.validate(&azure_core::http::Request::new(
                        endpoint,
                        azure_core::http::Method::Get,
                    )));
                }
            }
        }
        let version = locator.rsplit('/').next().unwrap_or_default();
        drop(ProviderKeyUri::new(
            ProviderFamily::AzureKeyVault,
            locator,
            version,
        ));
    }
    for operation in [
        protocol::Operation::Metadata,
        protocol::Operation::Wrap,
        protocol::Operation::Unwrap,
    ] {
        let _ = protocol::classify(
            operation,
            400 + u16::from(data.first().copied().unwrap_or_default()),
        );
    }
}
