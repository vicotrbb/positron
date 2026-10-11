//! Native AWS KMS v2014-11-01. No configurable endpoint or key lifecycle API.
use super::*;
use crate::{
    ResourceAmounts, ResourceDimension, ResourceReservation, TransferredResourceReservation,
};
use aws_config::default_provider::credentials::DefaultCredentialsChain;
use aws_credential_types::provider::ProvideCredentials;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing::instrument::WithSubscriber;
use zeroize::Zeroizing;
mod credentials_http;
mod dns;
pub(super) mod protocol;
#[cfg(test)]
mod tests;

const MEMORY_BYTES: u64 = 32 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(15);
fn credential_failure(
    error: aws_credential_types::provider::error::CredentialsError,
) -> KeyProviderFailure {
    use aws_credential_types::provider::error::CredentialsError;
    if std::error::Error::source(&error).is_some_and(|source| {
        source.is::<aws_config::credential_process::ProcessCapacityUnavailable>()
    }) {
        return KeyProviderFailure::LimitExceeded;
    }
    match error {
        CredentialsError::InvalidConfiguration(_) | CredentialsError::Unhandled(_) => {
            KeyProviderFailure::InvalidConfiguration
        },
        _ => KeyProviderFailure::Unavailable,
    }
}
struct ActiveOperation<'a>(&'a AtomicBool);
impl Drop for ActiveOperation<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// A pinned, pre-provisioned symmetric key and its native renewable SDK chain.
/// The governor grant precedes SDK construction and remains held across refresh.
pub struct AwsKmsKeyProvider {
    identity: ProviderKeyUri,
    endpoint: String,
    region: String,
    credentials: DefaultCredentialsChain,
    client: reqwest::Client,
    active: AtomicBool,
    _resources: std::sync::Arc<dns::Resources>,
}
impl AwsKmsKeyProvider {
    fn begin(&self) -> Result<ActiveOperation<'_>, KeyProviderFailure> {
        if self._resources.busy() {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        self.active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| KeyProviderFailure::LimitExceeded)?;
        Ok(ActiveOperation(&self.active))
    }
    /// Fixed admitted budget for one operation, including identity refresh and
    /// its native credential process, bounded files, TLS and response buffers.
    #[must_use]
    pub const fn required_resources() -> ResourceAmounts {
        ResourceAmounts::new([MEMORY_BYTES, 1, 4, 0, 0, 1, 2, 4, 1, 8, 0])
    }
    pub async fn from_standard_chain(
        identity: ProviderKeyUri,
        reservation: ResourceReservation<'_>,
    ) -> Result<Self, KeyProviderFailure> {
        if identity.family() != ProviderFamily::AwsKms {
            return Err(KeyProviderFailure::InvalidConfiguration);
        }
        let (partition, region, _) =
            aws_arn_parts(identity.locator()).ok_or(KeyProviderFailure::InvalidConfiguration)?;
        let suffix = match partition {
            "aws" | "aws-us-gov" => "amazonaws.com",
            "aws-cn" => "amazonaws.com.cn",
            "aws-eusc" => "amazonaws.eu",
            "aws-iso" => "c2s.ic.gov",
            "aws-iso-b" => "sc2s.sgov.gov",
            "aws-iso-e" => "cloud.adc-e.uk",
            "aws-iso-f" => "csp.hci.ic.gov",
            _ => return Err(KeyProviderFailure::InvalidConfiguration),
        };
        let required = Self::required_resources();
        if !reservation.is_active()
            || ResourceDimension::ALL
                .iter()
                .any(|dimension| reservation.granted().get(*dimension) < required.get(*dimension))
        {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        let resources = dns::Resources::new(reservation.transfer());
        let dns = dns::NativeDns(resources.clone());
        let endpoint = format!("https://kms.{region}.{suffix}/");
        let region = region.to_owned();
        let client = credentials_http::client(dns.clone())?;
        let config = aws_config::provider_config::ProviderConfig::without_region()
            .with_region(Some(aws_types::region::Region::new(region.clone())))
            .with_behavior_version(Some(aws_config::BehaviorVersion::latest()))
            .with_dns_resolver(dns.clone())
            .with_credential_process_admission(std::sync::Arc::new(dns::ProcessAdmission(
                resources.clone(),
            )))
            .with_http_client(credentials_http::AwsCredentialHttp::new(
                client.clone(),
                dns,
            ))
            .with_retry_config(
                aws_smithy_types::retry::RetryConfig::standard().with_max_attempts(2),
            )
            .with_timeout_config(
                aws_smithy_types::timeout::TimeoutConfig::builder()
                    .connect_timeout(Duration::from_secs(2))
                    .read_timeout(Duration::from_secs(5))
                    .operation_attempt_timeout(Duration::from_secs(5))
                    .operation_timeout(DEADLINE)
                    .build(),
            );
        // SDK errors sometimes contain raw provider response text. Prevent SDK
        // events from entering the application's subscriber on every future poll.
        let credentials = DefaultCredentialsChain::builder()
            .region(aws_types::region::Region::new(region.clone()))
            .configure(config)
            .build()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await;
        Ok(Self {
            identity,
            endpoint,
            region,
            credentials,
            client,
            active: AtomicBool::new(false),
            _resources: resources,
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
    /// Provider-bound embedded payloads require authenticated unwrap and rebuild.
    /// Native ReEncrypt cannot change that payload's source context digest.
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
    async fn request(
        &self,
        operation: protocol::Operation,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>, KeyProviderFailure> {
        tokio::runtime::Handle::try_current()
            .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
        let credentials = tokio::time::timeout(
            DEADLINE,
            self.credentials
                .provide_credentials()
                .with_subscriber(tracing::subscriber::NoSubscriber::default()),
        )
        .await
        .map_err(|_| KeyProviderFailure::Unavailable)?
        .map_err(credential_failure)?;
        if credentials.access_key_id().len() > 1024
            || credentials.secret_access_key().len() > 4096
            || credentials
                .session_token()
                .is_some_and(|token| token.len() > 65_536)
        {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        let bytes = bytes::Bytes::from_owner(body);
        // Encrypt is stateless, but an uncertain transport result is never
        // automatically retried. Only explicit throttle/unavailable rejections
        // are retried within the admitted two-attempt budget.
        let request = async {
            for attempt in 0..2 {
                let response = protocol::send(
                    &self.client,
                    &self.endpoint,
                    &self.region,
                    &credentials,
                    operation,
                    bytes.clone(),
                )
                .await?;
                match response {
                    Ok(body) => return Ok(body),
                    Err(failure)
                        if failure.disposition() == ProviderFailureDisposition::Retryable
                            && attempt == 0 =>
                    {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    },
                    Err(failure) => return Err(failure),
                }
            }
            Err(KeyProviderFailure::Unavailable)
        };
        tokio::time::timeout(DEADLINE, request)
            .await
            .map_err(|_| operation.transport_failure())?
    }
}
impl KeyProvider for AwsKmsKeyProvider {
    fn identity(&self) -> &ProviderKeyUri {
        &self.identity
    }
    fn credential_model(&self) -> &ProviderCredentialModel {
        &ProviderCredentialModel::AwsStandardChain
    }
    async fn probe(
        &self,
        _context: EnvelopeContext,
    ) -> Result<ProviderCapabilities, KeyProviderFailure> {
        let _active = self.begin()?;
        let request = protocol::describe_request(&self.identity)?;
        let response = self.request(protocol::Operation::Describe, request).await?;
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
        let ciphertext = protocol::wrapped_response(&response, &self.identity)?;
        KeyEnvelope::from_provider_response(
            self.identity.clone(),
            context,
            WrappingAlgorithm::AwsKmsSymmetricDefault,
            ciphertext,
        )
    }
    async fn unwrap(
        &self,
        envelope: &KeyEnvelope,
        context: EnvelopeContext,
    ) -> Result<SecretWrappedKeyPayload, KeyProviderFailure> {
        let _active = self.begin()?;
        envelope.check(&self.identity, context)?;
        if envelope.algorithm != WrappingAlgorithm::AwsKmsSymmetricDefault {
            return Err(KeyProviderFailure::ContextMismatch);
        }
        let request = protocol::decrypt_request(&self.identity, context, envelope.ciphertext())?;
        let response = self.request(protocol::Operation::Decrypt, request).await?;
        protocol::plaintext_response(&response, &self.identity)
    }
}
