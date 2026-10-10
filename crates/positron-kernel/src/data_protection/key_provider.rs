//! Version 1 provider port. Credentials and provider SDKs stay inside adapters.

use std::fmt::{Display, Formatter};

mod cache;
mod conformance;
pub use conformance::{
    ConformanceFailure, ConformanceStep, KeyProviderConformance, ProviderConformanceTarget,
};
mod codec;
mod credentials;
#[cfg(fuzzing)]
mod fuzzing;
mod local;
pub(super) mod owner;
mod payload;
mod session;
pub use cache::{CacheInvalidation, KeyCacheHealth, KeyCacheLease, KeyProviderCache};
#[cfg(test)]
pub(in crate::data_protection) use cache::{observe_cache_release, with_cache_lock_failure};
pub use credentials::{CredentialFileReference, ProviderCredentialModel, TransitAuthentication};
#[cfg(fuzzing)]
#[doc(hidden)]
pub use fuzzing::{fuzz_key_cache_stateful, fuzz_key_provider_envelope};
pub use local::LocalKeyProvider;
pub(crate) use owner::DataProtectionProvider;
pub use payload::{
    EnvelopeContext, KeyEnvelope, KeyScope, SecretKek, SecretWrappedKeyPayload, WrappingAlgorithm,
};
pub use session::KeyProviderSession;

/// Capabilities verified against the exact pre-provisioned key, never an alias.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderCapabilities {
    pub interface_version: u16,
    pub identity: ProviderKeyUri,
    pub verified_tls: bool,
    pub can_wrap: bool,
    pub can_unwrap: bool,
}

/// SDK adapters own renewable credentials and authenticate every connection.
/// No operation provisions or mutates an external root key.
#[allow(async_fn_in_trait)]
pub trait KeyProvider {
    fn identity(&self) -> &ProviderKeyUri;
    fn credential_model(&self) -> &ProviderCredentialModel;
    async fn probe(
        &self,
        context: EnvelopeContext,
    ) -> Result<ProviderCapabilities, KeyProviderFailure>;
    async fn wrap(
        &self,
        payload: SecretWrappedKeyPayload,
        context: EnvelopeContext,
    ) -> Result<KeyEnvelope, KeyProviderFailure>;
    async fn unwrap(
        &self,
        envelope: &KeyEnvelope,
        context: EnvelopeContext,
    ) -> Result<SecretWrappedKeyPayload, KeyProviderFailure>;
}

/// Distinct conformance targets, including Vault versus OpenBao and Azure HSM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProviderFamily {
    LocalFile = 1,
    AwsKms = 2,
    GoogleCloudKms = 3,
    AzureKeyVault = 4,
    AzureManagedHsm = 5,
    VaultTransit = 6,
    OpenBaoTransit = 7,
    Kmip21 = 8,
}

/// Immutable key locator plus the exact provider-owned version.
/// Adapters must verify this identity in every successful provider response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderKeyUri {
    family: ProviderFamily,
    locator: String,
    version: String,
}

impl ProviderKeyUri {
    pub fn new(
        family: ProviderFamily,
        locator: &str,
        version: &str,
    ) -> Result<Self, KeyProviderFailure> {
        let text = |value: &str, maximum| {
            !value.is_empty()
                && value.len() <= maximum
                && value.bytes().all(|byte| byte.is_ascii_graphic())
                && !value.contains(['?', '#', '@'])
        };
        let positive_version = version.parse::<u64>().is_ok_and(|value| value > 0);
        let pinned = match family {
            ProviderFamily::AwsKms => {
                version == "immutable"
                    && locator.starts_with("arn:")
                    && locator.contains(":kms:")
                    && locator.rsplit_once(":key/").is_some_and(|(_, key)| {
                        !key.is_empty()
                            && !key.contains('/')
                            && key.bytes().all(|byte| {
                                byte.is_ascii_hexdigit()
                                    || matches!(byte, b'-' | b'm' | b'r' | b'k')
                            })
                    })
            },
            ProviderFamily::GoogleCloudKms => {
                positive_version
                    && locator.starts_with("projects/")
                    && locator
                        .rsplit_once("/cryptoKeyVersions/")
                        .is_some_and(|(_, actual)| actual == version)
            },
            ProviderFamily::AzureKeyVault | ProviderFamily::AzureManagedHsm => {
                locator.starts_with("https://")
                    && locator.split_once("/keys/").is_some_and(|(_, path)| {
                        path.split_once('/').is_some_and(|(name, actual)| {
                            !name.is_empty()
                                && actual == version
                                && version.len() == 32
                                && version.bytes().all(|byte| byte.is_ascii_hexdigit())
                        })
                    })
            },
            ProviderFamily::VaultTransit | ProviderFamily::OpenBaoTransit => {
                positive_version
                    && locator.starts_with("https://")
                    && locator
                        .rsplit_once("/keys/")
                        .is_some_and(|(_, name)| !name.is_empty() && !name.contains('/'))
            },
            ProviderFamily::Kmip21 => version == "immutable",
            ProviderFamily::LocalFile => true,
        };
        if !text(locator, 512) || !text(version, 128) || !pinned {
            return Err(KeyProviderFailure::InvalidConfiguration);
        }
        Ok(Self {
            family,
            locator: locator.to_owned(),
            version: version.to_owned(),
        })
    }
    #[must_use]
    pub const fn family(&self) -> ProviderFamily {
        self.family
    }
    #[must_use]
    pub fn locator(&self) -> &str {
        &self.locator
    }
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// Secret-free classifications. Provider response bodies must never be attached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyProviderFailure {
    InvalidConfiguration,
    Unavailable,
    PermissionDenied,
    WrongKey,
    ContextMismatch,
    Ambiguous,
    LimitExceeded,
    MemoryProtection,
}

impl Display for KeyProviderFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "KEY_PROVIDER_UNAVAILABLE",
            Self::ContextMismatch => "KEY_ENVELOPE_CONTEXT_MISMATCH",
            _ => "key provider operation failed",
        })
    }
}
impl std::error::Error for KeyProviderFailure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderFailureDisposition {
    Retryable,
    Permanent,
    Ambiguous,
}
impl KeyProviderFailure {
    #[must_use]
    pub const fn disposition(self) -> ProviderFailureDisposition {
        match self {
            Self::Unavailable => ProviderFailureDisposition::Retryable,
            Self::Ambiguous => ProviderFailureDisposition::Ambiguous,
            _ => ProviderFailureDisposition::Permanent,
        }
    }
}
