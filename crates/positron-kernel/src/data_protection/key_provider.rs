//! Version 1 provider port. Credentials and provider SDKs stay inside adapters.

use std::fmt::{Display, Formatter};

mod aws;
mod azure;
mod wire;
pub use azure::{
    AzureKeyVaultKeyProvider, AzureManagedHsmKeyProvider, AzureManagedIdentityId,
    AzureWorkloadIdentity,
};
mod cache;
pub use aws::AwsKmsKeyProvider;
mod conformance;
pub use conformance::{
    ConformanceFailure, ConformanceStep, KeyProviderConformance, ProviderConformanceTarget,
};
mod codec;
mod credentials;
mod google;
pub use google::GoogleCloudKmsKeyProvider;
#[cfg(fuzzing)]
mod fuzzing;
mod kmip;
mod local;
pub use kmip::Kmip21KeyProvider;
mod openbao;
pub(super) mod owner;
mod payload;
mod session;
mod vault;
pub use cache::{CacheInvalidation, KeyCacheHealth, KeyCacheLease, KeyProviderCache};
#[cfg(test)]
pub(in crate::data_protection) use cache::{observe_cache_release, with_cache_lock_failure};
pub use credentials::{CredentialFileReference, ProviderCredentialModel, TransitAuthentication};
#[cfg(fuzzing)]
#[doc(hidden)]
pub use fuzzing::{fuzz_key_cache_stateful, fuzz_key_provider_envelope};
pub use local::LocalKeyProvider;
pub use openbao::OpenBaoTransitKeyProvider;
pub(crate) use owner::DataProtectionProvider;
pub use payload::{
    EnvelopeContext, KeyEnvelope, KeyScope, SecretKek, SecretWrappedKeyPayload, WrappingAlgorithm,
};
pub use session::KeyProviderSession;
pub use vault::VaultTransitKeyProvider;

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
            ProviderFamily::AwsKms => version == "immutable" && aws_arn_parts(locator).is_some(),
            ProviderFamily::GoogleCloudKms => {
                positive_version && google_version_resource(locator, version)
            },
            ProviderFamily::AzureKeyVault => azure_key_uri(locator, version, false),
            ProviderFamily::AzureManagedHsm => azure_key_uri(locator, version, true),
            ProviderFamily::VaultTransit | ProviderFamily::OpenBaoTransit => {
                transit_key_uri(locator, version)
            },
            ProviderFamily::Kmip21 => {
                version.strip_prefix("sha256:").is_some_and(|digest| {
                    digest.len() == 64
                        && digest
                            .bytes()
                            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
                }) && kmip_key_uri(locator)
            },
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

fn kmip_key_uri(locator: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(locator) else {
        return false;
    };
    let Some(object) = url.path().strip_prefix("/objects/") else {
        return false;
    };
    url.scheme() == "kmip"
        && url.as_str() == locator
        && url.host_str().is_some_and(|host| {
            rustls_pki_types::ServerName::try_from(host.trim_matches(['[', ']'])).is_ok()
        })
        && url.port() != Some(0)
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && !object.is_empty()
        && object.len() <= 256
        && !matches!(object, "." | "..")
        && object
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn transit_key_uri(locator: &str, version: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(locator) else {
        return false;
    };
    let Some(path) = url.path().strip_prefix("/v1/") else {
        return false;
    };
    let Some((mount, name)) = path.rsplit_once("/keys/") else {
        return false;
    };
    let component = |part: &str| {
        !part.is_empty()
            && part.len() <= 128
            && !matches!(part, "." | "..")
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    };
    url.scheme() == "https"
        && url.as_str() == locator
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && mount.split('/').all(component)
        && component(name)
        && version.bytes().all(|byte| byte.is_ascii_digit())
        && !version.starts_with('0')
        && version.parse::<i32>().is_ok_and(|v| v > 0)
}

/// Google resource names route requests directly, so reject path normalization.
fn google_version_resource(locator: &str, version: &str) -> bool {
    let mut parts = locator.split('/');
    for label in ["projects", "locations", "keyRings", "cryptoKeys"] {
        if parts.next() != Some(label)
            || !parts.next().is_some_and(|part| {
                !part.is_empty()
                    && part.len() <= 128
                    && part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            })
        {
            return false;
        }
    }
    parts.next() == Some("cryptoKeyVersions")
        && parts.next() == Some(version)
        && !version.starts_with('0')
        && version.bytes().all(|byte| byte.is_ascii_digit())
        && parts.next().is_none()
}

/// Exact immutable AWS key ARN; aliases and partial key IDs cannot route calls.
fn aws_arn_parts(locator: &str) -> Option<(&str, &str, &str)> {
    let mut parts = locator.split(':');
    if parts.next()? != "arn" {
        return None;
    }
    let partition = parts.next()?;
    if !matches!(
        partition,
        "aws"
            | "aws-cn"
            | "aws-eusc"
            | "aws-us-gov"
            | "aws-iso"
            | "aws-iso-b"
            | "aws-iso-e"
            | "aws-iso-f"
    ) || parts.next()? != "kms"
    {
        return None;
    }
    let region = parts.next()?;
    if region.is_empty()
        || region.len() > 63
        || !region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return None;
    }
    // Pinned AWS partition model, without a list of individual regions.
    let prefix = match partition {
        "aws" => {
            let (geography, _) = region.split_once('-')?;
            if !matches!(
                geography,
                "us" | "eu" | "ap" | "sa" | "ca" | "me" | "af" | "il" | "mx"
            ) {
                return None;
            }
            geography
        },
        "aws-cn" => "cn",
        "aws-eusc" => "eusc-de",
        "aws-us-gov" => "us-gov",
        "aws-iso" => "us-iso",
        "aws-iso-b" => "us-isob",
        "aws-iso-e" => "eu-isoe",
        "aws-iso-f" => "us-isof",
        _ => return None,
    };
    let (area, number) = region
        .strip_prefix(prefix)?
        .strip_prefix('-')?
        .rsplit_once('-')?;
    if area.is_empty()
        || !area.bytes().all(|byte| byte.is_ascii_alphanumeric())
        || number.is_empty()
        || !number.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let account = parts.next()?;
    if account.len() != 12 || !account.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let key = parts.next()?.strip_prefix("key/")?;
    if parts.next().is_some() {
        return None;
    }
    let valid = if let Some(id) = key.strip_prefix("mrk-") {
        id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
    } else {
        key.len() == 36
            && key.bytes().enumerate().all(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            })
    };
    valid.then_some((partition, region, key))
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

/// Canonical Azure service DNS names only; aliases and URL normalization are refused.
fn azure_key_uri(locator: &str, version: &str, hsm: bool) -> bool {
    let Some((host, path)) = locator
        .strip_prefix("https://")
        .and_then(|s| s.split_once("/keys/"))
    else {
        return false;
    };
    let suffixes = if hsm {
        [
            ".managedhsm.azure.net",
            ".managedhsm.azure.cn",
            ".managedhsm.usgovcloudapi.net",
        ]
    } else {
        [
            ".vault.azure.net",
            ".vault.azure.cn",
            ".vault.usgovcloudapi.net",
        ]
    };
    let vault = suffixes.iter().find_map(|suffix| host.strip_suffix(suffix));
    vault.is_some_and(|vault| {
        (3..=24).contains(&vault.len())
            && !vault.starts_with('-')
            && !vault.ends_with('-')
            && !vault.contains("--")
            && vault
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    }) && path.split_once('/').is_some_and(|(name, actual)| {
        !name.is_empty()
            && name.len() <= 127
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && actual == version
    }) && version.len() == 32
        && version
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
