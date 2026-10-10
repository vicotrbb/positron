use super::{KeyProviderFailure, ProviderFamily};
use std::path::{Path, PathBuf};

/// Reference only. Adapters reopen and verify custody before consuming secrets;
/// credentials are never copied into configuration, envelopes, or diagnostics.
#[derive(Clone, Eq, PartialEq)]
pub struct CredentialFileReference(PathBuf);
impl CredentialFileReference {
    pub fn new(path: &Path) -> Result<Self, KeyProviderFailure> {
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
            || path.as_os_str().len() > 4096
        {
            return Err(KeyProviderFailure::InvalidConfiguration);
        }
        Ok(Self(path.to_owned()))
    }
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }
}
impl std::fmt::Debug for CredentialFileReference {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CredentialFileReference { protected external reference }")
    }
}

/// Renewable Transit machine authentication. A JWT is consumed from its
/// protected projected file; no token string is accepted through this model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransitAuthentication {
    Kubernetes {
        role: String,
        jwt_file: CredentialFileReference,
    },
    Jwt {
        role: String,
        jwt_file: CredentialFileReference,
    },
    ProtectedTokenFile(CredentialFileReference),
}

/// Non-secret selection of the provider's native renewable credential chain.
/// There is deliberately no static secret, command, webhook, or insecure TLS field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderCredentialModel {
    LocalFile,
    AwsStandardChain,
    GoogleApplicationDefault,
    AzureManagedIdentity,
    AzureWorkloadIdentity,
    Transit(TransitAuthentication),
    KmipMutualTls {
        certificate: CredentialFileReference,
        private_key: CredentialFileReference,
        trust_roots: CredentialFileReference,
    },
}
impl ProviderCredentialModel {
    pub fn validate(&self, family: ProviderFamily) -> Result<(), KeyProviderFailure> {
        let compatible = matches!(
            (family, self),
            (ProviderFamily::LocalFile, Self::LocalFile)
                | (ProviderFamily::AwsKms, Self::AwsStandardChain)
                | (
                    ProviderFamily::GoogleCloudKms,
                    Self::GoogleApplicationDefault
                )
                | (
                    ProviderFamily::AzureKeyVault | ProviderFamily::AzureManagedHsm,
                    Self::AzureManagedIdentity | Self::AzureWorkloadIdentity
                )
                | (
                    ProviderFamily::VaultTransit | ProviderFamily::OpenBaoTransit,
                    Self::Transit(_)
                )
                | (ProviderFamily::Kmip21, Self::KmipMutualTls { .. })
        );
        let valid_role = match self {
            Self::Transit(
                TransitAuthentication::Kubernetes { role, .. }
                | TransitAuthentication::Jwt { role, .. },
            ) => {
                !role.is_empty()
                    && role.len() <= 128
                    && role.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                    })
            },
            _ => true,
        };
        if compatible && valid_role {
            Ok(())
        } else {
            Err(KeyProviderFailure::InvalidConfiguration)
        }
    }
}
