//! Non-secret selectors for the shipped adapters; no remote key material.
use super::*;

pub enum NativeRootConfiguration {
    Aws(ProviderKeyUri),
    Google(ProviderKeyUri),
    AzureKeyVault {
        identity: ProviderKeyUri,
        authentication: NativeAzureAuthentication,
    },
    AzureManagedHsm {
        identity: ProviderKeyUri,
        authentication: NativeAzureAuthentication,
    },
    Vault {
        identity: ProviderKeyUri,
        authentication: TransitAuthentication,
        mount: String,
        trust_roots: Option<CredentialFileReference>,
    },
    OpenBao {
        identity: ProviderKeyUri,
        authentication: TransitAuthentication,
        mount: String,
        trust_roots: Option<CredentialFileReference>,
    },
    Kmip {
        identity: ProviderKeyUri,
        credentials: ProviderCredentialModel,
    },
}
pub enum NativeAzureAuthentication {
    ManagedIdentity(Option<AzureManagedIdentityId>),
    WorkloadIdentity(AzureWorkloadIdentity),
}
impl NativeRootConfiguration {
    pub fn identity(&self) -> &ProviderKeyUri {
        match self {
            Self::Aws(identity)
            | Self::Google(identity)
            | Self::AzureKeyVault { identity, .. }
            | Self::AzureManagedHsm { identity, .. }
            | Self::Vault { identity, .. }
            | Self::OpenBao { identity, .. }
            | Self::Kmip { identity, .. } => identity,
        }
    }
    pub fn required_resources(&self) -> ResourceAmounts {
        match self {
            Self::Aws(_) => AwsKmsKeyProvider::required_resources(),
            _ => GoogleCloudKmsKeyProvider::required_resources(),
        }
    }
    async fn construct(
        self,
        grant: ResourceReservation<'_>,
    ) -> Result<NativeRootKey, KeyProviderFailure> {
        match self {
            Self::Aws(identity) => AwsKmsKeyProvider::from_standard_chain(identity, grant)
                .await
                .map(NativeRootKey::Aws),
            Self::Google(identity) => {
                GoogleCloudKmsKeyProvider::from_application_default(identity, grant)
                    .await
                    .map(NativeRootKey::Google)
            },
            Self::Kmip {
                identity,
                credentials,
            } => Kmip21KeyProvider::from_native(identity, credentials, grant)
                .map(NativeRootKey::Kmip),
            Self::Vault {
                identity,
                authentication,
                mount,
                trust_roots,
            } => VaultTransitKeyProvider::from_native(
                identity,
                authentication,
                &mount,
                trust_roots.as_ref(),
                grant,
            )
            .map(NativeRootKey::Vault),
            Self::OpenBao {
                identity,
                authentication,
                mount,
                trust_roots,
            } => OpenBaoTransitKeyProvider::from_native(
                identity,
                authentication,
                &mount,
                trust_roots.as_ref(),
                grant,
            )
            .map(NativeRootKey::OpenBao),
            Self::AzureKeyVault {
                identity,
                authentication,
            } => match authentication {
                NativeAzureAuthentication::ManagedIdentity(selector) => {
                    AzureKeyVaultKeyProvider::from_managed_identity(identity, selector, grant)
                        .await
                        .map(NativeRootKey::AzureKeyVault)
                },
                NativeAzureAuthentication::WorkloadIdentity(selectors) => {
                    AzureKeyVaultKeyProvider::from_workload_identity(identity, selectors, grant)
                        .await
                        .map(NativeRootKey::AzureKeyVault)
                },
            },
            Self::AzureManagedHsm {
                identity,
                authentication,
            } => match authentication {
                NativeAzureAuthentication::ManagedIdentity(selector) => {
                    AzureManagedHsmKeyProvider::from_managed_identity(identity, selector, grant)
                        .await
                        .map(NativeRootKey::AzureManagedHsm)
                },
                NativeAzureAuthentication::WorkloadIdentity(selectors) => {
                    AzureManagedHsmKeyProvider::from_workload_identity(identity, selectors, grant)
                        .await
                        .map(NativeRootKey::AzureManagedHsm)
                },
            },
        }
    }
}
impl NativeRootProvider {
    /// Admission precedes SDK setup and credential reads. The runtime used to
    /// construct renewable native credentials remains owned by their worker.
    pub fn from_configuration(
        configuration: NativeRootConfiguration,
        native: ResourceReservation<'_>,
        bridge: ResourceReservation<'_>,
    ) -> Result<Self, KeyProviderFailure> {
        if !bridge.is_active()
            || ResourceDimension::ALL
                .iter()
                .any(|d| bridge.granted().get(*d) < Self::required_resources().get(*d))
            || !native.is_active()
            || ResourceDimension::ALL
                .iter()
                .any(|d| native.granted().get(*d) < configuration.required_resources().get(*d))
        {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        let (key, runtime) = std::thread::scope(|scope| {
            let task = std::thread::Builder::new()
                .name("positron-key-initialization".to_owned())
                .stack_size(1_048_576)
                .spawn_scoped(scope, move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| KeyProviderFailure::Unavailable)?;
                    let key = runtime.block_on(async {
                        tokio::time::timeout(
                            Duration::from_secs(15),
                            configuration.construct(native),
                        )
                        .await
                        .map_err(|_| KeyProviderFailure::Unavailable)?
                    })?;
                    Ok::<_, KeyProviderFailure>((key, runtime))
                })
                .map_err(|_| KeyProviderFailure::Unavailable)?;
            task.join().map_err(|_| KeyProviderFailure::Unavailable)?
        })?;
        let identity = dispatch!(&key, provider => provider.identity().clone());
        let credentials = dispatch!(&key, provider => provider.credential_model().clone());
        let worker = worker::start_with_runtime(key, bridge.transfer(), Some(runtime))?;
        Ok(Self {
            identity,
            credentials,
            worker: Arc::new(Mutex::new(worker)),
        })
    }
}
