//! Native Azure Storage managed identity and admitted Blob transport.
use super::*;
use google_cloud_auth::native;
/// Owns Azure credentials and native transport under one Repository grant.
pub struct NativeAzureRepositoryRuntime {
    credentials: Option<Arc<dyn TokenCredential>>,
    runtime: Arc<super::super::google::native::NativeRuntime>,
    endpoint: String,
    #[cfg(feature = "test-support")]
    simulation: Option<std::net::SocketAddr>,
}
impl NativeAzureRepositoryRuntime {
    pub fn from_resources(
        resources: Arc<crate::NativeAwsResources>,
        account: &str,
        container: &str,
    ) -> Result<Self, KeyProviderFailure> {
        if !resources.authorizes_repository_transport() {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        let endpoint = Self::endpoint(account, container)?;
        let runtime = super::super::google::native::NativeRuntime::from_resources(resources)?;
        let identity = Arc::new(identity::IdentityRuntime(
            runtime.clone(),
            std::sync::OnceLock::new(),
            "https://storage.azure.com",
        ));
        let credentials =
            tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
                azure_identity::ManagedIdentityCredential::new(Some(
                    azure_identity::ManagedIdentityCredentialOptions {
                        user_assigned_id: None,
                        native_runtime: Some(identity.clone()),
                        client_options: azure_core::http::ClientOptions {
                            transport: Some(azure_core::http::Transport::new(identity)),
                            ..Default::default()
                        },
                    },
                ))
            })
            .map_err(credential_failure)?;
        Ok(Self {
            credentials: Some(credentials),
            runtime,
            endpoint,
            #[cfg(feature = "test-support")]
            simulation: None,
        })
    }
    fn endpoint(account: &str, container: &str) -> Result<String, KeyProviderFailure> {
        if !(3..=24).contains(&account.len())
            || !account
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            || !(3..=63).contains(&container.len())
            || !container
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(KeyProviderFailure::InvalidConfiguration);
        }
        Ok(format!(
            "https://{account}.blob.core.windows.net/{container}/"
        ))
    }
    #[cfg(feature = "test-support")]
    pub fn from_local_simulator(
        resources: Arc<crate::NativeAwsResources>,
        account: &str,
        container: &str,
        address: std::net::SocketAddr,
    ) -> Result<Self, KeyProviderFailure> {
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(KeyProviderFailure::InvalidConfiguration);
        }
        Ok(Self {
            credentials: None,
            runtime: super::super::google::native::NativeRuntime::from_resources(resources)?,
            endpoint: Self::endpoint(account, container)?,
            simulation: Some(address),
        })
    }
    pub async fn request(
        &self,
        mut request: native::Request,
        maximum: usize,
    ) -> native::Result<native::Response> {
        let parsed = azure_core::http::Url::parse(&request.url)
            .map_err(|_| native::Error::InvalidConfiguration)?;
        let origin = self
            .endpoint
            .split('/')
            .take(3)
            .collect::<Vec<_>>()
            .join("/");
        let service = parsed.as_str() == format!("{origin}/?restype=service&comp=properties")
            && request.method == http::Method::GET
            && request.body.is_empty();
        if (!parsed.as_str().starts_with(&self.endpoint) && !service)
            || parsed.fragment().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || request.headers.contains_key(http::header::AUTHORIZATION)
        {
            return Err(native::Error::PermissionDenied);
        }
        if let Some(credentials) = &self.credentials {
            let token = credentials
                .get_token(&["https://storage.azure.com/.default"], None)
                .with_subscriber(tracing::subscriber::NoSubscriber::default())
                .await
                .map_err(|error| match credential_failure(error) {
                    KeyProviderFailure::Unavailable | KeyProviderFailure::Ambiguous => {
                        native::Error::Unavailable
                    },
                    KeyProviderFailure::LimitExceeded => native::Error::LimitExceeded,
                    KeyProviderFailure::InvalidConfiguration => native::Error::InvalidConfiguration,
                    _ => native::Error::PermissionDenied,
                })?;
            if token.token.secret().is_empty() || token.token.secret().len() > 8192 {
                return Err(native::Error::PermissionDenied);
            }
            let authorization = Zeroizing::new(format!("Bearer {}", token.token.secret()));
            let mut value = http::HeaderValue::from_str(&authorization)
                .map_err(|_| native::Error::InvalidConfiguration)?;
            value.set_sensitive(true);
            request.headers.insert(http::header::AUTHORIZATION, value);
        }
        #[cfg(feature = "test-support")]
        if let Some(address) = self.simulation {
            let path = parsed.path();
            request.url = format!("http://{address}{path}");
            if let Some(query) = parsed.query() {
                request.url.push('?');
                request.url.push_str(query);
            }
            return self.runtime.azure_repository_http(request, maximum).await;
        }
        self.runtime.azure_repository_http(request, maximum).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn azure_repository_identity_uses_exact_storage_audience_and_native_endpoint()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            NativeAzureRepositoryRuntime::endpoint("positronbackup", "backups")?,
            "https://positronbackup.blob.core.windows.net/backups/"
        );
        for (account, container) in [
            ("evil.example", "backups"),
            ("UPPER", "backups"),
            ("account", "../other"),
            ("ab", "backups"),
        ] {
            assert!(NativeAzureRepositoryRuntime::endpoint(account, container).is_err());
        }
        let base = azure_core::http::Url::parse("http://127.0.0.1:8081/token")?;
        let endpoint = super::super::local_endpoint::LocalEndpoint::new(
            &base,
            None,
            "https://storage.azure.com",
        )?;
        let storage = azure_core::http::Request::new(
            azure_core::http::Url::parse(
                "http://127.0.0.1:8081/token?api-version=2019-08-01&resource=https%3A%2F%2Fstorage.azure.com",
            )?,
            azure_core::http::Method::Get,
        );
        endpoint.validate(&storage)?;
        let vault = azure_core::http::Request::new(
            azure_core::http::Url::parse(
                "http://127.0.0.1:8081/token?api-version=2019-08-01&resource=https%3A%2F%2Fvault.azure.net",
            )?,
            azure_core::http::Method::Get,
        );
        assert!(endpoint.validate(&vault).is_err());
        Ok(())
    }
}
