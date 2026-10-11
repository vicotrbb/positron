//! Official SDK identity with the existing admitted native transport and files.
use super::super::google::native::NativeRuntime;
use super::*;
use azure_core::http::{
    AsyncRawResponse, Body, HttpClient, Request, StatusCode, Transport, headers::Headers,
};
use google_cloud_auth::native::{Request as NativeRequest, Runtime};

pub(super) struct IdentityRuntime(
    pub(super) Arc<NativeRuntime>,
    pub(super) std::sync::OnceLock<super::local_endpoint::LocalEndpoint>,
    pub(super) &'static str,
);
impl std::fmt::Debug for IdentityRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IdentityRuntime { admitted Azure identity }")
    }
}
impl azure_identity::native::Runtime for IdentityRuntime {
    fn bind_app_service_endpoint(
        &self,
        endpoint: &azure_core::http::Url,
        selector: Option<(&str, &str)>,
    ) -> azure_core::Result<()> {
        let capability = super::local_endpoint::LocalEndpoint::new(endpoint, selector, self.2)
            .map_err(sdk_error)?;
        self.1
            .set(capability)
            .map_err(|_| sdk_error(KeyProviderFailure::InvalidConfiguration))
    }
    fn read_file(&self, path: &std::path::Path) -> std::io::Result<String> {
        let mut bytes = self
            .0
            .read_file(path)
            .map_err(|error| std::io::Error::other(super::super::google::native_failure(error)))?;
        std::str::from_utf8(&bytes)
            .map_err(|_| std::io::Error::other("native identity file invalid"))?;
        String::from_utf8(std::mem::take(&mut *bytes))
            .map_err(|_| std::io::Error::other("native identity file invalid"))
    }
}
fn sdk_error(failure: KeyProviderFailure) -> azure_core::Error {
    azure_core::Error::with_error(
        azure_core::error::ErrorKind::Other,
        failure,
        "native identity operation failed",
    )
}
#[async_trait::async_trait]
impl HttpClient for IdentityRuntime {
    async fn execute_request(&self, request: &Request) -> azure_core::Result<AsyncRawResponse> {
        let local = self.1.get();
        if let Some(endpoint) = local {
            endpoint.validate(request).map_err(sdk_error)?;
        }
        let body = match request.body() {
            Body::Bytes(bytes) if bytes.len() <= 131_072 => Zeroizing::new(bytes.to_vec()),
            _ => return Err(sdk_error(KeyProviderFailure::LimitExceeded)),
        };
        let mut headers = http::HeaderMap::new();
        let mut size = 0usize;
        for (name, value) in request.headers().iter() {
            size = size
                .checked_add(name.as_str().len())
                .and_then(|size| size.checked_add(value.as_str().len()))
                .ok_or_else(|| sdk_error(KeyProviderFailure::LimitExceeded))?;
            if size > 131_072 {
                return Err(sdk_error(KeyProviderFailure::LimitExceeded));
            }
            headers.insert(
                http::HeaderName::from_bytes(name.as_str().as_bytes())
                    .map_err(|_| sdk_error(KeyProviderFailure::InvalidConfiguration))?,
                http::HeaderValue::from_str(value.as_str())
                    .map_err(|_| sdk_error(KeyProviderFailure::InvalidConfiguration))?,
            );
        }
        let method = http::Method::from_bytes(request.method().as_ref().as_bytes())
            .map_err(|_| sdk_error(KeyProviderFailure::InvalidConfiguration))?;
        let request = NativeRequest {
            method,
            url: request.url().to_string(),
            headers,
            body,
        };
        let reply = match local {
            Some(_) => self.0.app_service_http(request).await,
            None => self.0.http(request).await,
        }
        .map_err(|e| sdk_error(super::super::google::native_failure(e)))?;
        let mut headers = Headers::new();
        for (name, value) in &reply.headers {
            headers.insert(
                name.as_str().to_owned(),
                value
                    .to_str()
                    .map_err(|_| sdk_error(KeyProviderFailure::ContextMismatch))?
                    .to_owned(),
            );
        }
        Ok(AsyncRawResponse::from_bytes(
            StatusCode::from(reply.status.as_u16()),
            headers,
            azure_core::Bytes::from_owner(reply.body),
        ))
    }
}
impl IdentityRuntime {
    pub(super) fn client_options(
        self: &Arc<Self>,
        identity: &ProviderKeyUri,
    ) -> azure_core::http::ClientOptions {
        use azure_core::cloud::CloudConfiguration;
        let cloud = if identity.locator().contains(".vault.azure.cn/")
            || identity.locator().contains(".managedhsm.azure.cn/")
        {
            CloudConfiguration::AzureChina
        } else if identity.locator().contains(".vault.usgovcloudapi.net/")
            || identity
                .locator()
                .contains(".managedhsm.usgovcloudapi.net/")
        {
            CloudConfiguration::AzureGovernment
        } else {
            CloudConfiguration::AzurePublic
        };
        azure_core::http::ClientOptions {
            transport: Some(Transport::new(self.clone())),
            cloud: Some(Arc::new(cloud)),
            ..Default::default()
        }
    }
}
