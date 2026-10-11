//! The native SDK identity chain's bounded transport, including metadata roles.
use super::*;
use aws_smithy_runtime_api::client::http::{
    HttpClient, HttpConnector, HttpConnectorFuture, HttpConnectorSettings, SharedHttpConnector,
};
use aws_smithy_runtime_api::client::orchestrator::HttpRequest;
use aws_smithy_runtime_api::client::result::ConnectorError;
use aws_smithy_runtime_api::client::runtime_components::RuntimeComponents;
use aws_smithy_types::body::SdkBody;

fn client_builder(dns: dns::NativeDns) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .https_only(false)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(0)
        .http1_only()
        .dns_resolver(std::sync::Arc::new(dns))
}
pub(super) fn client(dns: dns::NativeDns) -> Result<reqwest::Client, KeyProviderFailure> {
    client_builder(dns)
        .build()
        .map_err(|_| KeyProviderFailure::InvalidConfiguration)
}

pub(super) fn checked_uri(value: &str) -> Result<reqwest::Url, KeyProviderFailure> {
    if value.len() > 4096 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    let uri = reqwest::Url::parse(value).map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
    if !matches!(uri.scheme(), "https" | "http")
        || !uri.username().is_empty()
        || uri.password().is_some()
        || uri.fragment().is_some()
    {
        return Err(KeyProviderFailure::InvalidConfiguration);
    }
    Ok(uri)
}

pub(super) fn local_addresses(
    addresses: &[std::net::SocketAddr],
) -> Result<(), KeyProviderFailure> {
    if addresses.is_empty() || addresses.len() > 16 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    if addresses.iter().any(|address| !match address.ip() {
        std::net::IpAddr::V4(ip) => {
            ip.is_loopback()
                || matches!(
                    ip.octets(),
                    [169, 254, 169, 254] | [169, 254, 170, 2] | [169, 254, 170, 23]
                )
        },
        std::net::IpAddr::V6(ip) => {
            ip.is_loopback()
                || matches!(
                    ip.segments(),
                    [0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254] | [0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x23]
                )
        },
    }) {
        return Err(KeyProviderFailure::InvalidConfiguration);
    }
    Ok(())
}
/// Bounds the entire response before AWS's non-streaming deserializer sees it.
pub(super) async fn collect(
    mut response: reqwest::Response,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, KeyProviderFailure> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(maximum));
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| KeyProviderFailure::Unavailable)?
    {
        if chunk.len() > maximum.saturating_sub(bytes.len()) {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
#[derive(Clone)]
pub(super) struct AwsCredentialHttp {
    client: reqwest::Client,
    dns: dns::NativeDns,
}
impl std::fmt::Debug for AwsCredentialHttp {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AwsCredentialHttp { bounded native identity transport }")
    }
}
impl AwsCredentialHttp {
    pub(super) fn new(client: reqwest::Client, dns: dns::NativeDns) -> Self {
        Self { client, dns }
    }
    async fn call_native(
        &self,
        request: HttpRequest,
    ) -> Result<aws_smithy_runtime_api::client::orchestrator::HttpResponse, KeyProviderFailure>
    {
        const MAXIMUM: usize = 131_072;
        let uri = checked_uri(request.uri())?;
        request
            .headers()
            .iter()
            .try_fold(0usize, |used, (name, value)| {
                used.checked_add(name.len())
                    .and_then(|used| used.checked_add(value.len()))
                    .filter(|used| *used <= MAXIMUM)
                    .ok_or(KeyProviderFailure::LimitExceeded)
            })?;
        let request = request
            .try_into_http1x()
            .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
        let (mut parts, body) = request.into_parts();
        for value in parts.headers.values_mut() {
            value.set_sensitive(true);
        }
        let bytes = body.bytes().ok_or(KeyProviderFailure::LimitExceeded)?;
        if bytes.len() > MAXIMUM {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        let body = bytes::Bytes::from_owner(Zeroizing::new(bytes.to_vec()));
        let client = if uri.scheme() == "http" {
            let host = uri
                .host_str()
                .ok_or(KeyProviderFailure::InvalidConfiguration)?;
            let ip = host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>();
            let addresses = match ip {
                Ok(ip) => vec![std::net::SocketAddr::new(ip, 0)],
                Err(_) => self.dns.addresses(host).await?,
            };
            local_addresses(&addresses)?;
            client_builder(self.dns.clone())
                .resolve_to_addrs(host, &addresses)
                .build()
                .map_err(|_| KeyProviderFailure::InvalidConfiguration)?
        } else {
            self.client.clone()
        };
        let response = client
            .request(parts.method, uri)
            .headers(parts.headers)
            .body(body)
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|_| KeyProviderFailure::Unavailable)?;
        let mut result = http::Response::builder().status(response.status());
        response
            .headers()
            .iter()
            .try_fold(0usize, |used, (name, value)| {
                used.checked_add(name.as_str().len())
                    .and_then(|used| used.checked_add(value.len()))
                    .filter(|used| *used <= MAXIMUM)
                    .ok_or(KeyProviderFailure::LimitExceeded)
            })?;
        for (name, value) in response.headers() {
            result = result.header(name, value);
        }
        let bytes = collect(response, MAXIMUM).await?;
        let response = result
            .body(SdkBody::from(bytes::Bytes::from_owner(bytes)))
            .map_err(|_| KeyProviderFailure::Unavailable)?;
        response
            .try_into()
            .map_err(|_| KeyProviderFailure::Unavailable)
    }
}
impl HttpClient for AwsCredentialHttp {
    fn http_connector(
        &self,
        _settings: &HttpConnectorSettings,
        _components: &RuntimeComponents,
    ) -> SharedHttpConnector {
        SharedHttpConnector::new(self.clone())
    }
}
impl HttpConnector for AwsCredentialHttp {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let connector = self.clone();
        HttpConnectorFuture::new(async move {
            connector
                .call_native(request)
                .with_subscriber(tracing::subscriber::NoSubscriber::default())
                .await
                .map_err(|failure| ConnectorError::other(Box::new(failure), None))
        })
    }
}
