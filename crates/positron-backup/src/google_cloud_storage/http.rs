use super::{GoogleCloudStorageRepository, protocol};
use crate::RepositoryFailure;
use google_cloud_auth::{credentials::CacheableResource, native};
use http::{HeaderMap, HeaderValue, Method};
use tracing::instrument::WithSubscriber;
use zeroize::Zeroizing;

pub(super) fn native_failure(error: native::Error, mutation: bool) -> RepositoryFailure {
    match error {
        native::Error::LimitExceeded => RepositoryFailure::LimitExceeded,
        native::Error::PermissionDenied => RepositoryFailure::PermissionDenied,
        native::Error::InvalidConfiguration => RepositoryFailure::InvalidInput,
        native::Error::NotFound => RepositoryFailure::NotFound,
        native::Error::Unavailable if mutation => RepositoryFailure::OutcomeUnknown,
        native::Error::Unavailable => RepositoryFailure::StorageUnavailable,
    }
}
pub(super) fn response_failure(response: &native::Response, mutation: bool) -> RepositoryFailure {
    protocol::status(
        response.status.as_u16(),
        mutation,
        response
            .headers
            .get(http::header::RETRY_AFTER)
            .and_then(|header| header.to_str().ok()),
    )
}
impl GoogleCloudStorageRepository {
    pub(super) async fn request(
        &self,
        method: Method,
        url: String,
        mut headers: HeaderMap,
        body: Vec<u8>,
        maximum: usize,
    ) -> Result<native::Response, RepositoryFailure> {
        tokio::runtime::Handle::try_current().map_err(|_| RepositoryFailure::InvalidInput)?;
        self.faults
            .at(super::GoogleCloudStorageFaultPoint::BeforeRequest)?;
        let mutation = !matches!(method, Method::GET | Method::HEAD);
        let request = async {
            let native = self
                .credentials
                .headers(http::Extensions::new())
                .with_subscriber(tracing::subscriber::NoSubscriber::default())
                .await
                .map_err(|error| {
                    if error.is_transient() {
                        RepositoryFailure::StorageUnavailable
                    } else {
                        RepositoryFailure::PermissionDenied
                    }
                })?;
            let CacheableResource::New { data, .. } = native else {
                return Err(RepositoryFailure::StorageUnavailable);
            };
            for (name, value) in data.iter() {
                headers.insert(name.clone(), value.clone());
            }
            for value in headers.values_mut() {
                value.set_sensitive(true);
            }
            let request = native::Request {
                method,
                url,
                headers,
                body: Zeroizing::new(body),
            };
            #[cfg(feature = "test-support")]
            if let Some(address) = self.simulation_address {
                return self
                    .runtime
                    .repository_simulation_http(request, address, maximum)
                    .with_subscriber(tracing::subscriber::NoSubscriber::default())
                    .await
                    .map_err(|e| native_failure(e, mutation));
            }
            self.runtime
                .repository_http(request, maximum)
                .with_subscriber(tracing::subscriber::NoSubscriber::default())
                .await
                .map_err(|e| native_failure(e, mutation))
        };
        tokio::time::timeout(std::time::Duration::from_secs(15), request)
            .await
            .map_err(|_| {
                if mutation {
                    RepositoryFailure::OutcomeUnknown
                } else {
                    RepositoryFailure::StorageUnavailable
                }
            })?
    }
    pub(super) async fn checked(
        &self,
        method: Method,
        url: String,
        headers: HeaderMap,
        body: Vec<u8>,
        maximum: usize,
    ) -> Result<native::Response, RepositoryFailure> {
        let mutation = !matches!(method, Method::GET | Method::HEAD);
        let response = self.request(method, url, headers, body, maximum).await?;
        if !response.status.is_success() {
            return Err(response_failure(&response, mutation));
        }
        Ok(response)
    }
    pub(super) fn object_url(&self, key: &str) -> String {
        format!(
            "https://storage.googleapis.com/storage/v1/b/{}/o/{}",
            self.target.bucket(),
            protocol::escape(key)
        )
    }
    pub(super) fn upload_url(&self, key: &str, generation: u64) -> String {
        format!(
            "https://storage.googleapis.com/upload/storage/v1/b/{}/o?uploadType=media&name={}&ifGenerationMatch={generation}",
            self.target.bucket(),
            protocol::escape(key)
        )
    }
    pub(super) fn data_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        headers
    }
}
