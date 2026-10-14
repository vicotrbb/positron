use crate::{MAX_OBJECT_BYTES, RepositoryFailure};
use aws_smithy_runtime_api::client::{
    http::{
        HttpClient, HttpConnector, HttpConnectorFuture, HttpConnectorSettings, SharedHttpClient,
        SharedHttpConnector,
    },
    orchestrator::HttpRequest,
    result::ConnectorError,
    runtime_components::RuntimeComponents,
};
use aws_smithy_types::body::SdkBody;
use http_body_util::{BodyExt, Limited};
use positron_kernel::NativeAwsResources;
use std::sync::Arc;
use tracing::instrument::WithSubscriber;

#[derive(Clone)]
pub(super) struct BoundedClient {
    inner: SharedHttpClient,
    owner: Arc<NativeAwsResources>,
    endpoint: String,
    data_prefixes: [String; 5],
}
impl BoundedClient {
    pub(super) fn new(
        inner: SharedHttpClient,
        owner: Arc<NativeAwsResources>,
        target: &crate::AwsS3Target,
    ) -> Self {
        Self {
            inner,
            owner,
            endpoint: format!("{}/", target.endpoint()),
            data_prefixes: data_prefixes(target),
        }
    }
}
struct BoundedConnector {
    inner: SharedHttpConnector,
    owner: Arc<NativeAwsResources>,
    endpoint: String,
    data_prefixes: [String; 5],
}
impl std::fmt::Debug for BoundedClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundedClient").finish_non_exhaustive()
    }
}
impl std::fmt::Debug for BoundedConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundedConnector").finish_non_exhaustive()
    }
}
fn data_prefixes(target: &crate::AwsS3Target) -> [String; 5] {
    ["identity", "o-", "h-", "u-", "m-"].map(|kind| {
        format!(
            "{}/{}/{}{kind}",
            target.endpoint(),
            target.bucket(),
            target.prefix()
        )
    })
}
fn response_limit(
    method: &str,
    uri: &str,
    endpoint: &str,
    prefixes: &[String],
    success: bool,
) -> usize {
    if !uri.starts_with(endpoint) {
        return 32768;
    }
    let (path, query) = uri.split_once('?').unwrap_or((uri, ""));
    let object_query = query
        .split('&')
        .filter(|part| !part.is_empty())
        .all(|part| {
            part.split_once('=').is_some_and(|(name, value)| {
                name == "versionId" || (name == "x-id" && value == "GetObject")
            })
        });
    if success
        && method == "GET"
        && object_query
        && prefixes.iter().any(|prefix| path.starts_with(prefix))
    {
        MAX_OBJECT_BYTES as usize + 65536
    } else {
        1_048_576
    }
}
impl HttpClient for BoundedClient {
    fn http_connector(
        &self,
        settings: &HttpConnectorSettings,
        runtime: &RuntimeComponents,
    ) -> SharedHttpConnector {
        SharedHttpConnector::new(BoundedConnector {
            inner: self.inner.http_connector(settings, runtime),
            owner: self.owner.clone(),
            endpoint: self.endpoint.clone(),
            data_prefixes: self.data_prefixes.clone(),
        })
    }
}
impl HttpConnector for BoundedConnector {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let method = request.method().to_owned();
        let uri = request.uri().to_owned();
        let endpoint = self.endpoint.clone();
        let prefixes = self.data_prefixes.clone();
        let future = self.inner.call(request);
        let owner = self.owner.clone();
        HttpConnectorFuture::new(async move {
            let mut response = future
                .with_subscriber(tracing::subscriber::NoSubscriber::default())
                .await?;
            let limit = response_limit(
                &method,
                &uri,
                &endpoint,
                &prefixes,
                response.status().is_success(),
            );
            if response
                .headers()
                .get("content-length")
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|length| length > limit as u64)
            {
                return Err(ConnectorError::other(
                    Box::new(RepositoryFailure::LimitExceeded),
                    None,
                ));
            }
            let body = std::mem::replace(response.body_mut(), SdkBody::empty());
            let body = SdkBody::from_body_1_x(body.map_frame(move |frame| {
                let _owner = &owner;
                frame
            }));
            *response.body_mut() = bounded(body, limit);
            Ok(response)
        })
    }
}
fn bounded(body: SdkBody, limit: usize) -> SdkBody {
    SdkBody::from_body_1_x(Limited::new(body, limit))
}

#[cfg(test)]
mod tests {
    use aws_smithy_types::body::SdkBody;
    use http_body_util::BodyExt;
    fn unknown_body(length: usize) -> SdkBody {
        SdkBody::from_body_1_x(http_body_util::StreamBody::new(futures_util::stream::once(
            async move {
                Ok::<_, std::io::Error>(http_body::Frame::data(bytes::Bytes::from(vec![0; length])))
            },
        )))
    }
    #[test]
    fn control_and_credential_responses_cannot_consume_the_object_body_budget() {
        let target = crate::AwsS3Target::new(
            "positron-example",
            "us-east-1",
            "https://s3.us-east-1.amazonaws.com",
            "123456789012",
            "owned/",
        )
        .expect("target");
        let prefixes = super::data_prefixes(&target);
        let endpoint = format!("{}/", target.endpoint());
        assert_eq!(
            super::response_limit(
                "GET",
                "https://s3.us-east-1.amazonaws.com/positron-example?versions",
                &endpoint,
                &prefixes,
                true
            ),
            1_048_576
        );
        assert_eq!(
            super::response_limit(
                "GET",
                "https://s3.us-east-1.amazonaws.com/positron-example/owned/m-123?uploadId=opaque",
                &endpoint,
                &prefixes,
                true
            ),
            1_048_576
        );
        assert_eq!(
            super::response_limit(
                "GET",
                "https://s3.us-east-1.amazonaws.com/positron-example/owned/o-123?x-id=GetObject",
                &endpoint,
                &prefixes,
                true
            ),
            crate::MAX_OBJECT_BYTES as usize + 65536
        );
        assert_eq!(
            super::response_limit(
                "GET",
                "https://s3.us-east-1.amazonaws.com/positron-example/owned/o-123",
                &endpoint,
                &prefixes,
                false
            ),
            1_048_576
        );
        assert_eq!(
            super::response_limit(
                "POST",
                "https://sts.us-east-1.amazonaws.com/",
                &endpoint,
                &prefixes,
                true
            ),
            32768
        );
    }
    #[tokio::test]
    async fn body_limit_errors_remain_typed_and_mutation_acknowledgements_unknown() {
        use aws_sdk_s3::error::SdkError;
        use aws_smithy_runtime_api::http::{Response, StatusCode};
        let error = super::bounded(unknown_body(257), 256)
            .collect()
            .await
            .expect_err("oversized read");
        let response = Response::new(StatusCode::try_from(200).expect("status"), SdkBody::empty());
        assert_eq!(
            super::super::failure::sdk(
                SdkError::<aws_sdk_s3::operation::get_object::GetObjectError>::response_error(
                    error, response
                ),
                false
            ),
            crate::RepositoryFailure::LimitExceeded
        );
        let error = super::bounded(unknown_body(257), 256)
            .collect()
            .await
            .expect_err("oversized mutation response");
        let response = Response::new(StatusCode::try_from(200).expect("status"), SdkBody::empty());
        assert_eq!(
            super::super::failure::sdk(
                SdkError::<aws_sdk_s3::operation::put_object::PutObjectError>::response_error(
                    error, response
                ),
                true
            ),
            crate::RepositoryFailure::OutcomeUnknown
        );
    }
    #[tokio::test]
    async fn unknown_length_bodies_are_bounded_before_deserialization() {
        assert!(
            super::bounded(unknown_body(257), 256)
                .collect()
                .await
                .is_err()
        );
        assert_eq!(
            super::bounded(unknown_body(256), 256)
                .collect()
                .await
                .expect("bounded body")
                .to_bytes()
                .len(),
            256
        );
    }
}
