use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use google_cloud_auth::native;
use std::sync::Mutex;
struct Transcript {
    replies: Mutex<std::collections::VecDeque<native::Response>>,
    requests: Mutex<Vec<native::Request>>,
    wait_when_exhausted: bool,
}
impl std::fmt::Debug for Transcript {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PublishedTranscript")
    }
}
impl Runtime for Transcript {
    fn read_file(&self, _: &std::path::Path) -> native::Result<Zeroizing<Vec<u8>>> {
        Err(native::Error::InvalidConfiguration)
    }
    fn http(&self, request: native::Request) -> native::BoxFuture<'_, native::Response> {
        Box::pin(async move {
            self.requests
                .lock()
                .map_err(|_| native::Error::Unavailable)?
                .push(request);
            let reply = self
                .replies
                .lock()
                .map_err(|_| native::Error::Unavailable)?
                .pop_front();
            match reply {
                Some(reply) => Ok(reply),
                None if self.wait_when_exhausted => std::future::pending().await,
                None => Err(native::Error::Unavailable),
            }
        })
    }
    fn execute<'a>(
        &'a self,
        _: &'a str,
        _: &'a [String],
        _: Duration,
    ) -> native::BoxFuture<'a, Zeroizing<Vec<u8>>> {
        Box::pin(async { Err(native::Error::InvalidConfiguration) })
    }
    fn sha256(&self, _: &[u8]) -> native::Result<[u8; 32]> {
        Err(native::Error::InvalidConfiguration)
    }
    fn hmac_sha256(&self, _: &[u8], _: &[u8]) -> native::Result<[u8; 32]> {
        Err(native::Error::InvalidConfiguration)
    }
    fn rsa_sign(&self, _: &[u8], _: &[u8]) -> native::Result<Vec<u8>> {
        Err(native::Error::InvalidConfiguration)
    }
    fn spawn(
        &self,
        _: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>,
    ) -> native::Result<tokio::task::JoinHandle<()>> {
        Err(native::Error::InvalidConfiguration)
    }
}
#[derive(Debug)]
struct FictionalIdentity;
#[async_trait::async_trait]
impl TokenCredential for FictionalIdentity {
    async fn get_token(
        &self,
        _: &[&str],
        _: Option<azure_core::credentials::TokenRequestOptions<'_>>,
    ) -> azure_core::Result<azure_core::credentials::AccessToken> {
        Ok(azure_core::credentials::AccessToken::new(
            "fictional-native-token",
            azure_core::time::OffsetDateTime::now_utc() + azure_core::time::Duration::hours(1),
        ))
    }
}
fn uri() -> ProviderKeyUri {
    ProviderKeyUri::new(
        ProviderFamily::AzureKeyVault,
        "https://fixture.vault.azure.net/keys/root/0123456789abcdef0123456789abcdef",
        "0123456789abcdef0123456789abcdef",
    )
    .expect("valid published URI shape")
}
fn context() -> EnvelopeContext {
    EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1).expect("valid context")
}
fn metadata() -> Vec<u8> {
    format!(r#"{{"key":{{"kid":"{}","kty":"RSA","key_ops":["wrapKey","unwrapKey"],"n":"{}","e":"AQAB"}},"attributes":{{"enabled":true}}}}"#,uri().locator(),URL_SAFE_NO_PAD.encode([0xff;256])).into_bytes()
}
fn result(value: &[u8]) -> Vec<u8> {
    format!(
        r#"{{"kid":"{}","value":"{}"}}"#,
        uri().locator(),
        URL_SAFE_NO_PAD.encode(value)
    )
    .into_bytes()
}
fn fixture(bodies: Vec<Vec<u8>>) -> AzureProvider {
    AzureProvider {
        identity: uri(),
        credentials: Arc::new(FictionalIdentity),
        credential_model: ProviderCredentialModel::AzureManagedIdentity,
        runtime: Arc::new(Transcript {
            replies: Mutex::new(
                bodies
                    .into_iter()
                    .map(|body| native::Response {
                        status: http::StatusCode::OK,
                        headers: http::HeaderMap::new(),
                        body: Zeroizing::new(body),
                    })
                    .collect(),
            ),
            requests: Mutex::new(Vec::new()),
            wait_when_exhausted: false,
        }),
        active: AtomicBool::new(false),
    }
}

fn payload(context: EnvelopeContext, identity: &ProviderKeyUri) -> SecretWrappedKeyPayload {
    SecretWrappedKeyPayload::encode(&SecretKek::from_owned(Box::new([9; 32])), context, identity)
        .expect("bounded canonical fixture")
}

mod identity;
mod lifecycle;
mod wire;

mod hsm;
