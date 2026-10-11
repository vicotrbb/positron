use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

mod adc;
mod crypto;
mod lifecycle;
mod wire;

#[derive(Debug, Default)]
struct RejectedNativeAdc {
    reads: AtomicUsize,
    allow_crypto: bool,
    hash_calls: AtomicUsize,
    hmac_calls: AtomicUsize,
    execute_calls: AtomicUsize,
    execute_output: Option<Vec<u8>>,
    file_absent: bool,
    adc: Option<Vec<u8>>,
    subject: Option<Vec<u8>>,
    rsa_calls: AtomicUsize,
    allow_rsa: bool,
    authorized_user: bool,
    allow_tasks: bool,
    spawn_attempts: AtomicUsize,
    http_calls: AtomicUsize,
    pending_http: bool,
    tasks: Arc<AtomicUsize>,
    wire: std::sync::Mutex<std::collections::VecDeque<google_cloud_auth::native::Response>>,
    requests: std::sync::Mutex<Vec<(String, http::HeaderMap)>>,
}
impl google_cloud_auth::native::Runtime for RejectedNativeAdc {
    fn read_file(
        &self,
        path: &std::path::Path,
    ) -> google_cloud_auth::native::Result<Zeroizing<Vec<u8>>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if path == std::path::Path::new("/fictional/native-subject") {
            return self
                .subject
                .clone()
                .map(Zeroizing::new)
                .ok_or(google_cloud_auth::native::Error::NotFound);
        }
        if self.file_absent {
            return Err(google_cloud_auth::native::Error::NotFound);
        }
        if let Some(adc) = &self.adc {
            return Ok(Zeroizing::new(adc.clone()));
        }
        Ok(Zeroizing::new(if self.authorized_user {
            br#"{"type":"authorized_user","client_id":"native-client","client_secret":"native-secret-canary","refresh_token":"native-refresh-canary","token_uri":"http://127.0.0.1:9/isolated-native-identity"}"#.to_vec()
        } else {
            b"invalid-native-adc-json".to_vec()
        }))
    }
    fn http(
        &self,
        request: google_cloud_auth::native::Request,
    ) -> google_cloud_auth::native::BoxFuture<'_, google_cloud_auth::native::Response> {
        self.http_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if self.pending_http {
                return std::future::pending().await;
            }
            assert!(!format!("{request:?}").contains("canary"));
            self.requests
                .lock()
                .expect("test request mutex")
                .push((request.url.clone(), request.headers.clone()));
            if let Some(reply) = self.wire.lock().expect("test response mutex").pop_front() {
                return Ok(reply);
            }
            Ok(google_cloud_auth::native::Response { status: http::StatusCode::OK, headers: http::HeaderMap::new(), body: Zeroizing::new(br#"{"access_token":"native-access-canary","token_type":"Bearer","expires_in":3600}"#.to_vec()) })
        })
    }
    fn execute<'a>(
        &'a self,
        _: &'a str,
        _: &'a [String],
        _: std::time::Duration,
    ) -> google_cloud_auth::native::BoxFuture<'a, Zeroizing<Vec<u8>>> {
        self.execute_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            self.execute_output
                .clone()
                .map(Zeroizing::new)
                .ok_or(google_cloud_auth::native::Error::Unavailable)
        })
    }
    fn sha256(&self, _: &[u8]) -> google_cloud_auth::native::Result<[u8; 32]> {
        self.hash_calls.fetch_add(1, Ordering::SeqCst);
        if self.allow_crypto {
            Ok([7; 32])
        } else {
            Err(google_cloud_auth::native::Error::Unavailable)
        }
    }
    fn hmac_sha256(&self, _: &[u8], _: &[u8]) -> google_cloud_auth::native::Result<[u8; 32]> {
        self.hmac_calls.fetch_add(1, Ordering::SeqCst);
        if self.allow_crypto {
            Ok([8; 32])
        } else {
            Err(google_cloud_auth::native::Error::Unavailable)
        }
    }
    fn rsa_sign(&self, _: &[u8], _: &[u8]) -> google_cloud_auth::native::Result<Vec<u8>> {
        self.rsa_calls.fetch_add(1, Ordering::SeqCst);
        if self.allow_rsa {
            Ok(vec![7; 32])
        } else {
            Err(google_cloud_auth::native::Error::Unavailable)
        }
    }
    fn spawn(
        &self,
        work: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>,
    ) -> google_cloud_auth::native::Result<tokio::task::JoinHandle<()>> {
        self.spawn_attempts.fetch_add(1, Ordering::SeqCst);
        if !self.allow_tasks {
            return Err(google_cloud_auth::native::Error::LimitExceeded);
        }
        struct Task(Arc<AtomicUsize>);
        impl Drop for Task {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        self.tasks.fetch_add(1, Ordering::SeqCst);
        let task = Task(self.tasks.clone());
        Ok(tokio::spawn(async move {
            let _task = task;
            work.await;
        }))
    }
}

fn identity() -> Result<ProviderKeyUri, KeyProviderFailure> {
    ProviderKeyUri::new(
        ProviderFamily::GoogleCloudKms,
        "projects/project-1/locations/us-central1/keyRings/ring/cryptoKeys/root/cryptoKeyVersions/7",
        "7",
    )
}

#[derive(Debug)]
struct FixtureCredentials;
impl google_cloud_auth::credentials::CredentialsProvider for FixtureCredentials {
    async fn headers(
        &self,
        _: http::Extensions,
    ) -> Result<
        google_cloud_auth::credentials::CacheableResource<http::HeaderMap>,
        google_cloud_auth::errors::CredentialsError,
    > {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "authorization",
            http::HeaderValue::from_static("Bearer fixture-canary"),
        );
        headers.insert(
            "x-goog-user-project",
            http::HeaderValue::from_static("fixture-quota-project"),
        );
        Ok(google_cloud_auth::credentials::CacheableResource::New {
            entity_tag: google_cloud_auth::credentials::EntityTag::new(),
            data: headers,
        })
    }
    async fn universe_domain(&self) -> Option<String> {
        None
    }
}

#[derive(Debug)]
struct PendingCredentials;
impl google_cloud_auth::credentials::CredentialsProvider for PendingCredentials {
    async fn headers(
        &self,
        _: http::Extensions,
    ) -> Result<
        google_cloud_auth::credentials::CacheableResource<http::HeaderMap>,
        google_cloud_auth::errors::CredentialsError,
    > {
        std::future::pending().await
    }
    async fn universe_domain(&self) -> Option<String> {
        None
    }
}

fn isolated_child() -> std::io::Result<std::process::Command> {
    let mut command = std::process::Command::new(std::env::current_exe()?);
    command
        .env_clear()
        .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|value| ("LLVM_PROFILE_FILE", value)));
    Ok(command)
}
