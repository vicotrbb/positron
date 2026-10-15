//! The native SDK's explicit admitted owner for files, HTTP, tasks and children.
use super::super::aws::{credentials_http, dns};
use super::*;
use crate::TransferredResourceReservation;
use crate::data_protection::{CryptoBackend, RustCryptoBackend};
use google_cloud_auth::native::{self, Runtime};
use std::{io::Read, sync::atomic::AtomicUsize};
use tracing::instrument::WithSubscriber;

const MAXIMUM: usize = 131_072;

#[derive(Debug)]
struct Counts {
    tasks: AtomicUsize,
    http: AtomicUsize,
    files: AtomicUsize,
    processes: AtomicUsize,
    crypto: AtomicUsize,
    connections: AtomicUsize,
}
#[derive(Debug)]
struct Lease {
    counts: Arc<Counts>,
    kind: Kind,
    _resources: Arc<dns::Resources>,
}
#[derive(Clone, Copy, Debug)]
enum Kind {
    Tasks,
    Http,
    Files,
    Processes,
    Crypto,
    Connections,
}
impl Counts {
    fn counter(&self, kind: Kind) -> &AtomicUsize {
        match kind {
            Kind::Tasks => &self.tasks,
            Kind::Http => &self.http,
            Kind::Files => &self.files,
            Kind::Processes => &self.processes,
            Kind::Crypto => &self.crypto,
            Kind::Connections => &self.connections,
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.counts
            .counter(self.kind)
            .fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug)]
struct ConnectionExecutor {
    resources: Arc<dns::Resources>,
    counts: Arc<Counts>,
    refused: AtomicBool,
}
impl reqwest::ConnectionTaskExecutor for ConnectionExecutor {
    fn execute(
        &self,
        task: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>,
    ) {
        let admitted =
            self.counts
                .connections
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                    (used < 2).then_some(used + 1)
                });
        if admitted.is_err() {
            self.refused.store(true, Ordering::Release);
            drop(task);
            return;
        }
        let lease = Lease {
            counts: self.counts.clone(),
            kind: Kind::Connections,
            _resources: self.resources.clone(),
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                drop(
                    handle.spawn(
                        async move {
                            let _lease = lease;
                            task.await;
                        }
                        .with_subscriber(tracing::subscriber::NoSubscriber::default()),
                    ),
                );
            },
            Err(_) => {
                self.refused.store(true, Ordering::Release);
                drop(task);
                drop(lease);
            },
        }
    }
}

pub struct NativeRuntime {
    resources: Arc<dns::Resources>,
    counts: Arc<Counts>,
    dns: dns::NativeDns,
    tls_roots: Vec<reqwest::Certificate>,
}
impl std::fmt::Debug for NativeRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeRuntime { admitted Google native identity }")
    }
}
impl NativeRuntime {
    pub(in crate::data_protection::key_provider) fn new(
        grant: TransferredResourceReservation,
    ) -> Result<Arc<Self>, KeyProviderFailure> {
        let resources = dns::Resources::new(grant);
        Self::from_resources(resources)
    }
    pub fn from_resources(resources: Arc<dns::Resources>) -> Result<Arc<Self>, KeyProviderFailure> {
        let dns = dns::NativeDns(resources.clone());
        Ok(Arc::new(Self {
            resources,
            dns,
            tls_roots: Vec::new(),
            counts: Arc::new(Counts {
                tasks: AtomicUsize::new(0),
                http: AtomicUsize::new(0),
                files: AtomicUsize::new(0),
                processes: AtomicUsize::new(0),
                crypto: AtomicUsize::new(0),
                connections: AtomicUsize::new(0),
            }),
        }))
    }
    /// Additional operator-selected public CA roots, never an insecure TLS mode.
    pub(in crate::data_protection::key_provider) fn add_trust_roots(
        &mut self,
        pem: &[u8],
    ) -> Result<(), KeyProviderFailure> {
        if pem.len() > 32768 {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        let roots = reqwest::Certificate::from_pem_bundle(pem)
            .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
        if roots.is_empty() || roots.len() > 16 {
            return Err(KeyProviderFailure::InvalidConfiguration);
        }
        self.tls_roots = roots;
        Ok(())
    }
    pub(in crate::data_protection::key_provider) fn read_trust_roots(
        &self,
        path: &std::path::Path,
    ) -> Result<Zeroizing<Vec<u8>>, KeyProviderFailure> {
        self.read_protected(path, false)
    }
    pub(in crate::data_protection::key_provider) fn read_protected(
        &self,
        path: &std::path::Path,
        private: bool,
    ) -> Result<Zeroizing<Vec<u8>>, KeyProviderFailure> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let _lease = self
            .acquire(Kind::Files, 4)
            .map_err(super::native_failure)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(path)
            .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
        let metadata = file
            .metadata()
            .map_err(|_| KeyProviderFailure::Unavailable)?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || ![0, rustix::process::geteuid().as_raw()].contains(&metadata.uid())
            || metadata.mode() & 0o022 != 0
            || (private
                && (metadata.uid() != rustix::process::geteuid().as_raw()
                    || metadata.mode() & 0o077 != 0))
        {
            return Err(KeyProviderFailure::PermissionDenied);
        }
        if metadata.len() > 32768 {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(32769));
        file.take(32769)
            .read_to_end(&mut bytes)
            .map_err(|_| KeyProviderFailure::Unavailable)?;
        if bytes.len() > 32768 {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        Ok(bytes)
    }
    pub(in crate::data_protection::key_provider) async fn native_addresses(
        &self,
        host: &str,
    ) -> Result<Vec<std::net::SocketAddr>, KeyProviderFailure> {
        self.dns.addresses(host).await
    }
    fn acquire(&self, kind: Kind, maximum: usize) -> native::Result<Lease> {
        self.counts
            .counter(kind)
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                (used < maximum).then_some(used + 1)
            })
            .map_err(|_| native::Error::LimitExceeded)?;
        Ok(Lease {
            counts: self.counts.clone(),
            kind,
            _resources: self.resources.clone(),
        })
    }

    pub(in crate::data_protection::key_provider) fn app_service_http(
        &self,
        request: native::Request,
    ) -> native::BoxFuture<'_, native::Response> {
        Box::pin(async move { self.http_request(request, true, MAXIMUM, MAXIMUM).await })
    }

    /// GCS data transport shares the credential/DNS/task owner and its grant.
    /// Only the native verified-TLS endpoint accepts the larger data bound.
    pub fn repository_http(
        &self,
        request: native::Request,
        maximum: usize,
    ) -> native::BoxFuture<'_, native::Response> {
        Box::pin(async move {
            if !self.resources.authorizes_repository_transport()
                || maximum > 64 * 1024 * 1024 + 65536
            {
                return Err(native::Error::PermissionDenied);
            }
            if !(request
                .url
                .starts_with("https://storage.googleapis.com/storage/v1/")
                || request
                    .url
                    .starts_with("https://storage.googleapis.com/upload/storage/v1/"))
            {
                return Err(native::Error::InvalidConfiguration);
            }
            self.http_request(request, false, maximum, 64 * 1024 * 1024 + 65536)
                .await
        })
    }

    pub(in crate::data_protection::key_provider) fn azure_repository_http(
        &self,
        request: native::Request,
        maximum: usize,
    ) -> native::BoxFuture<'_, native::Response> {
        Box::pin(async move {
            if !self.resources.authorizes_repository_transport()
                || maximum > 64 * 1024 * 1024 + 65536
            {
                return Err(native::Error::PermissionDenied);
            }
            self.http_request(request, false, maximum, 64 * 1024 * 1024 + 65536)
                .await
        })
    }

    /// Exercises admitted repository HTTP against a loopback protocol fixture.
    /// Available only to tests; native construction never enables this route.
    #[cfg(feature = "test-support")]
    pub fn repository_simulation_http(
        &self,
        mut request: native::Request,
        address: std::net::SocketAddr,
        maximum: usize,
    ) -> native::BoxFuture<'_, native::Response> {
        Box::pin(async move {
            if !address.ip().is_loopback()
                || address.port() == 0
                || !self.resources.authorizes_repository_transport()
                || maximum > 64 * 1024 * 1024 + 65536
                || request.headers.contains_key(http::header::AUTHORIZATION)
            {
                return Err(native::Error::PermissionDenied);
            }
            let path = request
                .url
                .strip_prefix("https://storage.googleapis.com")
                .filter(|path| {
                    path.starts_with("/storage/v1/") || path.starts_with("/upload/storage/v1/")
                })
                .ok_or(native::Error::InvalidConfiguration)?;
            request.url = format!("http://{address}{path}");
            self.http_request(request, false, maximum, 64 * 1024 * 1024 + 65536)
                .await
        })
    }

    async fn http_request(
        &self,
        mut request: native::Request,
        app_service: bool,
        maximum: usize,
        request_maximum: usize,
    ) -> native::Result<native::Response> {
        let _lease = self.acquire(Kind::Http, 2)?;
        if request.url.len() > 4096 || request.body.len() > request_maximum {
            return Err(native::Error::LimitExceeded);
        }
        let uri =
            reqwest::Url::parse(&request.url).map_err(|_| native::Error::InvalidConfiguration)?;
        if !uri.username().is_empty() || uri.password().is_some() || uri.fragment().is_some() {
            return Err(native::Error::InvalidConfiguration);
        }
        let header_bytes = request
            .headers
            .iter()
            .try_fold(0usize, |used, (name, value)| {
                used.checked_add(name.as_str().len())
                    .and_then(|used| used.checked_add(value.len()))
            })
            .ok_or(native::Error::LimitExceeded)?;
        if header_bytes > MAXIMUM {
            return Err(native::Error::LimitExceeded);
        }
        for value in request.headers.values_mut() {
            value.set_sensitive(true);
        }
        let executor = Arc::new(ConnectionExecutor {
            resources: self.resources.clone(),
            counts: self.counts.clone(),
            refused: AtomicBool::new(false),
        });
        let mut builder = credentials_http::client_builder(self.dns.clone())
            .connection_task_executor(executor.clone());
        for certificate in &self.tls_roots {
            builder = builder.add_root_certificate(certificate.clone());
        }
        let client = match uri.scheme() {
            "https" => builder
                .https_only(true)
                .build()
                .map_err(|_| native::Error::InvalidConfiguration)?,
            "http" => {
                let host = uri.host_str().ok_or(native::Error::InvalidConfiguration)?;
                let mut addresses = match host.trim_matches(['[', ']']).parse::<std::net::IpAddr>()
                {
                    Ok(ip) => vec![std::net::SocketAddr::new(
                        ip,
                        uri.port_or_known_default().unwrap_or(80),
                    )],
                    Err(_) => self.dns.addresses(host).await.map_err(map_failure)?,
                };
                if app_service {
                    for address in &mut addresses {
                        address.set_port(
                            uri.port_or_known_default()
                                .ok_or(native::Error::InvalidConfiguration)?,
                        );
                    }
                    validate_app_service_peers(&addresses)?;
                } else {
                    validate_metadata_peers(&addresses)?;
                }
                builder
                    .resolve_to_addrs(host, &addresses)
                    .build()
                    .map_err(|_| native::Error::InvalidConfiguration)?
            },
            _ => return Err(native::Error::InvalidConfiguration),
        };
        let response = client
            .request(request.method.clone(), uri)
            .headers(std::mem::take(&mut request.headers))
            .body(bytes::Bytes::from_owner(std::mem::take(&mut request.body)))
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|_| {
                if executor.refused.load(Ordering::Acquire) {
                    native::Error::LimitExceeded
                } else {
                    native::Error::Unavailable
                }
            })?;
        let status = response.status();
        let mut headers = response.headers().clone();
        let size = headers
            .iter()
            .try_fold(0usize, |used, (name, value)| {
                used.checked_add(name.as_str().len())
                    .and_then(|used| used.checked_add(value.len()))
            })
            .ok_or(native::Error::LimitExceeded)?;
        if size > MAXIMUM {
            return Err(native::Error::LimitExceeded);
        }
        for value in headers.values_mut() {
            value.set_sensitive(true);
        }
        let body = credentials_http::collect(response, maximum)
            .await
            .map_err(map_failure)?;
        Ok(native::Response {
            status,
            headers,
            body,
        })
    }

    async fn execute_native(
        &self,
        command: &str,
        args: &[String],
        timeout: Duration,
    ) -> native::Result<Zeroizing<Vec<u8>>> {
        if command.is_empty()
            || command.len() > 4096
            || args.len() > 64
            || args
                .iter()
                .try_fold(command.len(), |used, arg| used.checked_add(arg.len()))
                .is_none_or(|size| size > 8192)
        {
            return Err(native::Error::LimitExceeded);
        }
        let lease = self.acquire(Kind::Processes, 1)?;
        let command = Zeroizing::new(command.to_owned());
        let args = Zeroizing::new(args.to_vec());
        let timeout = timeout.min(DEADLINE);
        let worker = tokio::runtime::Handle::try_current()
            .map_err(|_| native::Error::InvalidConfiguration)?
            .spawn(
                async move {
                    let _lease = lease;
                    let mut child = tokio::process::Command::new(command.as_str())
                        .args(args.iter())
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .kill_on_drop(true)
                        .spawn()
                        .map_err(|error| match error.kind() {
                            std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput => {
                                native::Error::InvalidConfiguration
                            },
                            std::io::ErrorKind::PermissionDenied => native::Error::PermissionDenied,
                            _ => native::Error::Unavailable,
                        })?;
                    drop(command);
                    drop(args);
                    let stdout = child.stdout.take().ok_or(native::Error::Unavailable)?;
                    let stderr = child.stderr.take().ok_or(native::Error::Unavailable)?;
                    let collected = tokio::time::timeout(timeout, async {
                        let (stdout, stderr, status) =
                            tokio::try_join!(read_pipe(stdout), read_pipe(stderr), async {
                                child.wait().await.map_err(|_| native::Error::Unavailable)
                            })?;
                        drop(stderr);
                        if !status.success() {
                            return Err(native::Error::PermissionDenied);
                        }
                        Ok(stdout)
                    })
                    .await;
                    match collected {
                        Ok(Ok(body)) => Ok(body),
                        result => {
                            let kill_result = match child.try_wait() {
                                Ok(Some(_)) => Ok(()),
                                _ => child.start_kill(),
                            };
                            let reap_result = child.wait().await;
                            if kill_result.is_err() || reap_result.is_err() {
                                return Err(native::Error::Unavailable);
                            }
                            match result {
                                Ok(Err(error)) => Err(error),
                                _ => Err(native::Error::Unavailable),
                            }
                        },
                    }
                }
                .with_subscriber(tracing::subscriber::NoSubscriber::default()),
            );
        worker.await.map_err(|_| native::Error::Unavailable)?
    }
}

async fn read_pipe(
    reader: impl tokio::io::AsyncRead + Unpin,
) -> native::Result<Zeroizing<Vec<u8>>> {
    use tokio::io::AsyncReadExt;
    let mut body = Zeroizing::new(Vec::with_capacity(MAXIMUM + 1));
    reader
        .take(MAXIMUM as u64 + 1)
        .read_to_end(&mut body)
        .await
        .map_err(|_| native::Error::Unavailable)?;
    if body.len() > MAXIMUM {
        return Err(native::Error::LimitExceeded);
    }
    Ok(body)
}

fn map_failure(failure: KeyProviderFailure) -> native::Error {
    match failure {
        KeyProviderFailure::LimitExceeded => native::Error::LimitExceeded,
        KeyProviderFailure::InvalidConfiguration => native::Error::InvalidConfiguration,
        KeyProviderFailure::PermissionDenied => native::Error::PermissionDenied,
        _ => native::Error::Unavailable,
    }
}

impl Runtime for NativeRuntime {
    fn read_file(&self, path: &std::path::Path) -> native::Result<Zeroizing<Vec<u8>>> {
        let _lease = self.acquire(Kind::Files, 4)?;
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
            .open(path)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::NotFound => native::Error::NotFound,
                std::io::ErrorKind::PermissionDenied => native::Error::PermissionDenied,
                _ => native::Error::Unavailable,
            })?;
        let metadata = file.metadata().map_err(|_| native::Error::Unavailable)?;
        if !metadata.is_file() || metadata.len() > MAXIMUM as u64 {
            return Err(native::Error::LimitExceeded);
        }
        let mut body = Zeroizing::new(Vec::with_capacity(MAXIMUM + 1));
        file.take(MAXIMUM as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|_| native::Error::Unavailable)?;
        if body.len() > MAXIMUM {
            return Err(native::Error::LimitExceeded);
        }
        Ok(body)
    }
    fn http(&self, request: native::Request) -> native::BoxFuture<'_, native::Response> {
        Box::pin(async move { self.http_request(request, false, MAXIMUM, MAXIMUM).await })
    }
    fn execute<'a>(
        &'a self,
        command: &'a str,
        args: &'a [String],
        timeout: Duration,
    ) -> native::BoxFuture<'a, Zeroizing<Vec<u8>>> {
        Box::pin(async move { self.execute_native(command, args, timeout).await })
    }
    fn sha256(&self, bytes: &[u8]) -> native::Result<[u8; 32]> {
        let _lease = self.acquire(Kind::Crypto, 1)?;
        if bytes.len() > MAXIMUM {
            return Err(native::Error::LimitExceeded);
        }
        RustCryptoBackend
            .sha256(bytes)
            .map_err(|_| native::Error::Unavailable)
    }
    fn hmac_sha256(&self, key: &[u8], bytes: &[u8]) -> native::Result<[u8; 32]> {
        let _lease = self.acquire(Kind::Crypto, 1)?;
        if key.len() > 8192 || bytes.len() > MAXIMUM {
            return Err(native::Error::LimitExceeded);
        }
        RustCryptoBackend
            .native_identity_hmac(key, bytes)
            .map_err(|_| native::Error::InvalidConfiguration)
    }
    fn rsa_sign(&self, pem: &[u8], bytes: &[u8]) -> native::Result<Vec<u8>> {
        let _lease = self.acquire(Kind::Crypto, 1)?;
        if pem.len() > 16_384 || bytes.len() > MAXIMUM {
            return Err(native::Error::LimitExceeded);
        }
        RustCryptoBackend
            .native_identity_rsa_sign(pem, bytes)
            .map_err(|error| match error {
                crate::data_protection::backend::CryptoBackendFailure::SignatureFailed
                | crate::data_protection::backend::CryptoBackendFailure::EntropyUnavailable => {
                    native::Error::Unavailable
                },
                _ => native::Error::InvalidConfiguration,
            })
    }
    fn spawn(
        &self,
        work: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>,
    ) -> native::Result<tokio::task::JoinHandle<()>> {
        let lease = self.acquire(Kind::Tasks, 8)?;
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| native::Error::InvalidConfiguration)?;
        Ok(handle.spawn(
            async move {
                let _lease = lease;
                work.await;
            }
            .with_subscriber(tracing::subscriber::NoSubscriber::default()),
        ))
    }
}

fn validate_app_service_peers(addresses: &[std::net::SocketAddr]) -> native::Result<()> {
    if addresses.is_empty()
        || addresses.iter().any(|address| !match address.ip() {
            std::net::IpAddr::V4(ip) => ip.is_loopback() || ip.is_link_local(),
            std::net::IpAddr::V6(ip) => ip.is_loopback() || ip.is_unicast_link_local(),
        })
    {
        return Err(native::Error::InvalidConfiguration);
    }
    Ok(())
}

fn validate_metadata_peers(addresses: &[std::net::SocketAddr]) -> native::Result<()> {
    if addresses.is_empty()
        || addresses.iter().any(|address| !match address.ip() {
            std::net::IpAddr::V4(ip) => ip.is_loopback() || ip.octets() == [169, 254, 169, 254],
            std::net::IpAddr::V6(ip) => {
                ip.is_loopback()
                    || ip.segments() == [0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254]
                    || ip.segments() == [0xfd20, 0xce, 0, 0, 0, 0, 0, 0x254]
            },
        })
    {
        return Err(native::Error::InvalidConfiguration);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
