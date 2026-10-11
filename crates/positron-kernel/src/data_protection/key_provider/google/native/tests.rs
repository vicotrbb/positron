use super::*;
use reqwest::ConnectionTaskExecutor as _;

#[tokio::test]
async fn native_files_and_crypto_refuse_bounded_failures_without_disclosing_input()
-> Result<(), Box<dyn std::error::Error>> {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let root = std::env::temp_dir().join(format!(
        "positron-google-native-file-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&root)?;
    let kernel = crate::data_protection::tests::providers::provider_governor(2_000_000_000)?;
    let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
        GoogleCloudKmsKeyProvider::required_resources(),
    )?)?;
    let runtime = NativeRuntime::new(grant.transfer())?;
    let file = root.join("isolated-native-config");
    std::fs::write(&file, b"native-secret-canary")?;
    assert_eq!(&*runtime.read_file(&file)?, b"native-secret-canary");
    let alias = root.join("projected-native-token");
    std::os::unix::fs::symlink(&file, &alias)?;
    assert_eq!(&*runtime.read_file(&alias)?, b"native-secret-canary");
    assert_eq!(
        runtime.read_file(&root.join("absent")).err(),
        Some(native::Error::NotFound)
    );
    assert_eq!(
        runtime.read_file(&root).err(),
        Some(native::Error::LimitExceeded)
    );
    std::fs::write(&file, vec![0; MAXIMUM + 1])?;
    assert_eq!(
        runtime.read_file(&file).err(),
        Some(native::Error::LimitExceeded)
    );
    assert_eq!(
        runtime.sha256(&vec![0; MAXIMUM + 1]),
        Err(native::Error::LimitExceeded)
    );
    assert_eq!(
        runtime.hmac_sha256(&vec![0; 8193], b"message"),
        Err(native::Error::LimitExceeded)
    );
    assert_eq!(
        runtime.rsa_sign(&vec![0; 16_385], b"message"),
        Err(native::Error::LimitExceeded)
    );
    assert!(
        runtime
            .rsa_sign(b"malformed-secret-canary", b"message")
            .is_err()
    );
    assert!(runtime.hmac_sha256(b"", b"message").is_err());
    assert!(runtime.hmac_sha256(b"key", b"message").is_ok());
    assert!(runtime.sha256(b"message").is_ok());
    drop(runtime);
    assert_eq!(kernel.inspect()?.outstanding_reservations(), 0);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn native_executable_results_are_bounded_and_redacted_after_reap()
-> Result<(), Box<dyn std::error::Error>> {
    let kernel = crate::data_protection::tests::providers::provider_governor(2_000_000_000)?;
    let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
        GoogleCloudKmsKeyProvider::required_resources(),
    )?)?;
    let runtime = NativeRuntime::new(grant.transfer())?;
    assert_eq!(
        &*runtime
            .execute(
                "/bin/echo",
                &["native-output-canary".into()],
                Duration::from_secs(1)
            )
            .await?,
        b"native-output-canary\n"
    );
    let error = runtime
        .execute(
            "/bin/sh",
            &[
                "-c".into(),
                "printf native-stderr-canary >&2; exit 1".into(),
            ],
            Duration::from_secs(1),
        )
        .await
        .err()
        .ok_or("failed child was accepted")?;
    assert_eq!(error, native::Error::PermissionDenied);
    assert!(!format!("{error:?} {error}").contains("canary"));
    assert_eq!(
        runtime.execute("", &[], Duration::from_secs(1)).await.err(),
        Some(native::Error::LimitExceeded)
    );
    assert_eq!(
        runtime
            .execute("/nonexistent-native-command", &[], Duration::from_secs(1))
            .await
            .err(),
        Some(native::Error::InvalidConfiguration)
    );
    assert_eq!(
        runtime
            .execute("/bin/sleep", &["1".into()], Duration::from_millis(1))
            .await
            .err(),
        Some(native::Error::Unavailable)
    );
    assert_eq!(
        runtime
            .execute(
                "/usr/bin/head",
                &["-c".into(), (MAXIMUM + 1).to_string(), "/dev/zero".into()],
                Duration::from_secs(1)
            )
            .await
            .err(),
        Some(native::Error::LimitExceeded)
    );
    drop(runtime);
    assert_eq!(kernel.inspect()?.outstanding_reservations(), 0);
    Ok(())
}

#[tokio::test]
async fn native_http_refuses_unverified_metadata_urls_before_io()
-> Result<(), Box<dyn std::error::Error>> {
    let kernel = crate::data_protection::tests::providers::provider_governor(2_000_000_000)?;
    let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
        GoogleCloudKmsKeyProvider::required_resources(),
    )?)?;
    let runtime = NativeRuntime::new(grant.transfer())?;
    for url in [
        "not-a-url",
        "ftp://127.0.0.1/token",
        "http://192.0.2.1/token",
        "https://user:password@example.invalid/token",
        "https://example.invalid/token#fragment",
    ] {
        let result = runtime
            .http(native::Request {
                method: http::Method::GET,
                url: url.into(),
                headers: http::HeaderMap::new(),
                body: Zeroizing::new(Vec::new()),
            })
            .await;
        assert_eq!(result.err(), Some(native::Error::InvalidConfiguration));
    }
    assert_eq!(
        runtime
            .http(native::Request {
                method: http::Method::GET,
                url: "https://example.invalid/token".into(),
                headers: http::HeaderMap::new(),
                body: Zeroizing::new(vec![0; MAXIMUM + 1])
            })
            .await
            .err(),
        Some(native::Error::LimitExceeded)
    );
    drop(runtime);
    assert_eq!(kernel.inspect()?.outstanding_reservations(), 0);
    Ok(())
}

#[derive(Debug)]
struct HeldConnection {
    inner: Arc<ConnectionExecutor>,
    finished: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}
impl reqwest::ConnectionTaskExecutor for HeldConnection {
    fn execute(
        &self,
        connection: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>,
    ) {
        let finished = self.finished.clone();
        let release = self.release.clone();
        self.inner.execute(Box::pin(async move {
            connection.await;
            finished.notify_one();
            release.notified().await;
        }));
    }
}

#[tokio::test]
async fn admitted_executor_keeps_actual_connection_task_owner_until_destruction()
-> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            socket.read_exact(&mut byte).await?;
            head.extend_from_slice(&byte);
            assert!(head.len() < 4096);
        }
        Ok::<(), std::io::Error>(())
    });
    let kernel = crate::data_protection::tests::providers::provider_governor(2_000_000_000)?;
    let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
        GoogleCloudKmsKeyProvider::required_resources(),
    )?)?;
    let runtime = NativeRuntime::new(grant.transfer())?;
    let executor = Arc::new(ConnectionExecutor {
        resources: runtime.resources.clone(),
        counts: runtime.counts.clone(),
        refused: AtomicBool::new(false),
    });
    let finished = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let client = credentials_http::client_builder(runtime.dns.clone())
        .connection_task_executor(Arc::new(HeldConnection {
            inner: executor.clone(),
            finished: finished.clone(),
            release: release.clone(),
        }))
        .build()?;
    assert!(
        client
            .get(format!("http://{address}/published-wire-fixture"))
            .send()
            .await
            .is_err()
    );
    tokio::time::timeout(Duration::from_secs(2), finished.notified()).await?;
    server.await??;
    drop(client);
    drop(runtime);
    drop(executor);
    assert_eq!(
        kernel.inspect()?.outstanding_reservations(),
        1,
        "completed transport released admission before its task was destroyed"
    );
    release.notify_one();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while kernel.inspect()?.outstanding_reservations() != 0 {
        assert!(std::time::Instant::now() < deadline);
        tokio::task::yield_now().await;
    }
    assert_eq!(
        kernel.inspect()?.usage(crate::ResourceDimension::TaskSlots),
        0
    );
    Ok(())
}

#[tokio::test]
async fn refused_connection_task_is_dropped_and_never_spawns()
-> Result<(), Box<dyn std::error::Error>> {
    let kernel = crate::data_protection::tests::providers::provider_governor(2_000_000_000)?;
    let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
        GoogleCloudKmsKeyProvider::required_resources(),
    )?)?;
    let runtime = NativeRuntime::new(grant.transfer())?;
    let executor = Arc::new(ConnectionExecutor {
        resources: runtime.resources.clone(),
        counts: runtime.counts.clone(),
        refused: AtomicBool::new(false),
    });
    let (first_tx, first_rx) = tokio::sync::oneshot::channel();
    let (second_tx, second_rx) = tokio::sync::oneshot::channel();
    executor.execute(Box::pin(async move {
        let _ = first_rx.await;
    }));
    executor.execute(Box::pin(async move {
        let _ = second_rx.await;
    }));
    let dropped = Arc::new(AtomicBool::new(false));
    struct DropProof(Arc<AtomicBool>);
    impl Drop for DropProof {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    let proof = DropProof(dropped.clone());
    executor.execute(Box::pin(async move {
        let _proof = proof;
        std::future::pending::<()>().await;
    }));
    assert!(executor.refused.load(Ordering::Acquire));
    assert!(dropped.load(Ordering::Acquire));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let (mut socket, _) = listener.accept().await?;
        let mut byte = [0];
        let read = socket.read(&mut byte).await?;
        assert_eq!(read, 0);
        Ok::<(), std::io::Error>(())
    });
    let result = runtime
        .http(native::Request {
            method: http::Method::GET,
            url: format!("http://{address}/capacity-fixture"),
            headers: http::HeaderMap::new(),
            body: Zeroizing::new(Vec::new()),
        })
        .await;
    assert_eq!(result.err(), Some(native::Error::LimitExceeded));
    tokio::time::timeout(Duration::from_secs(2), server).await???;
    first_tx
        .send(())
        .map_err(|_| "first admitted task disappeared")?;
    second_tx
        .send(())
        .map_err(|_| "second admitted task disappeared")?;
    drop(runtime);
    drop(executor);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while kernel.inspect()?.outstanding_reservations() != 0 {
        assert!(std::time::Instant::now() < deadline);
        tokio::task::yield_now().await;
    }
    Ok(())
}

#[tokio::test]
async fn native_http_bounds_wire_bodies_and_returns_redirects_without_following_them()
-> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for oversized in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut request = [0; 1024];
            assert!(stream.read(&mut request).await? > 0);
            let response = if oversized {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    MAXIMUM + 1,
                    "x".repeat(MAXIMUM + 1)
                )
            } else {
                "HTTP/1.1 302 Found\r\nLocation: http://192.0.2.1/forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
            };
            stream.write_all(response.as_bytes()).await?;
            stream.shutdown().await?;
            Ok::<(), std::io::Error>(())
        });
        let kernel = crate::data_protection::tests::providers::provider_governor(2_000_000_000)?;
        let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
            super::super::GoogleCloudKmsKeyProvider::required_resources(),
        )?)?;
        let runtime = NativeRuntime::new(grant.transfer())?;
        let result = runtime
            .http(native::Request {
                method: http::Method::GET,
                url: format!("http://{address}/identity"),
                headers: http::HeaderMap::new(),
                body: Zeroizing::new(Vec::new()),
            })
            .await;
        if oversized {
            assert_eq!(result.err(), Some(native::Error::LimitExceeded));
        } else {
            assert_eq!(result?.status, http::StatusCode::FOUND);
        }
        server.await??;
        drop(runtime);
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while kernel.inspect()?.outstanding_reservations() != 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "HTTP body failure retained native ownership"
            );
            tokio::task::yield_now().await;
        }
    }
    Ok(())
}

#[test]
fn metadata_peer_policy_accepts_exact_native_addresses_and_rejects_mixed_peers()
-> Result<(), Box<dyn std::error::Error>> {
    for literal in [
        "127.0.0.1",
        "::1",
        "169.254.169.254",
        "fd00:ec2::254",
        "fd20:ce::254",
    ] {
        let peer = std::net::SocketAddr::new(literal.parse()?, 80);
        assert_eq!(
            validate_metadata_peers(&[peer]),
            Ok(()),
            "native metadata peer {literal}"
        );
    }
    let uri = reqwest::Url::parse("http://[fd20:ce::254]/computeMetadata/v1/")?;
    let host = uri.host_str().ok_or("missing metadata host")?;
    let peer = std::net::SocketAddr::new(host.trim_matches(['[', ']']).parse()?, 80);
    assert_eq!(validate_metadata_peers(&[peer]), Ok(()));
    assert_eq!(
        validate_metadata_peers(&[]),
        Err(native::Error::InvalidConfiguration)
    );
    for literal in [
        "fd20:ce::255",
        "fd00:ec2::255",
        "fc00::1",
        "192.0.2.1",
        "169.254.169.253",
    ] {
        let peer = std::net::SocketAddr::new(literal.parse()?, 80);
        assert_eq!(
            validate_metadata_peers(&[peer]),
            Err(native::Error::InvalidConfiguration)
        );
        assert_eq!(
            validate_metadata_peers(&[std::net::SocketAddr::new("127.0.0.1".parse()?, 80), peer]),
            Err(native::Error::InvalidConfiguration)
        );
    }
    Ok(())
}

#[test]
fn selected_azure_app_service_accepts_local_link_local_peers() {
    let addresses = [std::net::SocketAddr::from(([169, 254, 42, 7], 8081))];
    assert_eq!(super::validate_app_service_peers(&addresses), Ok(()));
}

#[test]
fn app_service_peer_policy_refuses_empty_remote_and_mixed_addresses() {
    for addresses in [
        vec![],
        vec![std::net::SocketAddr::from(([192, 0, 2, 1], 80))],
        vec![
            std::net::SocketAddr::from(([169, 254, 42, 7], 80)),
            std::net::SocketAddr::from(([192, 0, 2, 1], 80)),
        ],
    ] {
        assert_eq!(
            super::validate_app_service_peers(&addresses),
            Err(native::Error::InvalidConfiguration)
        );
    }
    assert_eq!(
        super::validate_metadata_peers(&[std::net::SocketAddr::from(([169, 254, 42, 7], 80))]),
        Err(native::Error::InvalidConfiguration)
    );
}
