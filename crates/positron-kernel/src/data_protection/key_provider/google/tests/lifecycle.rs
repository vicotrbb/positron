use super::*;

#[tokio::test]
async fn native_process_cancellation_retains_admission_until_confirmed_reap()
-> Result<(), Box<dyn std::error::Error>> {
    use google_cloud_auth::native::Runtime;
    let kernel = crate::data_protection::tests::providers::provider_governor(2_000_000_000)?;
    let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
        GoogleCloudKmsKeyProvider::required_resources(),
    )?)?;
    let native = native::NativeRuntime::new(grant.transfer())?;
    let executing = native.clone();
    let work = tokio::spawn(async move {
        executing
            .execute("/bin/sleep", &["0.2".into()], Duration::from_secs(1))
            .await
    });
    tokio::task::yield_now().await;
    assert_eq!(
        native
            .execute("/bin/sleep", &["0".into()], Duration::from_secs(1))
            .await
            .err(),
        Some(google_cloud_auth::native::Error::LimitExceeded)
    );
    work.abort();
    assert!(work.await.is_err());
    drop(native);
    assert_eq!(
        kernel.inspect()?.outstanding_reservations(),
        1,
        "cancellation released the admitted child before reap"
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while kernel.inspect()?.outstanding_reservations() != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "native cleanup retained an admission cycle"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        kernel
            .inspect()?
            .usage(crate::ResourceDimension::MemoryBytes),
        0
    );
    Ok(())
}

// Extend existing RejectedNativeAdc with adc: Option<Vec<u8>> and spawn_attempts: AtomicUsize.
// Increment spawn_attempts as the first Runtime::spawn action, before the allow_tasks branch.

#[tokio::test]
async fn native_http_cancellation_retains_grant_through_connection_cleanup()
-> Result<(), Box<dyn std::error::Error>> {
    use google_cloud_auth::native::Runtime;
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            socket.read_exact(&mut byte).await?;
            head.extend_from_slice(&byte);
            assert!(head.len() < 4096);
        }
        accepted_tx
            .send(())
            .map_err(|_| std::io::Error::other("fixture receiver dropped"))?;
        let mut byte = [0];
        assert_eq!(
            socket.read(&mut byte).await?,
            0,
            "canceled request retained a live connection"
        );
        Ok::<(), std::io::Error>(())
    });
    let kernel = crate::data_protection::tests::providers::provider_governor(2_000_000_000)?;
    let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
        GoogleCloudKmsKeyProvider::required_resources(),
    )?)?;
    let native = native::NativeRuntime::new(grant.transfer())?;
    let executing = native.clone();
    let work = tokio::spawn(async move {
        executing
            .http(google_cloud_auth::native::Request {
                method: http::Method::GET,
                url: format!("http://{address}/isolated-native-identity"),
                headers: http::HeaderMap::new(),
                body: Zeroizing::new(Vec::new()),
            })
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), accepted_rx).await??;
    work.abort();
    assert!(work.await.is_err());
    drop(native);
    tokio::time::timeout(Duration::from_secs(2), server).await???;
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while kernel.inspect()?.outstanding_reservations() != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "connection cleanup retained its admission"
        );
        tokio::task::yield_now().await;
    }
    Ok(())
}

// Add `file_absent: bool` to RejectedNativeAdc and immediately after its read counter:
// if self.file_absent { return Err(google_cloud_auth::native::Error::NotFound); }
#[tokio::test(start_paused = true)]
async fn google_identity_deadline_before_kms_io_is_unavailable()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = identity()?;
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let payload = SecretWrappedKeyPayload::encode(
        &SecretKek::from_owned(Box::new([5; 32])),
        context,
        &identity,
    )?;
    let native = Arc::new(RejectedNativeAdc::default());
    let provider = GoogleCloudKmsKeyProvider {
        identity,
        credentials: PendingCredentials.into(),
        runtime: native.clone(),
        active: AtomicBool::new(false),
    };
    assert_eq!(
        provider.wrap(payload, context).await.err(),
        Some(KeyProviderFailure::Unavailable)
    );
    assert_eq!(native.http_calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn google_encrypt_retries_only_explicit_outage_and_quota_failures()
-> Result<(), Box<dyn std::error::Error>> {
    for (status, code, expected, attempts) in [
        (
            429,
            "RESOURCE_EXHAUSTED",
            KeyProviderFailure::Unavailable,
            2,
        ),
        (503, "UNAVAILABLE", KeyProviderFailure::Unavailable, 2),
        (504, "DEADLINE_EXCEEDED", KeyProviderFailure::Ambiguous, 1),
        (500, "INTERNAL", KeyProviderFailure::Ambiguous, 1),
        (500, "UNRECOGNIZED", KeyProviderFailure::Ambiguous, 1),
        (
            403,
            "PERMISSION_DENIED",
            KeyProviderFailure::PermissionDenied,
            1,
        ),
        (
            429,
            "FAILED_PRECONDITION",
            KeyProviderFailure::PermissionDenied,
            1,
        ),
        (
            429,
            "INVALID_ARGUMENT",
            KeyProviderFailure::ContextMismatch,
            1,
        ),
        (429, "INTERNAL", KeyProviderFailure::Ambiguous, 1),
    ] {
        let reply = || google_cloud_auth::native::Response {
            status: http::StatusCode::from_u16(status).expect("published HTTP status"),
            headers: http::HeaderMap::new(),
            body: Zeroizing::new(
                format!(r#"{{"error":{{"status":"{code}","message":"native-error-canary"}}}}"#)
                    .into_bytes(),
            ),
        };
        let native = Arc::new(RejectedNativeAdc {
            wire: std::sync::Mutex::new(std::collections::VecDeque::from([reply(), reply()])),
            ..RejectedNativeAdc::default()
        });
        let identity = identity()?;
        let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
        let payload = SecretWrappedKeyPayload::encode(
            &SecretKek::from_owned(Box::new([5; 32])),
            context,
            &identity,
        )?;
        let provider = GoogleCloudKmsKeyProvider {
            identity,
            credentials: FixtureCredentials.into(),
            runtime: native.clone(),
            active: AtomicBool::new(false),
        };
        assert_eq!(
            provider.wrap(payload, context).await.err(),
            Some(expected),
            "{code}"
        );
        assert_eq!(native.http_calls.load(Ordering::SeqCst), attempts, "{code}");
    }
    Ok(())
}

#[tokio::test]
async fn google_published_transcripts_rewrap_through_shared_identity_and_recovery_checks()
-> Result<(), Box<dyn std::error::Error>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let source_identity = identity()?;
    let destination_identity = ProviderKeyUri::new(
        ProviderFamily::GoogleCloudKms,
        "projects/project-1/locations/us-central1/keyRings/ring/cryptoKeys/root/cryptoKeyVersions/8",
        "8",
    )?;
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let metadata = |identity: &ProviderKeyUri| {
        format!(r#"{{"name":"{}","state":"ENABLED","algorithm":"GOOGLE_SYMMETRIC_ENCRYPTION","protectionLevel":"SOFTWARE"}}"#, identity.locator()).into_bytes()
    };
    let plaintext = |identity: &ProviderKeyUri| -> Result<Vec<u8>, KeyProviderFailure> {
        let payload = SecretWrappedKeyPayload::encode(
            &SecretKek::from_owned(Box::new([5; 32])),
            context,
            identity,
        )?;
        let encoded = Zeroizing::new(STANDARD.encode(payload.as_provider_plaintext()));
        Ok(format!(
            r#"{{"plaintext":"{}","plaintextCrc32c":"{}"}}"#,
            encoded.as_str(),
            crc32c::crc32c(payload.as_provider_plaintext())
        )
        .into_bytes())
    };
    let response = |body| google_cloud_auth::native::Response {
        status: http::StatusCode::OK,
        headers: http::HeaderMap::new(),
        body: Zeroizing::new(body),
    };
    let source_native = Arc::new(RejectedNativeAdc {
        wire: std::sync::Mutex::new(std::collections::VecDeque::from([
            response(metadata(&source_identity)),
            response(plaintext(&source_identity)?),
        ])),
        ..RejectedNativeAdc::default()
    });
    let destination_native = Arc::new(RejectedNativeAdc { wire: std::sync::Mutex::new(std::collections::VecDeque::from([
        response(metadata(&destination_identity)),
        response(format!(r#"{{"name":"{}","ciphertext":"MTIzNDU2Nzg5","ciphertextCrc32c":"3808858755","verifiedPlaintextCrc32c":true,"verifiedAdditionalAuthenticatedDataCrc32c":true}}"#, destination_identity.locator()).into_bytes()),
        response(metadata(&destination_identity)), response(plaintext(&destination_identity)?),
    ])), ..RejectedNativeAdc::default() });
    let source = GoogleCloudKmsKeyProvider {
        identity: source_identity.clone(),
        credentials: FixtureCredentials.into(),
        runtime: source_native.clone(),
        active: AtomicBool::new(false),
    };
    let destination = GoogleCloudKmsKeyProvider {
        identity: destination_identity.clone(),
        credentials: FixtureCredentials.into(),
        runtime: destination_native.clone(),
        active: AtomicBool::new(false),
    };
    let envelope = KeyEnvelope::from_provider_response(
        source_identity.clone(),
        context,
        WrappingAlgorithm::GoogleSymmetricEncryption,
        b"123456789".to_vec(),
    )?;
    let original = envelope.encode();
    let replacement = source
        .rewrap_envelope(&envelope, context, &destination)
        .await?;
    assert_eq!(envelope.encode(), original);
    replacement.check(&destination_identity, context)?;
    assert_eq!(
        replacement.check(&source_identity, context),
        Err(KeyProviderFailure::WrongKey)
    );
    assert_eq!(source_native.http_calls.load(Ordering::SeqCst), 2);
    assert_eq!(destination_native.http_calls.load(Ordering::SeqCst), 4);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn google_concurrent_operations_refuse_admission_and_cancellation_reopens_the_slot()
-> Result<(), Box<dyn std::error::Error>> {
    let native = Arc::new(RejectedNativeAdc::default());
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let provider = GoogleCloudKmsKeyProvider {
        identity: identity()?,
        credentials: PendingCredentials.into(),
        runtime: native.clone(),
        active: AtomicBool::new(false),
    };
    let mut first = Box::pin(provider.probe(context));
    tokio::select! { biased;
        result = &mut first => panic!("pending identity completed: {result:?}"),
        () = tokio::task::yield_now() => {},
    }
    assert_eq!(
        provider.probe(context).await,
        Err(KeyProviderFailure::LimitExceeded)
    );
    drop(first);
    assert_eq!(
        provider.probe(context).await,
        Err(KeyProviderFailure::Unavailable)
    );
    assert_eq!(native.http_calls.load(Ordering::SeqCst), 0);
    Ok(())
}
