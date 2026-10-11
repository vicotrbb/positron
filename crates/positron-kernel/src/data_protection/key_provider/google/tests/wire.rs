use super::*;

#[test]
fn google_version_rejects_noncanonical_signed_numbers() {
    assert_eq!(
        ProviderKeyUri::new(
            ProviderFamily::GoogleCloudKms,
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/+7",
            "+7"
        ),
        Err(KeyProviderFailure::InvalidConfiguration)
    );
}

#[test]
fn google_provider_requires_complete_admission_before_loading_native_identity()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::data_protection::tests::providers::{cache_governor, cache_reservation};
    let kernel = cache_governor()?;
    let grant = cache_reservation(&kernel, 1)?;
    let mut future = std::pin::pin!(GoogleCloudKmsKeyProvider::from_application_default(
        identity()?,
        grant
    ));
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(matches!(
        std::future::Future::poll(future.as_mut(), &mut context),
        std::task::Poll::Ready(Err(KeyProviderFailure::LimitExceeded))
    ));
    Ok(())
}

#[test]
fn google_encrypt_response_checks_pinned_version_and_published_crc32c_vector()
-> Result<(), Box<dyn std::error::Error>> {
    // CRC32C check value for ASCII "123456789", RFC 3720 Appendix B.4.
    let response = br#"{"name":"projects/project-1/locations/us-central1/keyRings/ring/cryptoKeys/root/cryptoKeyVersions/7","ciphertext":"MTIzNDU2Nzg5","ciphertextCrc32c":"3808858755","verifiedPlaintextCrc32c":true,"verifiedAdditionalAuthenticatedDataCrc32c":true}"#;
    assert_eq!(
        protocol::wrapped_response(response, &identity()?)?,
        b"123456789"
    );
    let wrong = String::from_utf8(response.to_vec())?.replace("Versions/7", "Versions/8");
    assert_eq!(
        protocol::wrapped_response(wrong.as_bytes(), &identity()?),
        Err(KeyProviderFailure::WrongKey)
    );
    let corrupt = String::from_utf8(response.to_vec())?.replace("3808858755", "3808858754");
    assert_eq!(
        protocol::wrapped_response(corrupt.as_bytes(), &identity()?),
        Err(KeyProviderFailure::ContextMismatch)
    );
    let unverified = String::from_utf8(response.to_vec())?.replace("true", "false");
    assert_eq!(
        protocol::wrapped_response(unverified.as_bytes(), &identity()?),
        Err(KeyProviderFailure::ContextMismatch)
    );
    Ok(())
}

#[test]
fn google_plaintext_response_keeps_borrowed_base64_and_checks_context_and_crc()
-> Result<(), Box<dyn std::error::Error>> {
    use base64::Engine;
    let identity = identity()?;
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let key = SecretKek::from_owned(Box::new([5; 32]));
    let payload = SecretWrappedKeyPayload::encode(&key, context, &identity)?;
    let encoded = Zeroizing::new(
        base64::engine::general_purpose::STANDARD.encode(payload.as_provider_plaintext()),
    );
    let checksum = crc32c::crc32c(payload.as_provider_plaintext());
    let response = Zeroizing::new(format!(
        "{{\"plaintext\":\"{}\",\"plaintextCrc32c\":\"{checksum}\"}}",
        encoded.as_str()
    ));
    let decoded = protocol::plaintext_response(response.as_bytes())?;
    decoded.verify(context, &identity)?;
    let wrong = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 2, 1)?;
    assert_eq!(
        protocol::plaintext_response(response.as_bytes())?
            .verify(wrong, &identity)
            .err(),
        Some(KeyProviderFailure::ContextMismatch)
    );
    assert_eq!(
        protocol::plaintext_response(
            br#"{"plaintext":"c2VjcmV0LWNhbmFyeQ==","plaintextCrc32c":"0"}"#
        )
        .err(),
        Some(KeyProviderFailure::ContextMismatch)
    );
    Ok(())
}

#[test]
fn google_error_classes_preserve_encrypt_uncertainty_and_redact_native_messages() {
    use protocol::Operation;
    for operation in [Operation::Metadata, Operation::Encrypt, Operation::Decrypt] {
        assert_eq!(
            protocol::classify(
                operation,
                429,
                br#"{"error":{"status":"RESOURCE_EXHAUSTED","message":"native-secret-canary"}}"#
            ),
            KeyProviderFailure::Unavailable
        );
        assert_eq!(
            protocol::classify(
                operation,
                400,
                br#"{"error":{"status":"INVALID_ARGUMENT"}}"#
            ),
            KeyProviderFailure::ContextMismatch
        );
        assert_eq!(
            protocol::classify(operation, 404, br#"{"error":{"status":"NOT_FOUND"}}"#),
            KeyProviderFailure::WrongKey
        );
        assert_eq!(
            protocol::classify(
                operation,
                403,
                br#"{"error":{"status":"PERMISSION_DENIED"}}"#
            ),
            KeyProviderFailure::PermissionDenied
        );
    }
    assert_eq!(
        protocol::classify(
            Operation::Encrypt,
            503,
            br#"{"error":{"status":"UNAVAILABLE"}}"#
        ),
        KeyProviderFailure::Unavailable
    );
    assert_eq!(
        protocol::classify(
            Operation::Encrypt,
            503,
            br#"{"error":{"message":"native-secret-canary"}}"#
        ),
        KeyProviderFailure::Ambiguous
    );
    assert_eq!(
        protocol::classify(Operation::Decrypt, 503, b"malformed-secret-canary"),
        KeyProviderFailure::Unavailable
    );
}

#[test]
fn published_google_version_response_requires_exact_enabled_symmetric_version()
-> Result<(), Box<dyn std::error::Error>> {
    // Relevant fields of the official CryptoKeyVersion JSON representation.
    let response = br#"{"name":"projects/project-1/locations/us-central1/keyRings/ring/cryptoKeys/root/cryptoKeyVersions/7","state":"ENABLED","algorithm":"GOOGLE_SYMMETRIC_ENCRYPTION","protectionLevel":"SOFTWARE"}"#;
    protocol::verify_metadata(response, &identity()?)?;
    let wrong = String::from_utf8(response.to_vec())?.replace("Versions/7", "Versions/8");
    assert_eq!(
        protocol::verify_metadata(wrong.as_bytes(), &identity()?),
        Err(KeyProviderFailure::WrongKey)
    );
    let disabled = String::from_utf8(response.to_vec())?.replace("ENABLED", "DISABLED");
    assert_eq!(
        protocol::verify_metadata(disabled.as_bytes(), &identity()?),
        Err(KeyProviderFailure::PermissionDenied)
    );
    Ok(())
}

#[test]
fn google_operations_route_encrypt_to_version_and_decrypt_to_parent()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = identity()?;
    assert_eq!(
        protocol::Operation::Metadata.endpoint(&identity)?,
        format!("https://cloudkms.googleapis.com/v1/{}", identity.locator())
    );
    assert_eq!(
        protocol::Operation::Encrypt.endpoint(&identity)?,
        format!(
            "https://cloudkms.googleapis.com/v1/{}:encrypt",
            identity.locator()
        )
    );
    assert_eq!(
        protocol::Operation::Decrypt.endpoint(&identity)?,
        "https://cloudkms.googleapis.com/v1/projects/project-1/locations/us-central1/keyRings/ring/cryptoKeys/root:decrypt"
    );
    assert_eq!(
        protocol::Operation::Encrypt.transport_failure(),
        KeyProviderFailure::Ambiguous
    );
    assert_eq!(
        protocol::Operation::Decrypt.transport_failure(),
        KeyProviderFailure::Unavailable
    );
    Ok(())
}

#[tokio::test]
async fn google_public_port_uses_published_wire_and_checks_context_before_io()
-> Result<(), Box<dyn std::error::Error>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let identity = identity()?;
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let payload = SecretWrappedKeyPayload::encode(
        &SecretKek::from_owned(Box::new([5; 32])),
        context,
        &identity,
    )?;
    let plaintext = Zeroizing::new(STANDARD.encode(payload.as_provider_plaintext()));
    let checksum = crc32c::crc32c(payload.as_provider_plaintext());
    let response = |bytes| google_cloud_auth::native::Response {
        status: http::StatusCode::OK,
        headers: http::HeaderMap::new(),
        body: Zeroizing::new(bytes),
    };
    let wire = std::collections::VecDeque::from([
        response(format!("{{\"name\":\"{}\",\"state\":\"ENABLED\",\"algorithm\":\"GOOGLE_SYMMETRIC_ENCRYPTION\",\"protectionLevel\":\"SOFTWARE\"}}", identity.locator()).into_bytes()),
        response(format!("{{\"name\":\"{}\",\"ciphertext\":\"MTIzNDU2Nzg5\",\"ciphertextCrc32c\":\"3808858755\",\"verifiedPlaintextCrc32c\":true,\"verifiedAdditionalAuthenticatedDataCrc32c\":true}}", identity.locator()).into_bytes()),
        response(format!("{{\"plaintext\":\"{}\",\"plaintextCrc32c\":\"{checksum}\"}}", plaintext.as_str()).into_bytes()),
    ]);
    let runtime = Arc::new(RejectedNativeAdc {
        wire: std::sync::Mutex::new(wire),
        ..RejectedNativeAdc::default()
    });
    let provider = GoogleCloudKmsKeyProvider {
        identity,
        credentials: FixtureCredentials.into(),
        runtime: runtime.clone(),
        active: AtomicBool::new(false),
    };
    assert!(provider.probe(context).await?.can_wrap);
    let envelope = provider.wrap(payload, context).await?;
    let wrong = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 2, 1)?;
    assert_eq!(
        provider.unwrap(&envelope, wrong).await.err(),
        Some(KeyProviderFailure::ContextMismatch)
    );
    assert_eq!(runtime.http_calls.load(Ordering::SeqCst), 2);
    provider
        .unwrap(&envelope, context)
        .await?
        .verify(context, provider.identity())?;
    let requests = runtime.requests.lock().expect("test request mutex");
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests[2].0,
        "https://cloudkms.googleapis.com/v1/projects/project-1/locations/us-central1/keyRings/ring/cryptoKeys/root:decrypt"
    );
    for (_, headers) in requests.iter() {
        assert_eq!(
            headers
                .get("x-goog-user-project")
                .and_then(|value| value.to_str().ok()),
            Some("fixture-quota-project")
        );
    }
    Ok(())
}

// Extend existing RejectedNativeAdc with:
// adc: Option<Vec<u8>>, rsa_calls: AtomicUsize, allow_rsa: bool.
// read_file: if let Some(adc) = &self.adc { return Ok(Zeroizing::new(adc.clone())); }
// rsa_sign: increment rsa_calls; when allow_rsa return Ok(vec![7; 32]), else Unavailable.

#[test]
fn google_plaintext_accepts_valid_escaped_json_without_unprotected_secret_strings()
-> Result<(), Box<dyn std::error::Error>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let identity = identity()?;
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let payload = SecretWrappedKeyPayload::encode(
        &SecretKek::from_owned(Box::new([5; 32])),
        context,
        &identity,
    )?;
    let encoded = Zeroizing::new(
        STANDARD
            .encode(payload.as_provider_plaintext())
            .replace("=", "\\u003d"),
    );
    let checksum = crc32c::crc32c(payload.as_provider_plaintext());
    let response = Zeroizing::new(format!(
        "{{\"plaintext\":\"{}\",\"plaintextCrc32c\":\"{checksum}\"}}",
        encoded.as_str()
    ));
    protocol::plaintext_response(response.as_bytes())?.verify(context, &identity)?;
    Ok(())
}

#[test]
fn google_deadline_exceeded_encrypt_is_ambiguous_and_never_retryable() {
    let reply = br#"{"error":{"status":"DEADLINE_EXCEEDED"}}"#;
    assert_eq!(
        protocol::classify(protocol::Operation::Encrypt, 504, reply),
        KeyProviderFailure::Ambiguous
    );
    assert_eq!(
        protocol::classify(protocol::Operation::Decrypt, 504, reply),
        KeyProviderFailure::Unavailable
    );
    assert_eq!(
        protocol::classify(protocol::Operation::Metadata, 504, reply),
        KeyProviderFailure::Unavailable
    );
}

#[test]
fn google_canonical_rpc_rejections_have_explicit_stable_classes() {
    for (code, status, expected) in [
        (400, "INVALID_ARGUMENT", KeyProviderFailure::ContextMismatch),
        (400, "OUT_OF_RANGE", KeyProviderFailure::ContextMismatch),
        (409, "ABORTED", KeyProviderFailure::ContextMismatch),
        (
            409,
            "ALREADY_EXISTS",
            KeyProviderFailure::InvalidConfiguration,
        ),
        (
            501,
            "UNIMPLEMENTED",
            KeyProviderFailure::InvalidConfiguration,
        ),
        (
            400,
            "FAILED_PRECONDITION",
            KeyProviderFailure::PermissionDenied,
        ),
        (500, "DATA_LOSS", KeyProviderFailure::ContextMismatch),
        (
            403,
            "PERMISSION_DENIED",
            KeyProviderFailure::PermissionDenied,
        ),
        (401, "UNAUTHENTICATED", KeyProviderFailure::PermissionDenied),
        (404, "NOT_FOUND", KeyProviderFailure::WrongKey),
        (429, "RESOURCE_EXHAUSTED", KeyProviderFailure::Unavailable),
        (503, "UNAVAILABLE", KeyProviderFailure::Unavailable),
    ] {
        let reply = format!(
            "{{\"error\":{{\"status\":\"{status}\",\"message\":\"native-secret-canary\"}}}}"
        );
        for operation in [
            protocol::Operation::Metadata,
            protocol::Operation::Encrypt,
            protocol::Operation::Decrypt,
        ] {
            assert_eq!(
                protocol::classify(operation, code, reply.as_bytes()),
                expected,
                "{status}"
            );
        }
    }
    for status in ["CANCELLED", "DEADLINE_EXCEEDED", "UNKNOWN", "INTERNAL"] {
        let reply = format!("{{\"error\":{{\"status\":\"{status}\"}}}}");
        assert_eq!(
            protocol::classify(protocol::Operation::Encrypt, 500, reply.as_bytes()),
            KeyProviderFailure::Ambiguous
        );
        assert_eq!(
            protocol::classify(protocol::Operation::Decrypt, 500, reply.as_bytes()),
            KeyProviderFailure::Unavailable
        );
    }
}

#[test]
fn google_published_wire_accepts_equivalent_escaped_resource_and_integrity_strings()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = identity()?;
    let name = identity.locator().replace('/', "\\/");
    let metadata = format!(
        r#"{{"name":"{name}","state":"ENABLED","algorithm":"GOOGLE_SYMMETRIC_ENCRYPTION","protectionLevel":"SOFTWARE"}}"#
    );
    protocol::verify_metadata(metadata.as_bytes(), &identity)?;
    let wrapped = format!(
        r#"{{"name":"{name}","ciphertext":"\u004dTIzNDU2Nzg5","ciphertextCrc32c":"\u0033808858755","verifiedPlaintextCrc32c":true,"verifiedAdditionalAuthenticatedDataCrc32c":true}}"#
    );
    assert_eq!(
        protocol::wrapped_response(wrapped.as_bytes(), &identity)?,
        b"123456789"
    );
    assert_eq!(
        protocol::classify(
            protocol::Operation::Encrypt,
            503,
            br#"{"error":{"status":"UN\u0041VAILABLE"}}"#
        ),
        KeyProviderFailure::Unavailable
    );
    Ok(())
}
