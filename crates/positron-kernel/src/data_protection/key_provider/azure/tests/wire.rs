use super::*;

#[tokio::test]
async fn published_wrap_response_becomes_pinned_context_envelope()
-> Result<(), Box<dyn std::error::Error>> {
    let provider = fixture(vec![metadata(), metadata(), result(&[7; 256])]);
    let envelope = KeyProviderSession::new(&provider)
        .wrap(SecretKek::from_owned(Box::new([9; 32])), context())
        .await?;
    assert_eq!(envelope.identity(), &uri());
    assert_eq!(envelope.ciphertext(), &[7; 256]);
    Ok(())
}

#[tokio::test]
async fn unwrap_authenticates_embedded_context_after_untrusted_routing_passes()
-> Result<(), Box<dyn std::error::Error>> {
    let canonical = payload(context(), &uri());
    let provider = fixture(vec![metadata(), result(canonical.as_provider_plaintext())]);
    let envelope = KeyEnvelope::from_provider_response(
        uri(),
        context(),
        WrappingAlgorithm::RsaOaepSha256,
        vec![7; 256],
    )?;
    let recovered = provider.unwrap(&envelope, context()).await?;
    assert!(recovered.verify(context(), &uri()).is_ok());
    let wrong = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 2, 1)?;
    let substituted = KeyEnvelope::from_provider_response(
        uri(),
        wrong,
        WrappingAlgorithm::RsaOaepSha256,
        vec![7; 256],
    )?;
    let provider = fixture(vec![metadata(), result(canonical.as_provider_plaintext())]);
    assert_eq!(
        provider.unwrap(&substituted, wrong).await.err(),
        Some(KeyProviderFailure::ContextMismatch)
    );
    Ok(())
}
#[tokio::test]
async fn metadata_and_crypto_receipts_reject_wrong_key_disabled_and_malformed_boundaries()
-> Result<(), Box<dyn std::error::Error>> {
    for (bytes, expected) in [
        (
            String::from_utf8(metadata())?
                .replace("fixture.vault", "other.vault")
                .into_bytes(),
            KeyProviderFailure::WrongKey,
        ),
        (
            String::from_utf8(metadata())?
                .replace("\"enabled\":true", "\"enabled\":false")
                .into_bytes(),
            KeyProviderFailure::PermissionDenied,
        ),
        (
            String::from_utf8(metadata())?
                .replace("RSA", "EC")
                .into_bytes(),
            KeyProviderFailure::PermissionDenied,
        ),
        (
            String::from_utf8(metadata())?
                .replace("unwrapKey", "sign")
                .into_bytes(),
            KeyProviderFailure::PermissionDenied,
        ),
        (
            String::from_utf8(metadata())?
                .replace("AQAB", "Ag")
                .into_bytes(),
            KeyProviderFailure::InvalidConfiguration,
        ),
        (
            String::from_utf8(metadata())?
                .replace(
                    "\"enabled\":true",
                    "\"enabled\":true,\"nbf\":18446744073709551615",
                )
                .into_bytes(),
            KeyProviderFailure::PermissionDenied,
        ),
        (
            String::from_utf8(metadata())?
                .replace("\"enabled\":true", "\"enabled\":true,\"exp\":0")
                .into_bytes(),
            KeyProviderFailure::PermissionDenied,
        ),
        (b"{".to_vec(), KeyProviderFailure::ContextMismatch),
        (vec![b' '; 32769], KeyProviderFailure::LimitExceeded),
    ] {
        assert_eq!(
            fixture(vec![bytes]).probe(context()).await.err(),
            Some(expected)
        );
    }
    for (bytes, expected) in [
        (
            result(&[7; 256]).into_iter().take(20).collect(),
            KeyProviderFailure::ContextMismatch,
        ),
        (
            String::from_utf8(result(&[7; 256]))?
                .replace("fixture.vault", "other.vault")
                .into_bytes(),
            KeyProviderFailure::WrongKey,
        ),
        (result(&[7; 255]), KeyProviderFailure::ContextMismatch),
        (result(&[7; 513]), KeyProviderFailure::LimitExceeded),
        (
            format!(
                r#"{{"kid":"{}","value":"invalid+base64"}}"#,
                uri().locator()
            )
            .into_bytes(),
            KeyProviderFailure::ContextMismatch,
        ),
        (
            format!(r#"{{"kid":"{}","value":""}}"#, uri().locator()).into_bytes(),
            KeyProviderFailure::ContextMismatch,
        ),
    ] {
        assert_eq!(
            fixture(vec![metadata(), bytes])
                .wrap(payload(context(), &uri()), context())
                .await
                .err(),
            Some(expected)
        );
    }
    Ok(())
}
#[tokio::test(start_paused = true)]
async fn retry_classification_is_bounded_and_provider_messages_are_redacted()
-> Result<(), Box<dyn std::error::Error>> {
    for (status, expected, attempts) in [
        (401, KeyProviderFailure::PermissionDenied, 1),
        (403, KeyProviderFailure::PermissionDenied, 1),
        (404, KeyProviderFailure::WrongKey, 1),
        (410, KeyProviderFailure::WrongKey, 1),
        (429, KeyProviderFailure::Unavailable, 2),
        (500, KeyProviderFailure::Ambiguous, 1),
        (503, KeyProviderFailure::Ambiguous, 1),
        (400, KeyProviderFailure::ContextMismatch, 1),
    ] {
        let runtime = Arc::new(Transcript {
            replies: Mutex::new(
                std::iter::once(native::Response {
                    status: http::StatusCode::OK,
                    headers: http::HeaderMap::new(),
                    body: Zeroizing::new(metadata()),
                })
                .chain((0..attempts).map(|_| native::Response {
                    status: http::StatusCode::from_u16(status).expect("published status"),
                    headers: http::HeaderMap::new(),
                    body: Zeroizing::new(b"secret-error-canary".to_vec()),
                }))
                .collect(),
            ),
            requests: Mutex::new(Vec::new()),
            wait_when_exhausted: false,
        });
        let mut provider = fixture(vec![]);
        provider.runtime = runtime.clone();
        let failure = provider
            .wrap(payload(context(), &uri()), context())
            .await
            .err()
            .ok_or("failure transcript accepted")?;
        assert_eq!(failure, expected);
        assert_eq!(
            runtime.requests.lock().map_err(|_| "poisoned")?.len(),
            attempts + 1
        );
        assert!(!format!("{failure:?} {failure}").contains("canary"));
        let requests = runtime.requests.lock().map_err(|_| "poisoned")?;
        let wrap = requests.get(1).ok_or("missing wrap request")?;
        assert_eq!(wrap.method, http::Method::POST);
        assert_eq!(
            wrap.url,
            format!("{}/wrapkey?api-version=7.6", uri().locator())
        );
        let body: serde_json::Value = serde_json::from_slice(&wrap.body)?;
        assert_eq!(
            body.get("alg").and_then(serde_json::Value::as_str),
            Some("RSA-OAEP-256")
        );
    }
    Ok(())
}
