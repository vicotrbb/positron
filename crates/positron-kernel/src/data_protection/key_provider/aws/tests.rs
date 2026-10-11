//! Pure AWS wire-contract fixtures and local admission. No provider emulation.
use super::*;
use crate::data_protection::tests::providers::{cache_governor, cache_reservation};

fn identity() -> Result<ProviderKeyUri, KeyProviderFailure> {
    ProviderKeyUri::new(
        ProviderFamily::AwsKms,
        "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        "immutable",
    )
}
fn context() -> Result<EnvelopeContext, KeyProviderFailure> {
    EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)
}
#[test]
fn aws_operation_requires_the_complete_governor_grant_before_sdk_loading()
-> Result<(), Box<dyn std::error::Error>> {
    let kernel = cache_governor()?;
    let grant = cache_reservation(&kernel, 1)?;
    let future = AwsKmsKeyProvider::from_standard_chain(identity()?, grant);
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    use std::future::Future;
    assert!(matches!(
        future.as_mut().poll(&mut context),
        std::task::Poll::Ready(Err(KeyProviderFailure::LimitExceeded))
    ));
    Ok(())
}

#[test]
fn request_without_the_owning_tokio_runtime_is_a_closed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let kernel = crate::data_protection::tests::providers::provider_governor(200_000_000)?;
    let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
        AwsKmsKeyProvider::required_resources(),
    )?)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let provider = runtime.block_on(AwsKmsKeyProvider::from_standard_chain(identity()?, grant))?;
    let mut request = std::pin::pin!(provider.create_envelope(context()?));
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(matches!(
        std::future::Future::poll(request.as_mut(), &mut context),
        std::task::Poll::Ready(Err(KeyProviderFailure::InvalidConfiguration))
    ));
    Ok(())
}
#[test]
fn published_describe_key_response_pins_arn_and_symmetric_capability()
-> Result<(), Box<dyn std::error::Error>> {
    // AWS API DescribeKey's published example, restricted to relevant fields.
    let response = br#"{"KeyMetadata":{"Arn":"arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab","KeyId":"1234abcd-12ab-34cd-56ef-1234567890ab","Enabled":true,"KeyState":"Enabled","KeyUsage":"ENCRYPT_DECRYPT","KeySpec":"SYMMETRIC_DEFAULT","EncryptionAlgorithms":["SYMMETRIC_DEFAULT"]}}"#;
    protocol::verify_metadata(response, &identity()?)?;
    let disabled = String::from_utf8(response.to_vec())?.replace("true", "false");
    assert_eq!(
        protocol::verify_metadata(disabled.as_bytes(), &identity()?),
        Err(KeyProviderFailure::PermissionDenied)
    );
    let substituted = String::from_utf8(response.to_vec())?.replace("111122223333", "999999999999");
    assert_eq!(
        protocol::verify_metadata(substituted.as_bytes(), &identity()?),
        Err(KeyProviderFailure::WrongKey)
    );
    Ok(())
}
#[test]
fn native_encryption_context_is_identical_for_encrypt_and_decrypt_and_changes_with_epoch()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = identity()?;
    let context = context()?;
    let payload = SecretWrappedKeyPayload::encode(
        &SecretKek::from_owned(Box::new([5; 32])),
        context,
        &identity,
    )?;
    let encrypt = protocol::encrypt_request(&identity, context, payload.as_provider_plaintext())?;
    let decrypt = protocol::decrypt_request(&identity, context, &[9; 48])?;
    let encrypted: serde_json::Value = serde_json::from_slice(&encrypt)?;
    let decrypted: serde_json::Value = serde_json::from_slice(&decrypt)?;
    assert_eq!(
        encrypted.get("KeyId").and_then(|value| value.as_str()),
        Some(identity.locator())
    );
    assert_eq!(
        encrypted
            .get("EncryptionAlgorithm")
            .and_then(|value| value.as_str()),
        Some("SYMMETRIC_DEFAULT")
    );
    assert_eq!(
        encrypted.get("EncryptionContext"),
        decrypted.get("EncryptionContext")
    );
    let changed = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 2, 1)?;
    let request = protocol::decrypt_request(&identity, changed, &[9; 48])?;
    let changed: serde_json::Value = serde_json::from_slice(&request)?;
    assert_ne!(
        decrypted.get("EncryptionContext"),
        changed.get("EncryptionContext")
    );
    Ok(())
}
#[test]
fn response_identity_and_algorithm_are_verified_before_plaintext_transfer()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = identity()?;
    let response = br#"{"KeyId":"wrong-key","EncryptionAlgorithm":"SYMMETRIC_DEFAULT","Plaintext":"cHJvdmlkZXItc2VjcmV0LWNhbmFyeQ=="}"#;
    assert_eq!(
        protocol::plaintext_response(response, &identity).err(),
        Some(KeyProviderFailure::WrongKey)
    );
    let response = br#"{"KeyId":"wrong-key","EncryptionAlgorithm":"SYMMETRIC_DEFAULT","CiphertextBlob":"AQID"}"#;
    assert_eq!(
        protocol::wrapped_response(response, &identity).err(),
        Some(KeyProviderFailure::WrongKey)
    );
    let response = format!(
        r#"{{"KeyId":"{}","EncryptionAlgorithm":"RSAES_OAEP_SHA_256","Plaintext":"AQID"}}"#,
        identity.locator()
    );
    assert_eq!(
        protocol::plaintext_response(response.as_bytes(), &identity).err(),
        Some(KeyProviderFailure::ContextMismatch)
    );
    Ok(())
}
#[test]
fn documented_service_unavailability_is_retryable_even_for_encrypt() {
    let failure = protocol::classify(
        protocol::Operation::Encrypt,
        503,
        br#"{"__type":"com.amazonaws.kms#ServiceUnavailable","message":"outage-secret-canary"}"#,
    );
    assert_eq!(failure, KeyProviderFailure::Unavailable);
    assert_eq!(failure.disposition(), ProviderFailureDisposition::Retryable);
    assert!(!format!("{failure:?}{failure}").contains("outage-secret-canary"));
}
#[test]
fn documented_permanent_native_codes_override_server_status_without_retry() {
    for code in [
        "InvalidArnException",
        "InvalidKeyUsageException",
        "DryRunOperationException",
        "ExpiredTokenException",
        "IncompleteSignature",
        "MalformedHttpRequestException",
        "NotAuthorized",
        "OptInRequired",
        "RequestAbortedException",
        "RequestEntityTooLargeException",
        "UnknownOperationException",
        "UnrecognizedClientException",
        "ValidationError",
    ] {
        let response = format!(r#"{{"__type":"{code}"}}"#);
        for operation in [
            protocol::Operation::Describe,
            protocol::Operation::Encrypt,
            protocol::Operation::Decrypt,
        ] {
            for status in [400, 403, 500, 503] {
                let failure = protocol::classify(operation, status, response.as_bytes());
                assert_eq!(failure, KeyProviderFailure::PermissionDenied);
                assert_eq!(failure.disposition(), ProviderFailureDisposition::Permanent);
            }
        }
    }
}
#[test]
fn common_native_outages_and_unrecognized_server_failures_are_retryable() {
    for (status, body) in [
        (500, br#"{"__type":"InternalFailure"}"#.as_slice()),
        (408, br#"{"__type":"RequestTimeoutException"}"#.as_slice()),
        (500, b"".as_slice()),
        (502, b"malformed native response".as_slice()),
        (504, br#"{"__type":"UnknownFutureError"}"#.as_slice()),
    ] {
        assert_eq!(
            protocol::classify(protocol::Operation::Describe, status, body),
            KeyProviderFailure::Unavailable
        );
    }
}
#[test]
fn unknown_server_replies_preserve_encrypt_uncertainty_and_native_codes_are_authoritative() {
    use protocol::Operation;
    for status in [500, 502, 503, 504] {
        for body in [
            b"".as_slice(),
            b"malformed response".as_slice(),
            br#"{"__type":"FutureError","message":"response-secret-canary"}"#.as_slice(),
        ] {
            for operation in [Operation::Describe, Operation::Decrypt] {
                assert_eq!(
                    protocol::classify(operation, status, body),
                    KeyProviderFailure::Unavailable
                );
            }
            let failure = protocol::classify(Operation::Encrypt, status, body);
            assert_eq!(failure, KeyProviderFailure::Ambiguous);
            assert_eq!(failure.disposition(), ProviderFailureDisposition::Ambiguous);
            assert!(!format!("{failure:?}{failure}").contains("response-secret-canary"));
        }
        for operation in [Operation::Describe, Operation::Encrypt, Operation::Decrypt] {
            for (body, expected) in [
                (
                    br#"{"__type":"AccessDeniedException"}"#.as_slice(),
                    KeyProviderFailure::PermissionDenied,
                ),
                (
                    br#"{"__type":"IncorrectKeyException"}"#.as_slice(),
                    KeyProviderFailure::WrongKey,
                ),
                (
                    br#"{"__type":"InvalidCiphertextException"}"#.as_slice(),
                    KeyProviderFailure::ContextMismatch,
                ),
                (
                    br#"{"__type":"ThrottlingException"}"#.as_slice(),
                    KeyProviderFailure::Unavailable,
                ),
                (
                    br#"{"__type":"InternalFailure"}"#.as_slice(),
                    KeyProviderFailure::Unavailable,
                ),
            ] {
                assert_eq!(protocol::classify(operation, status, body), expected);
            }
        }
    }
    for operation in [Operation::Describe, Operation::Encrypt, Operation::Decrypt] {
        assert_eq!(
            protocol::classify(operation, 408, br#"{"__type":"RequestTimeoutException"}"#),
            KeyProviderFailure::Unavailable
        );
    }
}
#[test]
fn provider_error_classes_are_closed_and_secret_free() {
    for (code, expected) in [
        ("ThrottlingException", KeyProviderFailure::Unavailable),
        ("KMSInternalException", KeyProviderFailure::Unavailable),
        (
            "DependencyTimeoutException",
            KeyProviderFailure::Unavailable,
        ),
        ("KeyUnavailableException", KeyProviderFailure::Unavailable),
        (
            "InvalidCiphertextException",
            KeyProviderFailure::ContextMismatch,
        ),
        ("IncorrectKeyException", KeyProviderFailure::WrongKey),
        ("NotFoundException", KeyProviderFailure::WrongKey),
        (
            "AccessDeniedException",
            KeyProviderFailure::PermissionDenied,
        ),
        ("DisabledException", KeyProviderFailure::PermissionDenied),
        (
            "KMSInvalidStateException",
            KeyProviderFailure::PermissionDenied,
        ),
        ("UnknownFutureError", KeyProviderFailure::PermissionDenied),
    ] {
        let bytes = format!(
            r#"{{"__type":"com.amazonaws.kms#{}","message":"credential-secret-canary"}}"#,
            code
        );
        let actual = protocol::classify(protocol::Operation::Describe, 400, bytes.as_bytes());
        assert_eq!(actual, expected);
        assert!(!format!("{actual:?}{actual}").contains("credential-secret-canary"));
    }
    assert_eq!(
        protocol::classify(protocol::Operation::Describe, 429, b""),
        KeyProviderFailure::Unavailable
    );
    assert_eq!(
        protocol::Operation::Encrypt.transport_failure(),
        KeyProviderFailure::Ambiguous
    );
    assert_eq!(
        protocol::Operation::Decrypt.transport_failure(),
        KeyProviderFailure::Unavailable
    );
}

#[test]
fn aws_envelope_rejects_a_non_native_wrapping_algorithm_before_io()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        KeyEnvelope::from_provider_response(
            identity()?,
            context()?,
            WrappingAlgorithm::RsaOaepSha256,
            vec![9; 48]
        )
        .err(),
        Some(KeyProviderFailure::ContextMismatch)
    );
    Ok(())
}

#[test]
fn native_response_bounds_and_canonical_payload_authentication_are_preserved()
-> Result<(), Box<dyn std::error::Error>> {
    use base64::Engine;
    let identity = identity()?;
    let context = context()?;
    let key = SecretKek::from_owned(Box::new([5; 32]));
    let payload = SecretWrappedKeyPayload::encode(&key, context, &identity)?;
    let encoded = zeroize::Zeroizing::new(
        base64::engine::general_purpose::STANDARD.encode(payload.as_provider_plaintext()),
    );
    let response = zeroize::Zeroizing::new(format!(
        r#"{{"KeyId":"{}","EncryptionAlgorithm":"SYMMETRIC_DEFAULT","Plaintext":"{}"}}"#,
        identity.locator(),
        &*encoded,
    ));
    let decoded = protocol::plaintext_response(response.as_bytes(), &identity)?;
    let recovered = decoded.verify(context, &identity)?;
    use subtle::ConstantTimeEq;
    assert!(bool::from(
        recovered
            .0
            .expose_to_backend()
            .ct_eq(key.0.expose_to_backend())
    ));
    let wrong = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 2, 1)?;
    let decoded = protocol::plaintext_response(response.as_bytes(), &identity)?;
    assert_eq!(
        decoded.verify(wrong, &identity).err(),
        Some(KeyProviderFailure::ContextMismatch)
    );
    let wrapped = format!(
        r#"{{"KeyId":"{}","EncryptionAlgorithm":"SYMMETRIC_DEFAULT","CiphertextBlob":"AQID"}}"#,
        identity.locator()
    );
    assert_eq!(
        protocol::wrapped_response(wrapped.as_bytes(), &identity)?,
        vec![1, 2, 3]
    );
    assert_eq!(
        protocol::plaintext_response(&vec![b' '; protocol::RESPONSE_BYTES + 1], &identity).err(),
        Some(KeyProviderFailure::LimitExceeded)
    );
    assert_eq!(
        protocol::plaintext_response(b"{}", &identity).err(),
        Some(KeyProviderFailure::ContextMismatch)
    );
    assert_eq!(
        protocol::encrypt_request(&identity, context, &[0; 1025]).err(),
        Some(KeyProviderFailure::LimitExceeded)
    );
    assert_eq!(
        protocol::decrypt_request(&identity, context, &[0; 6145]).err(),
        Some(KeyProviderFailure::LimitExceeded)
    );
    Ok(())
}

#[test]
fn identity_transport_requires_tls_except_native_local_workload_addresses() {
    for uri in [
        "https://sts.us-east-2.amazonaws.com/",
        "http://169.254.169.254/",
        "http://169.254.170.2/",
        "http://169.254.170.23/",
        "http://[fd00:ec2::23]/",
        "http://[fd00:ec2::254]/",
        "http://127.0.0.1:8080/",
        "http://[::1]:8080/",
        "http://localhost:8080/",
        "http://metadata-alias.example/",
    ] {
        assert!(credentials_http::checked_uri(uri).is_ok());
    }
    for uri in [
        "file:///credentials",
        "https://user:credential-canary@example.com/",
        "https://example.com/#credential-canary",
    ] {
        assert_eq!(
            credentials_http::checked_uri(uri).err(),
            Some(KeyProviderFailure::InvalidConfiguration)
        );
    }
    assert_eq!(
        credentials_http::checked_uri(&"x".repeat(4097)).err(),
        Some(KeyProviderFailure::LimitExceeded)
    );
}

#[test]
fn every_bound_http_address_must_be_local_and_dns_collection_is_capped()
-> Result<(), Box<dyn std::error::Error>> {
    let local = [
        "127.0.0.1:80".parse()?,
        "[::1]:80".parse()?,
        "169.254.170.2:80".parse()?,
    ];
    credentials_http::local_addresses(&local)?;
    let mixed = [local[0], "192.0.2.1:80".parse()?];
    assert_eq!(
        credentials_http::local_addresses(&mixed),
        Err(KeyProviderFailure::InvalidConfiguration)
    );
    assert_eq!(
        credentials_http::local_addresses(&[]),
        Err(KeyProviderFailure::LimitExceeded)
    );
    assert_eq!(
        dns::collect_addresses(std::iter::repeat_n(local[0], 17)).err(),
        Some(KeyProviderFailure::LimitExceeded)
    );
    assert_eq!(
        dns::collect_addresses(std::iter::empty()).err(),
        Some(KeyProviderFailure::Unavailable)
    );
    assert_eq!(dns::collect_addresses(local.into_iter())?, local);
    Ok(())
}

#[test]
fn native_identity_failures_keep_configuration_distinct_from_outage_without_sources() {
    use aws_credential_types::provider::error::CredentialsError;
    for (error, expected) in [
        (
            CredentialsError::invalid_configuration("credential-error-canary"),
            KeyProviderFailure::InvalidConfiguration,
        ),
        (
            CredentialsError::unhandled("credential-error-canary"),
            KeyProviderFailure::InvalidConfiguration,
        ),
        (
            CredentialsError::not_loaded("credential-error-canary"),
            KeyProviderFailure::Unavailable,
        ),
        (
            CredentialsError::provider_error("credential-error-canary"),
            KeyProviderFailure::Unavailable,
        ),
        (
            CredentialsError::provider_timed_out(Duration::from_secs(1)),
            KeyProviderFailure::Unavailable,
        ),
    ] {
        let failure = credential_failure(error);
        assert_eq!(failure, expected);
        assert!(!format!("{failure:?}{failure}").contains("credential-error-canary"));
    }
}
