use super::*;

#[test]
fn native_identity_crypto_uses_published_hmac_and_rejects_invalid_rsa_keys()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::data_protection::{CryptoBackend, RustCryptoBackend};
    // RFC 4231 test case 1; deliberately a 20-byte HMAC key, not a KEK.
    assert_eq!(
        RustCryptoBackend.native_identity_hmac(&[0x0b; 20], b"Hi There"),
        Ok([
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ])
    );
    assert!(
        RustCryptoBackend
            .native_identity_rsa_sign(b"malformed-secret-canary", b"message")
            .is_err()
    );
    Ok(())
}

#[test]
fn native_google_aad_is_shared_by_encrypt_and_decrypt_and_bound_to_epoch()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = identity()?;
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let encrypt = protocol::encrypt_request(&identity, context, b"payload")?;
    let decrypt = protocol::decrypt_request(&identity, context, b"ciphertext")?;
    let encrypt: serde_json::Value = serde_json::from_slice(&encrypt)?;
    let decrypt: serde_json::Value = serde_json::from_slice(&decrypt)?;
    assert_eq!(
        encrypt.get("additionalAuthenticatedData"),
        decrypt.get("additionalAuthenticatedData")
    );
    assert_eq!(
        encrypt.get("plaintext").and_then(|value| value.as_str()),
        Some("cGF5bG9hZA==")
    );
    let changed = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 2, 1)?;
    let other: serde_json::Value = serde_json::from_slice(&protocol::decrypt_request(
        &identity,
        changed,
        b"ciphertext",
    )?)?;
    assert_ne!(
        decrypt.get("additionalAuthenticatedData"),
        other.get("additionalAuthenticatedData")
    );
    Ok(())
}

#[test]
fn native_identity_rsa_signs_the_published_ring_example_with_rs256_parameters() {
    use crate::data_protection::{CryptoBackend, RustCryptoBackend};
    let pem = Zeroizing::new(include_bytes!("fixtures/ring-example-rsa-2048.pem").to_vec());
    let signature = RustCryptoBackend
        .native_identity_rsa_sign(&pem, b"hello, world")
        .expect("published RSA key must sign");
    assert_eq!(signature.len(), 256);
    assert!(
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            include_bytes!("fixtures/ring-example-rsa-2048-public.der")
        )
        .verify(b"hello, world", &signature)
        .is_ok()
    );
    assert!(
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            include_bytes!("fixtures/ring-example-rsa-2048-public.der")
        )
        .verify(b"changed message", &signature)
        .is_err()
    );
}
#[test]
fn native_subject_token_debug_redacts_credential_material() {
    let token =
        google_cloud_auth::credentials::subject_token::Builder::new("native-subject-debug-canary")
            .build();
    assert!(!format!("{token:?}").contains("native-subject-debug-canary"));
}
