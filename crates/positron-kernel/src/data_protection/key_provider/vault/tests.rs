use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use google_cloud_auth::native;
mod lifecycle;
mod openbao;

struct Transcript {
    replies: Mutex<std::collections::VecDeque<native::Response>>,
    requests: Mutex<Vec<native::Request>>,
    pending: bool,
    delay: Duration,
}
impl std::fmt::Debug for Transcript {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PublishedVaultTranscript")
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
            tokio::time::sleep(self.delay).await;
            match reply {
                Some(reply) => Ok(reply),
                None if self.pending => std::future::pending().await,
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
fn uri() -> ProviderKeyUri {
    ProviderKeyUri::new(
        ProviderFamily::VaultTransit,
        "https://vault.example:8200/v1/transit/keys/root",
        "1",
    )
    .expect("fixed URI")
}
fn context() -> EnvelopeContext {
    EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1).expect("fixed context")
}
fn payload(context: EnvelopeContext, identity: &ProviderKeyUri) -> SecretWrappedKeyPayload {
    SecretWrappedKeyPayload::encode(&SecretKek::from_owned(Box::new([9; 32])), context, identity)
        .expect("canonical fixture payload")
}
const HEALTH: &[u8] = br#"{"version":"2.1.2","initialized":true,"sealed":false,"standby":false}"#;
const METADATA: &[u8] = br#"{"data":{"name":"root","type":"aes256-gcm96","derived":true,"convergent_encryption":false,"supports_encryption":true,"supports_decryption":true,"min_available_version":0,"min_decryption_version":1,"min_encryption_version":0,"latest_version":1,"keys":{"1":1442851412}}}"#;
// Published Transit tutorial ciphertext; this is a wire transcript, not local
// encryption by an emulated Vault. Cryptographic frame vectors remain shared.
const CIPHERTEXT: &str = "vault:v1:XjsPWPjqPrBi1N2Ms2s1QM798YyFWnO4TR4lsFA=";
fn reply(bytes: impl AsRef<[u8]>) -> native::Response {
    native::Response {
        status: http::StatusCode::OK,
        headers: http::HeaderMap::new(),
        body: Zeroizing::new(bytes.as_ref().to_vec()),
    }
}
fn encrypted() -> native::Response {
    reply(format!(
        r#"{{"data":{{"ciphertext":"{CIPHERTEXT}","key_version":1}}}}"#
    ))
}
fn decrypted(context: EnvelopeContext, identity: &ProviderKeyUri) -> native::Response {
    let plain = payload(context, identity);
    let encoded = Zeroizing::new(STANDARD.encode(plain.as_provider_plaintext()));
    reply(Zeroizing::new(format!(
        r#"{{"data":{{"plaintext":"{}"}}}}"#,
        encoded.as_str()
    )))
}
fn fixture(replies: Vec<native::Response>) -> (VaultTransitKeyProvider, Arc<Transcript>) {
    let transcript = Arc::new(Transcript {
        replies: Mutex::new(replies.into()),
        requests: Mutex::new(Vec::new()),
        pending: false,
        delay: Duration::ZERO,
    });
    let now = tokio::time::Instant::now();
    let provider = VaultTransitKeyProvider {
        identity: uri(),
        credential_model: ProviderCredentialModel::Transit(
            TransitAuthentication::ProtectedTokenFile(
                CredentialFileReference::new(std::path::Path::new("/fictional/token"))
                    .expect("reference"),
            ),
        ),
        authentication_mount: String::new(),
        runtime: transcript.clone(),
        token: Mutex::new(Some(authentication::Token {
            value: Zeroizing::new("fictional-token-canary".to_owned()),
            renew_at: now + Duration::from_secs(100),
            expires_at: now + Duration::from_secs(200),
        })),
        active: AtomicBool::new(false),
    };
    (provider, transcript)
}

#[test]
fn published_vault_212_health_receipt_pins_service_version()
-> Result<(), Box<dyn std::error::Error>> {
    protocol::verify_health(
        br#"{"version":"2.1.2","initialized":true,"sealed":false,"standby":false}"#,
        ProviderFamily::VaultTransit,
    )?;
    assert_eq!(
        protocol::verify_health(
            br#"{"version":"2.1.1","initialized":true,"sealed":false,"standby":false}"#,
            ProviderFamily::VaultTransit,
        ),
        Err(KeyProviderFailure::InvalidConfiguration)
    );
    Ok(())
}

#[tokio::test]
async fn native_wrap_and_unwrap_bind_exact_mount_version_and_full_payload()
-> Result<(), Box<dyn std::error::Error>> {
    let (provider, transcript) = fixture(vec![
        reply(HEALTH),
        reply(METADATA),
        encrypted(),
        reply(HEALTH),
        reply(METADATA),
        decrypted(context(), &uri()),
    ]);
    let envelope = provider.wrap(payload(context(), &uri()), context()).await?;
    assert_eq!(envelope.identity(), &uri());
    assert_eq!(envelope.ciphertext(), CIPHERTEXT.as_bytes());
    provider
        .unwrap(&envelope, context())
        .await?
        .verify(context(), &uri())?;
    let requests = transcript.requests.lock().map_err(|_| "poisoned")?;
    assert_eq!(requests.len(), 6);
    assert_eq!(
        requests.get(2).ok_or("missing encrypt")?.url,
        "https://vault.example:8200/v1/transit/encrypt/root"
    );
    let encrypt: serde_json::Value =
        serde_json::from_slice(&requests.get(2).ok_or("missing encrypt")?.body)?;
    assert_eq!(encrypt.get("key_version"), Some(&serde_json::json!(1)));
    assert_eq!(encrypt.get("context"), encrypt.get("associated_data"));
    assert!(encrypt.get("nonce").is_none());
    assert!(encrypt.get("batch_input").is_none());
    assert_eq!(
        requests.get(5).ok_or("missing decrypt")?.url,
        "https://vault.example:8200/v1/transit/decrypt/root"
    );
    assert!(
        requests
            .iter()
            .filter_map(|r| r.headers.get("x-vault-token"))
            .all(http::HeaderValue::is_sensitive)
    );
    Ok(())
}

#[tokio::test]
async fn native_unwrap_rejects_payload_substitution_after_routing_matches()
-> Result<(), Box<dyn std::error::Error>> {
    let wrong = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 2, 1)?;
    let (provider, _) = fixture(vec![
        reply(HEALTH),
        reply(METADATA),
        decrypted(context(), &uri()),
    ]);
    let envelope = KeyEnvelope::from_provider_response(
        uri(),
        wrong,
        WrappingAlgorithm::Aes256Gcm,
        CIPHERTEXT.as_bytes().to_vec(),
    )?;
    assert_eq!(
        provider.unwrap(&envelope, wrong).await.err(),
        Some(KeyProviderFailure::ContextMismatch)
    );
    let (provider, transcript) = fixture(vec![]);
    assert_eq!(
        provider.unwrap(&envelope, context()).await.err(),
        Some(KeyProviderFailure::ContextMismatch)
    );
    assert!(
        transcript
            .requests
            .lock()
            .map_err(|_| "poisoned")?
            .is_empty()
    );
    for (ciphertext, algorithm, expected) in [
        (
            CIPHERTEXT.replace("v1:", "v2:").into_bytes(),
            WrappingAlgorithm::Aes256Gcm,
            KeyProviderFailure::WrongKey,
        ),
        (
            b"vault:v1:!".to_vec(),
            WrappingAlgorithm::Aes256Gcm,
            KeyProviderFailure::ContextMismatch,
        ),
        (
            CIPHERTEXT.as_bytes().to_vec(),
            WrappingAlgorithm::Aes256Kwp,
            KeyProviderFailure::ContextMismatch,
        ),
    ] {
        let envelope =
            KeyEnvelope::from_provider_response(uri(), context(), algorithm, ciphertext)?;
        assert_eq!(
            provider.unwrap(&envelope, context()).await.err(),
            Some(expected)
        );
    }
    Ok(())
}

#[tokio::test]
async fn metadata_health_and_crypto_receipts_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    for (source, from, to, expected) in [
        (
            HEALTH,
            "2.1.2",
            "2.1.1",
            KeyProviderFailure::InvalidConfiguration,
        ),
        (
            HEALTH,
            "\"sealed\":false",
            "\"sealed\":true",
            KeyProviderFailure::Unavailable,
        ),
        (
            METADATA,
            "\"root\"",
            "\"other\"",
            KeyProviderFailure::WrongKey,
        ),
        (
            METADATA,
            "aes256-gcm96",
            "aes128-gcm96",
            KeyProviderFailure::InvalidConfiguration,
        ),
        (
            METADATA,
            "\"derived\":true",
            "\"derived\":false",
            KeyProviderFailure::InvalidConfiguration,
        ),
        (
            METADATA,
            "\"convergent_encryption\":false",
            "\"convergent_encryption\":true",
            KeyProviderFailure::InvalidConfiguration,
        ),
        (
            METADATA,
            "\"supports_decryption\":true",
            "\"supports_decryption\":false",
            KeyProviderFailure::PermissionDenied,
        ),
        (
            METADATA,
            "\"min_decryption_version\":1",
            "\"min_decryption_version\":2",
            KeyProviderFailure::PermissionDenied,
        ),
        (
            METADATA,
            "\"min_encryption_version\":0",
            "\"min_encryption_version\":2",
            KeyProviderFailure::PermissionDenied,
        ),
    ] {
        let changed = String::from_utf8(source.to_vec())?.replace(from, to);
        let replies = if source == HEALTH {
            vec![reply(changed)]
        } else {
            vec![reply(HEALTH), reply(changed)]
        };
        let (provider, _) = fixture(replies);
        assert_eq!(
            provider
                .wrap(payload(context(), &uri()), context())
                .await
                .err(),
            Some(expected)
        );
    }
    for bytes in [
        b"{}".to_vec(),
        vec![b' '; 32769],
        br#"{"data":{"ciphertext":"vault:v2:AAAA","key_version":2}}"#.to_vec(),
    ] {
        let (provider, _) = fixture(vec![reply(HEALTH), reply(METADATA), reply(bytes)]);
        assert!(
            provider
                .wrap(payload(context(), &uri()), context())
                .await
                .is_err()
        );
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn native_outages_throttling_and_deadlines_do_not_replay_uncertain_encryption()
-> Result<(), Box<dyn std::error::Error>> {
    for (status, expected) in [
        (403, KeyProviderFailure::PermissionDenied),
        (404, KeyProviderFailure::WrongKey),
        (400, KeyProviderFailure::ContextMismatch),
        (500, KeyProviderFailure::Ambiguous),
        (503, KeyProviderFailure::Unavailable),
    ] {
        let mut failure = reply(b"secret-response-canary");
        failure.status = http::StatusCode::from_u16(status)?;
        let (provider, transcript) = fixture(vec![reply(HEALTH), reply(METADATA), failure]);
        let error = provider
            .wrap(payload(context(), &uri()), context())
            .await
            .err()
            .ok_or("failure accepted")?;
        assert_eq!(error, expected);
        assert!(!format!("{error:?} {error}").contains("canary"));
        assert_eq!(transcript.requests.lock().map_err(|_| "poisoned")?.len(), 3);
    }
    let mut throttled = reply(b"{\"errors\":[\"rate limit exceeded\"]}");
    throttled.status = http::StatusCode::TOO_MANY_REQUESTS;
    throttled.headers.insert(
        http::header::RETRY_AFTER,
        http::HeaderValue::from_static("1"),
    );
    let (provider, transcript) =
        fixture(vec![reply(HEALTH), reply(METADATA), throttled, encrypted()]);
    provider.wrap(payload(context(), &uri()), context()).await?;
    assert_eq!(transcript.requests.lock().map_err(|_| "poisoned")?.len(), 4);
    let (mut provider, _) = fixture(vec![reply(HEALTH), reply(METADATA)]);
    let transcript = Arc::new(Transcript {
        replies: Mutex::new(vec![reply(HEALTH), reply(METADATA)].into()),
        requests: Mutex::new(Vec::new()),
        pending: true,
        delay: Duration::ZERO,
    });
    provider.runtime = transcript.clone();
    let wrapping = provider.wrap(payload(context(), &uri()), context());
    tokio::pin!(wrapping);
    tokio::select! { result=&mut wrapping=>panic!("pending request completed {}",result.is_ok()), ()=tokio::task::yield_now()=>{} }
    assert_eq!(
        provider.probe(context()).await.err(),
        Some(KeyProviderFailure::LimitExceeded)
    );
    assert_eq!(wrapping.await.err(), Some(KeyProviderFailure::Ambiguous));
    assert_eq!(transcript.requests.lock().map_err(|_| "poisoned")?.len(), 3);
    Ok(())
}

#[tokio::test]
async fn native_login_refuses_limited_use_machine_tokens() -> Result<(), Box<dyn std::error::Error>>
{
    use std::os::unix::fs::PermissionsExt;
    let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let file = root.path.join("jwt");
    std::fs::write(&file, b"fictional-projected-jwt-canary")?;
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))?;
    let (mut provider,_) = fixture(vec![reply(br#"{"auth":{"client_token":"fictional-machine-token","lease_duration":300,"renewable":true,"token_type":"service","num_uses":1}}"#),reply(HEALTH),reply(METADATA)]);
    provider.credential_model =
        ProviderCredentialModel::Transit(TransitAuthentication::Kubernetes {
            role: "positron".to_owned(),
            jwt_file: CredentialFileReference::new(&file)?,
        });
    provider.authentication_mount = "kubernetes".to_owned();
    *provider.token.lock().map_err(|_| "poisoned")? = None;
    assert_eq!(
        provider.probe(context()).await.err(),
        Some(KeyProviderFailure::PermissionDenied)
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn native_login_transport_delay_cannot_extend_the_vault_token_lease()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let file = root.path.join("jwt");
    std::fs::write(&file, b"fictional-jwt-canary")?;
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))?;
    let (mut provider, _) = fixture(vec![]);
    provider.credential_model = ProviderCredentialModel::Transit(TransitAuthentication::Jwt {
        role: "positron".to_owned(),
        jwt_file: CredentialFileReference::new(&file)?,
    });
    provider.authentication_mount = "jwt".to_owned();
    *provider.token.lock().map_err(|_| "poisoned")? = None;
    let transcript=Arc::new(Transcript {replies:Mutex::new(vec![reply(br#"{"auth":{"client_token":"fictional-machine-token","lease_duration":2,"renewable":true,"token_type":"service","num_uses":0}}"#),reply(HEALTH),reply(METADATA)].into()),requests:Mutex::new(Vec::new()),pending:false,delay:Duration::from_secs(2)});
    provider.runtime = transcript.clone();
    assert_eq!(
        provider.probe(context()).await.err(),
        Some(KeyProviderFailure::Unavailable)
    );
    assert_eq!(transcript.requests.lock().map_err(|_| "poisoned")?.len(), 1);
    Ok(())
}
