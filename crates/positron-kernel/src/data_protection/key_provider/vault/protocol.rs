//! Independently verified native Transit v1 fields: Vault 2.1.2 (76fdd658)
//! and OpenBao 2.7.1 (a5db72ce). See each target's operations document.
use super::super::wire::SecretText;
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy)]
pub(super) enum Operation {
    Health,
    Metadata,
    Login,
    Lookup,
    Renew,
    Encrypt,
    Decrypt,
}
impl Operation {
    pub(super) fn method(self) -> http::Method {
        match self {
            Self::Health | Self::Metadata | Self::Lookup => http::Method::GET,
            _ => http::Method::POST,
        }
    }
    pub(super) fn endpoint(
        self,
        identity: &ProviderKeyUri,
        auth_mount: &str,
    ) -> Result<String, KeyProviderFailure> {
        let (base, key) = identity
            .locator()
            .rsplit_once("/keys/")
            .ok_or(KeyProviderFailure::InvalidConfiguration)?;
        let (origin, _) = base
            .split_once("/v1/")
            .ok_or(KeyProviderFailure::InvalidConfiguration)?;
        Ok(match self {
            Self::Health => format!("{origin}/v1/sys/health"),
            Self::Metadata => identity.locator().to_owned(),
            Self::Login => format!("{origin}/v1/auth/{auth_mount}/login"),
            Self::Lookup => format!("{origin}/v1/auth/token/lookup-self"),
            Self::Renew => format!("{origin}/v1/auth/token/renew-self"),
            Self::Encrypt => format!("{base}/encrypt/{key}"),
            Self::Decrypt => format!("{base}/decrypt/{key}"),
        })
    }
    pub(super) const fn transport_failure(self) -> KeyProviderFailure {
        match self {
            Self::Encrypt | Self::Login | Self::Renew => KeyProviderFailure::Ambiguous,
            _ => KeyProviderFailure::Unavailable,
        }
    }
    pub(super) const fn classify(self, status: u16) -> KeyProviderFailure {
        match status {
            401 | 403 => KeyProviderFailure::PermissionDenied,
            404 => KeyProviderFailure::WrongKey,
            429 | 503 => KeyProviderFailure::Unavailable,
            500..=599 => self.transport_failure(),
            _ => KeyProviderFailure::ContextMismatch,
        }
    }
}
pub(super) fn retry_delay(headers: &http::HeaderMap) -> Result<Duration, KeyProviderFailure> {
    let seconds = match headers.get(http::header::RETRY_AFTER) {
        Some(value) => value
            .to_str()
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|s| *s <= 2)
            .ok_or(KeyProviderFailure::Unavailable)?,
        None => return Ok(Duration::from_millis(100)),
    };
    Ok(Duration::from_millis((seconds * 1000).max(100)))
}
fn parse<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, KeyProviderFailure> {
    if bytes.len() > 32768 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    serde_json::from_slice(bytes).map_err(|_| KeyProviderFailure::ContextMismatch)
}
#[derive(Deserialize)]
struct Health<'a> {
    #[serde(borrow)]
    version: SecretText<'a>,
    initialized: bool,
    sealed: bool,
    standby: bool,
}
pub(super) fn verify_health(
    bytes: &[u8],
    family: ProviderFamily,
) -> Result<(), KeyProviderFailure> {
    let health: Health<'_> = parse(bytes)?;
    let expected = match family {
        ProviderFamily::VaultTransit => "2.1.2",
        ProviderFamily::OpenBaoTransit => "2.7.1",
        _ => return Err(KeyProviderFailure::InvalidConfiguration),
    };
    if health.version.as_str() != expected {
        return Err(KeyProviderFailure::InvalidConfiguration);
    }
    if !health.initialized || health.sealed || health.standby {
        return Err(KeyProviderFailure::Unavailable);
    }
    Ok(())
}
#[derive(Deserialize)]
struct MetadataReply<'a> {
    #[serde(borrow)]
    data: Metadata<'a>,
}
#[derive(Deserialize)]
struct Metadata<'a> {
    #[serde(borrow)]
    name: SecretText<'a>,
    #[serde(rename = "type", borrow)]
    key_type: SecretText<'a>,
    derived: bool,
    convergent_encryption: bool,
    supports_encryption: bool,
    supports_decryption: bool,
    min_available_version: u32,
    min_decryption_version: u32,
    min_encryption_version: u32,
    latest_version: u32,
    keys: std::collections::BTreeMap<String, i64>,
    soft_deleted: Option<bool>,
}
pub(super) fn verify_metadata(
    bytes: &[u8],
    identity: &ProviderKeyUri,
    wrapping: bool,
) -> Result<(), KeyProviderFailure> {
    let metadata = parse::<MetadataReply<'_>>(bytes)?.data;
    if identity.family() == ProviderFamily::OpenBaoTransit && metadata.soft_deleted != Some(false) {
        return Err(KeyProviderFailure::PermissionDenied);
    }
    let version = identity
        .version()
        .parse::<u32>()
        .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
    let name = identity
        .locator()
        .rsplit_once("/keys/")
        .ok_or(KeyProviderFailure::InvalidConfiguration)?
        .1;
    if metadata.name.as_str() != name
        || !metadata.keys.contains_key(identity.version())
        || metadata.latest_version < version
    {
        return Err(KeyProviderFailure::WrongKey);
    }
    if metadata.key_type.as_str() != "aes256-gcm96"
        || !metadata.derived
        || metadata.convergent_encryption
    {
        return Err(KeyProviderFailure::InvalidConfiguration);
    }
    if !metadata.supports_encryption
        || !metadata.supports_decryption
        || metadata.min_available_version > version
        || metadata.min_decryption_version > version
        || (wrapping && metadata.min_encryption_version > version)
    {
        return Err(KeyProviderFailure::PermissionDenied);
    }
    Ok(())
}
#[derive(Serialize)]
struct Login<'a> {
    role: &'a str,
    jwt: &'a str,
}
pub(super) fn login_request(
    role: &str,
    jwt: &str,
) -> Result<Zeroizing<Vec<u8>>, KeyProviderFailure> {
    let mut output = Zeroizing::new(Vec::with_capacity(16384));
    serde_json::to_writer(&mut *output, &Login { role, jwt })
        .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
    Ok(output)
}
#[derive(Deserialize)]
struct AuthReply<'a> {
    #[serde(borrow)]
    auth: Authentication<'a>,
}
#[derive(Deserialize)]
struct Authentication<'a> {
    #[serde(borrow)]
    client_token: SecretText<'a>,
    lease_duration: u64,
    renewable: bool,
    #[serde(borrow)]
    token_type: SecretText<'a>,
    num_uses: u64,
}
fn token(
    value: Zeroizing<String>,
    ttl: u64,
    renewable: bool,
    kind: &str,
    issued_at: tokio::time::Instant,
) -> Result<authentication::Token, KeyProviderFailure> {
    if !renewable || kind != "service" || ttl == 0 || ttl > i32::MAX as u64 {
        return Err(KeyProviderFailure::PermissionDenied);
    }
    if value.is_empty() || value.len() > 8192 || !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(KeyProviderFailure::InvalidConfiguration);
    }
    let expires_at = issued_at + Duration::from_secs(ttl);
    if expires_at <= tokio::time::Instant::now() {
        return Err(KeyProviderFailure::Unavailable);
    }
    Ok(authentication::Token {
        value,
        renew_at: issued_at + Duration::from_secs(ttl / 2),
        expires_at,
    })
}
pub(super) fn authentication_response(
    bytes: &[u8],
    issued_at: tokio::time::Instant,
) -> Result<authentication::Token, KeyProviderFailure> {
    let auth = parse::<AuthReply<'_>>(bytes)?.auth;
    if auth.num_uses != 0 {
        return Err(KeyProviderFailure::PermissionDenied);
    }
    token(
        Zeroizing::new(auth.client_token.as_str().to_owned()),
        auth.lease_duration,
        auth.renewable,
        auth.token_type.as_str(),
        issued_at,
    )
}
#[derive(Deserialize)]
struct LookupReply<'a> {
    #[serde(borrow)]
    data: Lookup<'a>,
}
#[derive(Deserialize)]
struct Lookup<'a> {
    #[serde(borrow)]
    id: SecretText<'a>,
    ttl: u64,
    renewable: bool,
    #[serde(rename = "type", borrow)]
    token_type: SecretText<'a>,
    num_uses: u64,
}
pub(super) fn lookup_response(
    bytes: &[u8],
    value: Zeroizing<String>,
    issued_at: tokio::time::Instant,
) -> Result<authentication::Token, KeyProviderFailure> {
    let data = parse::<LookupReply<'_>>(bytes)?.data;
    if data.id.as_str() != value.as_str() || data.num_uses != 0 {
        return Err(KeyProviderFailure::PermissionDenied);
    }
    token(
        value,
        data.ttl,
        data.renewable,
        data.token_type.as_str(),
        issued_at,
    )
}
#[derive(Serialize)]
struct Encrypt<'a> {
    plaintext: &'a str,
    context: &'a str,
    associated_data: &'a str,
    key_version: u32,
}
pub(super) fn encrypt_request(
    bytes: &[u8],
    context: EnvelopeContext,
    identity: &ProviderKeyUri,
) -> Result<Zeroizing<Vec<u8>>, KeyProviderFailure> {
    if bytes.is_empty() || bytes.len() > 1024 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    let plaintext = Zeroizing::new(STANDARD.encode(bytes));
    let context = STANDARD.encode(context.digest(identity)?);
    let mut output = Zeroizing::new(Vec::with_capacity(4096));
    serde_json::to_writer(
        &mut *output,
        &Encrypt {
            plaintext: &plaintext,
            context: &context,
            associated_data: &context,
            key_version: identity
                .version()
                .parse()
                .map_err(|_| KeyProviderFailure::InvalidConfiguration)?,
        },
    )
    .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
    Ok(output)
}
#[derive(Serialize)]
struct Decrypt<'a> {
    ciphertext: &'a str,
    context: &'a str,
    associated_data: &'a str,
}
pub(super) fn decrypt_request(
    bytes: &[u8],
    context: EnvelopeContext,
    identity: &ProviderKeyUri,
) -> Result<Zeroizing<Vec<u8>>, KeyProviderFailure> {
    verify_ciphertext(bytes, identity)?;
    let ciphertext = std::str::from_utf8(bytes).map_err(|_| KeyProviderFailure::ContextMismatch)?;
    let context = STANDARD.encode(context.digest(identity)?);
    let mut output = Zeroizing::new(Vec::with_capacity(4096));
    serde_json::to_writer(
        &mut *output,
        &Decrypt {
            ciphertext,
            context: &context,
            associated_data: &context,
        },
    )
    .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
    Ok(output)
}
#[derive(Deserialize)]
struct EncryptReply<'a> {
    #[serde(borrow)]
    data: Encrypted<'a>,
}
#[derive(Deserialize)]
struct Encrypted<'a> {
    #[serde(borrow)]
    ciphertext: SecretText<'a>,
    key_version: u32,
}
pub(super) fn verify_ciphertext(
    bytes: &[u8],
    identity: &ProviderKeyUri,
) -> Result<(), KeyProviderFailure> {
    if bytes.len() > 1500 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| KeyProviderFailure::ContextMismatch)?;
    let prefix = format!("vault:v{}:", identity.version());
    let encoded = text
        .strip_prefix(&prefix)
        .ok_or(KeyProviderFailure::WrongKey)?;
    let mut decoded = Zeroizing::new(vec![0; 1052]);
    let length = STANDARD
        .decode_slice(encoded, &mut decoded)
        .map_err(|_| KeyProviderFailure::ContextMismatch)?;
    // Native AES-GCM ciphertext carries its random 12-byte nonce and 16-byte tag.
    if !(29..=1052).contains(&length)
        || STANDARD.encode(
            decoded
                .get(..length)
                .ok_or(KeyProviderFailure::ContextMismatch)?,
        ) != encoded
    {
        return Err(KeyProviderFailure::ContextMismatch);
    }
    Ok(())
}
pub(super) fn encrypted_response(
    bytes: &[u8],
    identity: &ProviderKeyUri,
) -> Result<Vec<u8>, KeyProviderFailure> {
    let data = parse::<EncryptReply<'_>>(bytes)?.data;
    if data.key_version.to_string() != identity.version() {
        return Err(KeyProviderFailure::WrongKey);
    }
    verify_ciphertext(data.ciphertext.as_str().as_bytes(), identity)?;
    Ok(data.ciphertext.as_str().as_bytes().to_vec())
}
#[derive(Deserialize)]
struct DecryptReply<'a> {
    #[serde(borrow)]
    data: Decrypted<'a>,
}
#[derive(Deserialize)]
struct Decrypted<'a> {
    #[serde(borrow)]
    plaintext: SecretText<'a>,
}
pub(super) fn decrypted_response(
    bytes: &[u8],
) -> Result<SecretWrappedKeyPayload, KeyProviderFailure> {
    let data = parse::<DecryptReply<'_>>(bytes)?.data;
    if data.plaintext.as_str().len() > 1368 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    let mut plaintext = Zeroizing::new(vec![0; 1024]);
    let length = STANDARD
        .decode_slice(data.plaintext.as_str(), &mut plaintext)
        .map_err(|_| KeyProviderFailure::ContextMismatch)?;
    if length == 0 {
        return Err(KeyProviderFailure::ContextMismatch);
    }
    plaintext.truncate(length);
    SecretWrappedKeyPayload::from_provider_plaintext(std::mem::take(&mut *plaintext))
}
