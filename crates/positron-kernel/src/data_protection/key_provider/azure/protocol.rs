//! Key Vault 7.6 published wire fields. RSA has no native authenticated context;
//! the canonical Wrapped Key Payload remains the required context authority.
use super::super::wire::SecretText;
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy)]
pub(super) enum Operation {
    Metadata,
    Wrap,
    Unwrap,
}
impl Operation {
    pub(super) fn endpoint(self, identity: &ProviderKeyUri) -> String {
        let suffix = match self {
            Self::Metadata => "",
            Self::Wrap => "/wrapkey",
            Self::Unwrap => "/unwrapkey",
        };
        format!("{}{suffix}?api-version=7.6", identity.locator())
    }
    pub(super) const fn transport_failure(self) -> KeyProviderFailure {
        match self {
            Self::Wrap => KeyProviderFailure::Ambiguous,
            _ => KeyProviderFailure::Unavailable,
        }
    }
}
pub(super) fn scope(identity: &ProviderKeyUri) -> &'static str {
    if identity.locator().contains(".vault.azure.cn/") {
        "https://vault.azure.cn/.default"
    } else if identity.locator().contains(".vault.usgovcloudapi.net/") {
        "https://vault.usgovcloudapi.net/.default"
    } else {
        "https://vault.azure.net/.default"
    }
}
pub(super) fn classify(operation: Operation, status: u16) -> KeyProviderFailure {
    match status {
        401 | 403 => KeyProviderFailure::PermissionDenied,
        404 | 410 => KeyProviderFailure::WrongKey,
        429 => KeyProviderFailure::Unavailable,
        500..=599 => operation.transport_failure(),
        _ => KeyProviderFailure::ContextMismatch,
    }
}
pub(super) fn retry_delay(headers: &http::HeaderMap) -> Result<Duration, KeyProviderFailure> {
    let milliseconds = if let Some(value) = headers.get("x-ms-retry-after-ms") {
        value.to_str().ok().and_then(|s| s.parse::<u64>().ok())
    } else if let Some(value) = headers.get(http::header::RETRY_AFTER) {
        value
            .to_str()
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .and_then(|s| s.checked_mul(1000))
    } else {
        Some(100)
    }
    .ok_or(KeyProviderFailure::Unavailable)?;
    if milliseconds > 2000 {
        return Err(KeyProviderFailure::Unavailable);
    }
    Ok(Duration::from_millis(milliseconds.max(100)))
}
fn parse<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, KeyProviderFailure> {
    if bytes.len() > 32_768 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    serde_json::from_slice(bytes).map_err(|_| KeyProviderFailure::ContextMismatch)
}
#[derive(Deserialize)]
struct Metadata<'a> {
    #[serde(borrow)]
    key: Key<'a>,
    attributes: Attributes,
}
#[derive(Deserialize)]
struct Key<'a> {
    #[serde(borrow)]
    kid: SecretText<'a>,
    #[serde(borrow)]
    kty: SecretText<'a>,
    #[serde(borrow)]
    key_ops: Vec<SecretText<'a>>,
    #[serde(borrow)]
    n: SecretText<'a>,
    #[serde(borrow)]
    e: SecretText<'a>,
}
#[derive(Deserialize)]
struct Attributes {
    enabled: bool,
    nbf: Option<u64>,
    exp: Option<u64>,
}
pub(super) fn verify_metadata(
    bytes: &[u8],
    identity: &ProviderKeyUri,
) -> Result<usize, KeyProviderFailure> {
    let metadata: Metadata<'_> = parse(bytes)?;
    if metadata.key.kid.as_str() != identity.locator() {
        return Err(KeyProviderFailure::WrongKey);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| KeyProviderFailure::Unavailable)?
        .as_secs();
    if !metadata.attributes.enabled
        || metadata.attributes.nbf.is_some_and(|nbf| nbf > now)
        || metadata.attributes.exp.is_some_and(|exp| exp <= now)
        || !matches!(metadata.key.kty.as_str(), "RSA" | "RSA-HSM")
        || !["wrapKey", "unwrapKey"].iter().all(|op| {
            metadata
                .key
                .key_ops
                .iter()
                .any(|actual| actual.as_str() == *op)
        })
    {
        return Err(KeyProviderFailure::PermissionDenied);
    }
    if metadata.key.n.as_str().len() > 683 || metadata.key.e.as_str() != "AQAB" {
        return Err(KeyProviderFailure::InvalidConfiguration);
    }
    let modulus = URL_SAFE_NO_PAD
        .decode(metadata.key.n.as_str())
        .map_err(|_| KeyProviderFailure::ContextMismatch)?;
    if !matches!(modulus.len(), 256 | 384 | 512)
        || modulus.first().is_none_or(|b| b & 0x80 == 0)
        || modulus.last().is_none_or(|b| b & 1 == 0)
    {
        return Err(KeyProviderFailure::InvalidConfiguration);
    }
    Ok(modulus.len())
}
#[derive(Serialize)]
struct Wrap<'a> {
    alg: &'static str,
    value: &'a str,
}
pub(super) fn request(
    bytes: &[u8],
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, KeyProviderFailure> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    let value = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes));
    let mut output = Zeroizing::new(Vec::with_capacity(2048));
    serde_json::to_writer(
        &mut *output,
        &Wrap {
            alg: "RSA-OAEP-256",
            value: &value,
        },
    )
    .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
    Ok(output)
}
#[derive(Deserialize)]
struct ResultBody<'a> {
    #[serde(borrow)]
    kid: SecretText<'a>,
    #[serde(borrow)]
    value: SecretText<'a>,
}
pub(super) fn response(
    bytes: &[u8],
    identity: &ProviderKeyUri,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, KeyProviderFailure> {
    let reply: ResultBody<'_> = parse(bytes)?;
    if reply.kid.as_str() != identity.locator() {
        return Err(KeyProviderFailure::WrongKey);
    }
    if reply.value.as_str().len() > maximum.div_ceil(3) * 4 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    let mut result = Zeroizing::new(vec![0; maximum]);
    let length = URL_SAFE_NO_PAD
        .decode_slice(reply.value.as_str(), &mut result)
        .map_err(|_| KeyProviderFailure::ContextMismatch)?;
    if length == 0 {
        return Err(KeyProviderFailure::ContextMismatch);
    }
    result.truncate(length);
    Ok(result)
}
