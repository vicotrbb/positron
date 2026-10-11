//! Published Google REST wire contract; never a provider emulator.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

const RESPONSE_BYTES: usize = 32_768;

use super::super::wire::SecretText;

#[derive(Clone, Copy)]
pub(super) enum Operation {
    Metadata,
    Encrypt,
    Decrypt,
}
impl Operation {
    pub(super) fn endpoint(self, identity: &ProviderKeyUri) -> Result<String, KeyProviderFailure> {
        if identity.family() != ProviderFamily::GoogleCloudKms {
            return Err(KeyProviderFailure::InvalidConfiguration);
        }
        let resource = identity.locator();
        let path = match self {
            Self::Metadata => resource.to_owned(),
            Self::Encrypt => format!("{resource}:encrypt"),
            Self::Decrypt => {
                let (parent, _) = resource
                    .rsplit_once("/cryptoKeyVersions/")
                    .ok_or(KeyProviderFailure::InvalidConfiguration)?;
                format!("{parent}:decrypt")
            },
        };
        Ok(format!("https://cloudkms.googleapis.com/v1/{path}"))
    }
    pub(super) const fn transport_failure(self) -> KeyProviderFailure {
        match self {
            Self::Encrypt => KeyProviderFailure::Ambiguous,
            Self::Metadata | Self::Decrypt => KeyProviderFailure::Unavailable,
        }
    }
}

pub(super) fn classify(operation: Operation, code: u16, bytes: &[u8]) -> KeyProviderFailure {
    #[derive(Deserialize)]
    struct Reply<'a> {
        #[serde(borrow)]
        error: Failure<'a>,
    }
    #[derive(Deserialize)]
    struct Failure<'a> {
        #[serde(borrow)]
        status: SecretText<'a>,
    }
    let reply = parse::<Reply<'_>>(bytes).ok();
    let status = reply.as_ref().map(|reply| reply.error.status.as_str());
    match (code, status) {
        (_, Some("DEADLINE_EXCEEDED" | "CANCELLED")) => operation.transport_failure(),
        (_, Some("RESOURCE_EXHAUSTED" | "UNAVAILABLE")) => KeyProviderFailure::Unavailable,
        (_, Some("PERMISSION_DENIED" | "UNAUTHENTICATED")) => KeyProviderFailure::PermissionDenied,
        (_, Some("NOT_FOUND")) => KeyProviderFailure::WrongKey,
        (_, Some("ALREADY_EXISTS" | "UNIMPLEMENTED")) => KeyProviderFailure::InvalidConfiguration,
        (_, Some("INVALID_ARGUMENT" | "OUT_OF_RANGE" | "ABORTED" | "DATA_LOSS")) => {
            KeyProviderFailure::ContextMismatch
        },
        (_, Some("FAILED_PRECONDITION")) => KeyProviderFailure::PermissionDenied,
        (_, Some("UNKNOWN" | "INTERNAL")) => operation.transport_failure(),
        (401 | 403, _) => KeyProviderFailure::PermissionDenied,
        (404, _) => KeyProviderFailure::WrongKey,
        (429, _) => KeyProviderFailure::Unavailable,
        (500..=599, _) if matches!(operation, Operation::Encrypt) => KeyProviderFailure::Ambiguous,
        (500..=599, _) => KeyProviderFailure::Unavailable,
        _ => KeyProviderFailure::ContextMismatch,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Encrypt<'a> {
    plaintext: &'a str,
    plaintext_crc32c: String,
    additional_authenticated_data: String,
    additional_authenticated_data_crc32c: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Decrypt<'a> {
    ciphertext: &'a str,
    ciphertext_crc32c: String,
    additional_authenticated_data: String,
    additional_authenticated_data_crc32c: String,
}

fn encode(value: &impl Serialize) -> Result<Zeroizing<Vec<u8>>, KeyProviderFailure> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(16_384));
    serde_json::to_writer(&mut *bytes, value)
        .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
    if bytes.len() > 16_384 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    Ok(bytes)
}
pub(super) fn encrypt_request(
    identity: &ProviderKeyUri,
    context: EnvelopeContext,
    plaintext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeyProviderFailure> {
    if plaintext.is_empty() || plaintext.len() > 1024 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    let digest = context.digest(identity)?;
    let checksum = crc32c::crc32c(plaintext).to_string();
    let plaintext = Zeroizing::new(STANDARD.encode(plaintext));
    encode(&Encrypt {
        plaintext: &plaintext,
        plaintext_crc32c: checksum,
        additional_authenticated_data: STANDARD.encode(digest),
        additional_authenticated_data_crc32c: crc32c::crc32c(&digest).to_string(),
    })
}
pub(super) fn decrypt_request(
    identity: &ProviderKeyUri,
    context: EnvelopeContext,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeyProviderFailure> {
    if ciphertext.is_empty() || ciphertext.len() > 6144 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    let digest = context.digest(identity)?;
    encode(&Decrypt {
        ciphertext: &STANDARD.encode(ciphertext),
        ciphertext_crc32c: crc32c::crc32c(ciphertext).to_string(),
        additional_authenticated_data: STANDARD.encode(digest),
        additional_authenticated_data_crc32c: crc32c::crc32c(&digest).to_string(),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Wrapped<'a> {
    #[serde(borrow)]
    name: SecretText<'a>,
    #[serde(borrow)]
    ciphertext: SecretText<'a>,
    #[serde(borrow)]
    ciphertext_crc32c: SecretText<'a>,
    verified_plaintext_crc32c: bool,
    verified_additional_authenticated_data_crc32c: bool,
}

pub(super) fn wrapped_response(
    bytes: &[u8],
    identity: &ProviderKeyUri,
) -> Result<Vec<u8>, KeyProviderFailure> {
    let response: Wrapped<'_> = parse(bytes)?;
    if response.name.as_str() != identity.locator() {
        return Err(KeyProviderFailure::WrongKey);
    }
    if !response.verified_plaintext_crc32c
        || !response.verified_additional_authenticated_data_crc32c
    {
        return Err(KeyProviderFailure::ContextMismatch);
    }
    if response.ciphertext.as_str().len() > 8192 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    let ciphertext = STANDARD
        .decode(response.ciphertext.as_str())
        .map_err(|_| KeyProviderFailure::ContextMismatch)?;
    if ciphertext.is_empty() || ciphertext.len() > 6144 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    if response.ciphertext_crc32c.as_str().parse::<u32>().ok() != Some(crc32c::crc32c(&ciphertext))
    {
        return Err(KeyProviderFailure::ContextMismatch);
    }
    Ok(ciphertext)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Plaintext<'a> {
    #[serde(borrow)]
    plaintext: SecretText<'a>,
    #[serde(borrow)]
    plaintext_crc32c: SecretText<'a>,
}

pub(super) fn plaintext_response(
    bytes: &[u8],
) -> Result<SecretWrappedKeyPayload, KeyProviderFailure> {
    let response: Plaintext<'_> = parse(bytes)?;
    if response.plaintext.as_str().len() > 1368 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    let mut plaintext = Zeroizing::new(vec![0; 1024]);
    let length = STANDARD
        .decode_slice(response.plaintext.as_str(), &mut plaintext)
        .map_err(|_| KeyProviderFailure::ContextMismatch)?;
    if length == 0 {
        return Err(KeyProviderFailure::ContextMismatch);
    }
    plaintext.truncate(length);
    if response.plaintext_crc32c.as_str().parse::<u32>().ok() != Some(crc32c::crc32c(&plaintext)) {
        return Err(KeyProviderFailure::ContextMismatch);
    }
    SecretWrappedKeyPayload::from_provider_plaintext(std::mem::take(&mut *plaintext))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Metadata<'a> {
    #[serde(borrow)]
    name: SecretText<'a>,
    #[serde(borrow)]
    state: SecretText<'a>,
    #[serde(borrow)]
    algorithm: SecretText<'a>,
    #[serde(borrow)]
    protection_level: SecretText<'a>,
}

fn parse<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, KeyProviderFailure> {
    if bytes.len() > RESPONSE_BYTES {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    serde_json::from_slice(bytes).map_err(|_| KeyProviderFailure::ContextMismatch)
}

pub(super) fn verify_metadata(
    bytes: &[u8],
    identity: &ProviderKeyUri,
) -> Result<(), KeyProviderFailure> {
    let response: Metadata<'_> = parse(bytes)?;
    if response.name.as_str() != identity.locator() {
        return Err(KeyProviderFailure::WrongKey);
    }
    if response.state.as_str() != "ENABLED"
        || response.algorithm.as_str() != "GOOGLE_SYMMETRIC_ENCRYPTION"
        || !matches!(
            response.protection_level.as_str(),
            "SOFTWARE" | "HSM" | "EXTERNAL" | "EXTERNAL_VPC"
        )
    {
        return Err(KeyProviderFailure::PermissionDenied);
    }
    Ok(())
}
