//! Bounded AWS JSON codec. Fixture tests exercise bytes, never a fake provider.
use super::*;
use crate::data_protection::{CryptoBackend, RustCryptoBackend};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
pub(super) const RESPONSE_BYTES: usize = 32_768;
const REQUEST_BYTES: usize = 16_384;

#[derive(Clone, Copy)]
pub(in crate::data_protection::key_provider) enum Operation {
    Describe,
    Encrypt,
    Decrypt,
}
impl Operation {
    fn target(self) -> &'static str {
        match self {
            Self::Describe => "TrentService.DescribeKey",
            Self::Encrypt => "TrentService.Encrypt",
            Self::Decrypt => "TrentService.Decrypt",
        }
    }
    pub(super) fn transport_failure(self) -> KeyProviderFailure {
        match self {
            Self::Encrypt => KeyProviderFailure::Ambiguous,
            _ => KeyProviderFailure::Unavailable,
        }
    }
}
fn encode(value: &impl Serialize) -> Result<Zeroizing<Vec<u8>>, KeyProviderFailure> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(REQUEST_BYTES));
    serde_json::to_writer(&mut *bytes, value)
        .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
    if bytes.len() > REQUEST_BYTES {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    Ok(bytes)
}
#[derive(Serialize)]
struct Describe<'a> {
    #[serde(rename = "KeyId")]
    key: &'a str,
}
pub(super) fn describe_request(
    identity: &ProviderKeyUri,
) -> Result<Zeroizing<Vec<u8>>, KeyProviderFailure> {
    encode(&Describe {
        key: identity.locator(),
    })
}
#[derive(Serialize)]
struct NativeContext {
    #[serde(rename = "positron-envelope-context-v1")]
    digest: String,
    #[serde(rename = "positron-purpose")]
    purpose: &'static str,
}
fn native_context(
    identity: &ProviderKeyUri,
    context: EnvelopeContext,
) -> Result<NativeContext, KeyProviderFailure> {
    let digest = context.digest(identity)?;
    use std::fmt::Write;
    let mut hex = String::with_capacity(64);
    for byte in digest {
        write!(&mut hex, "{byte:02x}").map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
    }
    Ok(NativeContext {
        digest: hex,
        purpose: "root-wrap-kek",
    })
}
#[derive(Serialize)]
struct Encrypt<'a> {
    #[serde(rename = "KeyId")]
    key: &'a str,
    #[serde(rename = "EncryptionAlgorithm")]
    algorithm: &'static str,
    #[serde(rename = "EncryptionContext")]
    context: NativeContext,
    #[serde(rename = "Plaintext")]
    plaintext: &'a str,
}
pub(super) fn encrypt_request(
    identity: &ProviderKeyUri,
    context: EnvelopeContext,
    plaintext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeyProviderFailure> {
    if plaintext.is_empty() || plaintext.len() > 1024 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    let plaintext = Zeroizing::new(STANDARD.encode(plaintext));
    encode(&Encrypt {
        key: identity.locator(),
        algorithm: "SYMMETRIC_DEFAULT",
        context: native_context(identity, context)?,
        plaintext: &plaintext,
    })
}
#[derive(Serialize)]
struct Decrypt<'a> {
    #[serde(rename = "KeyId")]
    key: &'a str,
    #[serde(rename = "EncryptionAlgorithm")]
    algorithm: &'static str,
    #[serde(rename = "EncryptionContext")]
    context: NativeContext,
    #[serde(rename = "CiphertextBlob")]
    ciphertext: &'a str,
}
pub(super) fn decrypt_request(
    identity: &ProviderKeyUri,
    context: EnvelopeContext,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeyProviderFailure> {
    if ciphertext.is_empty() || ciphertext.len() > 6144 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    let ciphertext = STANDARD.encode(ciphertext);
    encode(&Decrypt {
        key: identity.locator(),
        algorithm: "SYMMETRIC_DEFAULT",
        context: native_context(identity, context)?,
        ciphertext: &ciphertext,
    })
}
#[derive(Deserialize)]
struct MetadataResponse<'a> {
    #[serde(rename = "KeyMetadata", borrow)]
    metadata: Metadata<'a>,
}
#[derive(Deserialize)]
struct Metadata<'a> {
    #[serde(rename = "Arn")]
    arn: &'a str,
    #[serde(rename = "KeyId")]
    key: &'a str,
    #[serde(rename = "Enabled")]
    enabled: bool,
    #[serde(rename = "KeyState")]
    state: &'a str,
    #[serde(rename = "KeyUsage")]
    usage: &'a str,
    #[serde(rename = "KeySpec")]
    spec: &'a str,
    #[serde(rename = "EncryptionAlgorithms")]
    algorithms: Vec<&'a str>,
}
fn parse<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, KeyProviderFailure> {
    if bytes.len() > RESPONSE_BYTES {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    serde_json::from_slice(bytes).map_err(|_| KeyProviderFailure::ContextMismatch)
}
pub(in crate::data_protection::key_provider) fn verify_metadata(
    bytes: &[u8],
    identity: &ProviderKeyUri,
) -> Result<(), KeyProviderFailure> {
    let response: MetadataResponse<'_> = parse(bytes)?;
    let metadata = response.metadata;
    let (_, _, expected_key) =
        aws_arn_parts(identity.locator()).ok_or(KeyProviderFailure::InvalidConfiguration)?;
    if metadata.arn != identity.locator() || metadata.key != expected_key {
        return Err(KeyProviderFailure::WrongKey);
    }
    if !metadata.enabled
        || metadata.state != "Enabled"
        || metadata.usage != "ENCRYPT_DECRYPT"
        || metadata.spec != "SYMMETRIC_DEFAULT"
        || metadata.algorithms != ["SYMMETRIC_DEFAULT"]
    {
        return Err(KeyProviderFailure::PermissionDenied);
    }
    Ok(())
}
#[derive(Deserialize)]
struct WrappedResponse<'a> {
    #[serde(rename = "KeyId")]
    key: &'a str,
    #[serde(rename = "EncryptionAlgorithm")]
    algorithm: &'a str,
    #[serde(rename = "CiphertextBlob")]
    ciphertext: &'a str,
}
fn identity_matches(
    identity: &ProviderKeyUri,
    key: &str,
    algorithm: &str,
) -> Result<(), KeyProviderFailure> {
    if key != identity.locator() {
        return Err(KeyProviderFailure::WrongKey);
    }
    if algorithm != "SYMMETRIC_DEFAULT" {
        return Err(KeyProviderFailure::ContextMismatch);
    }
    Ok(())
}
pub(in crate::data_protection::key_provider) fn wrapped_response(
    bytes: &[u8],
    identity: &ProviderKeyUri,
) -> Result<Vec<u8>, KeyProviderFailure> {
    let response: WrappedResponse<'_> = parse(bytes)?;
    identity_matches(identity, response.key, response.algorithm)?;
    if response.ciphertext.len() > 8192 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    let ciphertext = STANDARD
        .decode(response.ciphertext)
        .map_err(|_| KeyProviderFailure::ContextMismatch)?;
    if ciphertext.is_empty() || ciphertext.len() > 6144 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    Ok(ciphertext)
}
#[derive(Deserialize)]
struct PlaintextResponse<'a> {
    #[serde(rename = "KeyId")]
    key: &'a str,
    #[serde(rename = "EncryptionAlgorithm")]
    algorithm: &'a str,
    #[serde(rename = "Plaintext")]
    plaintext: &'a str,
}
pub(in crate::data_protection::key_provider) fn plaintext_response(
    bytes: &[u8],
    identity: &ProviderKeyUri,
) -> Result<SecretWrappedKeyPayload, KeyProviderFailure> {
    let response: PlaintextResponse<'_> = parse(bytes)?;
    identity_matches(identity, response.key, response.algorithm)?;
    if response.plaintext.len() > 1368 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    let mut plaintext = Zeroizing::new(vec![0; 1024]);
    let length = STANDARD
        .decode_slice(response.plaintext, &mut plaintext)
        .map_err(|_| KeyProviderFailure::ContextMismatch)?;
    if length == 0 {
        return Err(KeyProviderFailure::ContextMismatch);
    }
    plaintext.truncate(length);
    SecretWrappedKeyPayload::from_provider_plaintext(std::mem::take(&mut *plaintext))
}
#[derive(Deserialize)]
struct ErrorResponse<'a> {
    #[serde(rename = "__type")]
    code: Option<&'a str>,
}
/// Native codes are authoritative. Unknown server replies preserve uncertainty;
/// raw provider messages never enter errors.
pub(in crate::data_protection::key_provider) fn classify(
    operation: Operation,
    status: u16,
    bytes: &[u8],
) -> KeyProviderFailure {
    let code = serde_json::from_slice::<ErrorResponse<'_>>(bytes)
        .ok()
        .and_then(|error| error.code)
        .unwrap_or("")
        .rsplit('#')
        .next()
        .unwrap_or("");
    match code {
        "ThrottlingException"
        | "KMSInternalException"
        | "InternalFailure"
        | "RequestTimeoutException"
        | "ServiceUnavailable"
        | "DependencyTimeoutException"
        | "KeyUnavailableException" => KeyProviderFailure::Unavailable,
        "InvalidCiphertextException" | "InvalidGrantTokenException" => {
            KeyProviderFailure::ContextMismatch
        },
        "IncorrectKeyException" | "NotFoundException" => KeyProviderFailure::WrongKey,
        "AccessDeniedException"
        | "NotAuthorizedException"
        | "NotAuthorized"
        | "InvalidArnException"
        | "InvalidKeyUsageException"
        | "DryRunOperationException"
        | "ExpiredTokenException"
        | "IncompleteSignature"
        | "MalformedHttpRequestException"
        | "OptInRequired"
        | "RequestAbortedException"
        | "RequestEntityTooLargeException"
        | "UnknownOperationException"
        | "UnrecognizedClientException"
        | "ValidationError"
        | "DisabledException"
        | "KMSInvalidStateException" => KeyProviderFailure::PermissionDenied,
        _ if status == 429 => KeyProviderFailure::Unavailable,
        _ if matches!(status, 500 | 502 | 503 | 504) => operation.transport_failure(),
        _ => KeyProviderFailure::PermissionDenied,
    }
}
pub(super) async fn send(
    client: &reqwest::Client,
    endpoint: &str,
    region: &str,
    credentials: &aws_credential_types::Credentials,
    operation: Operation,
    body: bytes::Bytes,
) -> Result<Result<Zeroizing<Vec<u8>>, KeyProviderFailure>, KeyProviderFailure> {
    let headers = RustCryptoBackend
        .aws_kms_request_headers(credentials, endpoint, region, operation.target(), &body)
        .map_err(|_| KeyProviderFailure::Unavailable)?;
    let mut request = client
        .post(endpoint)
        .header("content-type", "application/x-amz-json-1.1")
        .header("x-amz-target", operation.target())
        .body(body);
    for (name, value) in headers {
        let mut header =
            http::HeaderValue::from_str(&value).map_err(|_| KeyProviderFailure::Unavailable)?;
        header.set_sensitive(true);
        request = request.header(name, header);
    }
    let response = request
        .send()
        .with_subscriber(tracing::subscriber::NoSubscriber::default())
        .await
        .map_err(|error| {
            if error.is_connect() {
                KeyProviderFailure::Unavailable
            } else {
                operation.transport_failure()
            }
        })?;
    let status = response.status().as_u16();
    let body = super::credentials_http::collect(response, RESPONSE_BYTES)
        .await
        .map_err(|failure| {
            if failure == KeyProviderFailure::Unavailable {
                operation.transport_failure()
            } else {
                failure
            }
        })?;
    if status == 200 {
        Ok(Ok(body))
    } else {
        Ok(Err(classify(operation, status, &body)))
    }
}
