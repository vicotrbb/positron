//! KMIP 2.1 OS: one synchronous binary TTLV batch; no generic object codec.
use super::*;
const MAXIMUM: usize = 8192;
const UID: u32 = 0x420094;
const DATA: u32 = 0x4200c2;
const IV: u32 = 0x42003d;
const AAD: u32 = 0x4200fe;
const TAG: u32 = 0x4200ff;
const ATTRIBUTES: &[u32] = &[0x420057, 0x420028, 0x42002a, 0x42002c, 0x42008d, 0x420034];
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Operation {
    DiscoverVersions,
    GetAttributes,
    Encrypt,
    Decrypt,
}
impl Operation {
    fn value(self) -> u32 {
        match self {
            Self::DiscoverVersions => 0x1e,
            Self::GetAttributes => 0x0b,
            Self::Encrypt => 0x1f,
            Self::Decrypt => 0x20,
        }
    }
    pub(super) fn transport_failure(self) -> KeyProviderFailure {
        if self == Self::Encrypt {
            KeyProviderFailure::Ambiguous
        } else {
            KeyProviderFailure::Unavailable
        }
    }
}
fn item(tag: u32, kind: u8, bytes: &[u8], out: &mut Vec<u8>) -> Result<(), KeyProviderFailure> {
    if bytes.len() > MAXIMUM || out.len() > MAXIMUM {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    let padded = bytes
        .len()
        .checked_add(7)
        .map(|n| n / 8 * 8)
        .ok_or(KeyProviderFailure::LimitExceeded)?;
    if out.len() + 8 + padded > MAXIMUM {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    out.extend_from_slice(
        tag.to_be_bytes()
            .get(1..)
            .ok_or(KeyProviderFailure::InvalidConfiguration)?,
    );
    out.push(kind);
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out.resize(out.len() + padded - bytes.len(), 0);
    Ok(())
}
fn number(tag: u32, kind: u8, value: u32, out: &mut Vec<u8>) -> Result<(), KeyProviderFailure> {
    item(tag, kind, &value.to_be_bytes(), out)
}
pub(super) fn version() -> Result<Vec<u8>, KeyProviderFailure> {
    let mut value = Vec::with_capacity(32);
    number(0x42006a, 2, 2, &mut value)?;
    number(0x42006b, 2, 1, &mut value)?;
    let mut result = Vec::with_capacity(40);
    item(0x420069, 1, &value, &mut result)?;
    Ok(result)
}
pub(super) fn request(
    operation: Operation,
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeyProviderFailure> {
    if payload.len() > 4096 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    let mut header = version()?;
    number(0x420050, 2, MAXIMUM as u32, &mut header)?;
    number(0x42000d, 2, 1, &mut header)?;
    let mut body = Zeroizing::new(Vec::with_capacity(MAXIMUM));
    item(0x420077, 1, &header, &mut body)?;
    let mut batch = Zeroizing::new(Vec::with_capacity(4096));
    number(0x42005c, 5, operation.value(), &mut batch)?;
    item(0x420079, 1, payload, &mut batch)?;
    item(0x42000f, 1, &batch, &mut body)?;
    let mut result = Zeroizing::new(Vec::with_capacity(MAXIMUM));
    item(0x420078, 1, &body, &mut result)?;
    Ok(result)
}
pub(super) fn frame_length(header: &[u8; 8]) -> Result<usize, KeyProviderFailure> {
    if header.get(..4) != Some(&[0x42, 0, 0x7b, 1]) {
        return Err(KeyProviderFailure::ContextMismatch);
    }
    let length = u32::from_be_bytes(
        header
            .get(4..)
            .ok_or(KeyProviderFailure::ContextMismatch)?
            .try_into()
            .map_err(|_| KeyProviderFailure::ContextMismatch)?,
    ) as usize;
    if length > MAXIMUM - 8 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    if length == 0 || !length.is_multiple_of(8) {
        return Err(KeyProviderFailure::ContextMismatch);
    }
    Ok(length)
}
struct Field<'a> {
    tag: u32,
    kind: u8,
    value: &'a [u8],
}
struct Fields<'a>(Vec<Field<'a>>);
impl<'a> Fields<'a> {
    fn parse(mut bytes: &'a [u8]) -> Result<Self, KeyProviderFailure> {
        if bytes.len() > MAXIMUM {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        let mut fields = Vec::with_capacity(32);
        while !bytes.is_empty() {
            if fields.len() == 32 {
                return Err(KeyProviderFailure::LimitExceeded);
            }
            let header: [u8; 8] = bytes
                .get(..8)
                .ok_or(KeyProviderFailure::ContextMismatch)?
                .try_into()
                .map_err(|_| KeyProviderFailure::ContextMismatch)?;
            let [a, b, c, kind, l0, l1, l2, l3] = header;
            let tag = u32::from_be_bytes([0, a, b, c]);
            let length = u32::from_be_bytes([l0, l1, l2, l3]) as usize;
            if length > MAXIMUM {
                return Err(KeyProviderFailure::LimitExceeded);
            }
            let padded = length
                .checked_add(7)
                .map(|n| n / 8 * 8)
                .ok_or(KeyProviderFailure::LimitExceeded)?;
            let value = bytes
                .get(8..8 + length)
                .ok_or(KeyProviderFailure::ContextMismatch)?;
            if bytes
                .get(8 + length..8 + padded)
                .ok_or(KeyProviderFailure::ContextMismatch)?
                .iter()
                .any(|b| *b != 0)
                || match kind {
                    1 => !length.is_multiple_of(8),
                    2 | 5 => length != 4,
                    6 => length != 8 || !matches!(value, [0, 0, 0, 0, 0, 0, 0, 0 | 1]),
                    7 => std::str::from_utf8(value).is_err(),
                    8 => false,
                    9 => length != 8,
                    _ => true,
                }
            {
                return Err(KeyProviderFailure::ContextMismatch);
            }
            if fields.iter().any(|f: &Field<'_>| f.tag == tag) {
                return Err(KeyProviderFailure::ContextMismatch);
            }
            fields.push(Field { tag, kind, value });
            bytes = bytes
                .get(8 + padded..)
                .ok_or(KeyProviderFailure::ContextMismatch)?;
        }
        Ok(Self(fields))
    }
    fn get(&self, tag: u32, kind: u8) -> Result<&'a [u8], KeyProviderFailure> {
        self.0
            .iter()
            .find(|f| f.tag == tag && f.kind == kind)
            .map(|f| f.value)
            .ok_or(KeyProviderFailure::ContextMismatch)
    }
    fn number(&self, tag: u32, kind: u8) -> Result<u32, KeyProviderFailure> {
        Ok(u32::from_be_bytes(
            self.get(tag, kind)?
                .try_into()
                .map_err(|_| KeyProviderFailure::ContextMismatch)?,
        ))
    }
    fn only(&self, tags: &[u32]) -> Result<(), KeyProviderFailure> {
        if self.0.iter().all(|f| tags.contains(&f.tag)) {
            Ok(())
        } else {
            Err(KeyProviderFailure::ContextMismatch)
        }
    }
}
pub(super) fn verify_version(bytes: &[u8]) -> Result<(), KeyProviderFailure> {
    let outer = Fields::parse(bytes)?;
    outer.only(&[0x420069])?;
    let fields = Fields::parse(outer.get(0x420069, 1)?)?;
    fields.only(&[0x42006a, 0x42006b])?;
    if fields.number(0x42006a, 2)? == 2 && fields.number(0x42006b, 2)? == 1 {
        Ok(())
    } else {
        Err(KeyProviderFailure::PermissionDenied)
    }
}
pub(super) fn response(bytes: &[u8], operation: Operation) -> Result<&[u8], KeyProviderFailure> {
    let outer = Fields::parse(bytes)?;
    outer.only(&[0x42007b])?;
    let message = Fields::parse(outer.get(0x42007b, 1)?)?;
    message.only(&[0x42007a, 0x42000f])?;
    let header = Fields::parse(message.get(0x42007a, 1)?)?;
    header.only(&[0x420069, 0x420092, 0x42000d])?;
    let mut version = Vec::with_capacity(40);
    item(0x420069, 1, header.get(0x420069, 1)?, &mut version)?;
    verify_version(&version)?;
    header.get(0x420092, 9)?;
    if header.number(0x42000d, 2)? != 1 {
        return Err(KeyProviderFailure::ContextMismatch);
    }
    let batch = Fields::parse(message.get(0x42000f, 1)?)?;
    batch.only(&[0x42005c, 0x42007f, 0x42007e, 0x42007d, 0x42007c])?;
    if batch.number(0x42005c, 5)? != operation.value() {
        return Err(KeyProviderFailure::ContextMismatch);
    }
    match batch.number(0x42007f, 5)? {
        0 => {
            batch.only(&[0x42005c, 0x42007f, 0x42007c])?;
            batch.get(0x42007c, 1)
        },
        1 => {
            if batch.0.iter().any(|f| f.tag == 0x42007c) {
                return Err(KeyProviderFailure::ContextMismatch);
            }
            if batch.0.iter().any(|f| f.tag == 0x42007d) {
                batch.get(0x42007d, 7)?;
            }
            Err(match batch.number(0x42007e, 5)? {
                1 | 0x37 | 0x42 => KeyProviderFailure::WrongKey,
                2 | 0x3a => KeyProviderFailure::LimitExceeded,
                0x04 | 0x07 | 0x0a | 0x24 | 0x26 | 0x2e | 0x34 => {
                    KeyProviderFailure::ContextMismatch
                },
                0x2a | 0x44 | 0x48 | 0x49 | 0x100 => KeyProviderFailure::Unavailable,
                _ => KeyProviderFailure::PermissionDenied,
            })
        },
        _ => Err(KeyProviderFailure::ContextMismatch),
    }
}
fn object(identity: &ProviderKeyUri) -> Result<&str, KeyProviderFailure> {
    identity
        .locator()
        .rsplit_once("/objects/")
        .map(|(_, id)| id)
        .ok_or(KeyProviderFailure::InvalidConfiguration)
}
fn uid(identity: &ProviderKeyUri, out: &mut Vec<u8>) -> Result<(), KeyProviderFailure> {
    item(UID, 7, object(identity)?.as_bytes(), out)
}
fn receipt(fields: &Fields<'_>, identity: &ProviderKeyUri) -> Result<(), KeyProviderFailure> {
    if fields.get(UID, 7)? == object(identity)?.as_bytes() {
        Ok(())
    } else {
        Err(KeyProviderFailure::WrongKey)
    }
}
pub(super) fn metadata_request(identity: &ProviderKeyUri) -> Result<Vec<u8>, KeyProviderFailure> {
    let mut result = Vec::with_capacity(128);
    uid(identity, &mut result)?;
    for tag in ATTRIBUTES {
        number(0x42013b, 5, *tag, &mut result)?;
    }
    Ok(result)
}
pub(super) fn verify_metadata(
    bytes: &[u8],
    identity: &ProviderKeyUri,
    wrapping: bool,
) -> Result<(), KeyProviderFailure> {
    let fields = Fields::parse(bytes)?;
    fields.only(&[UID, 0x420125])?;
    receipt(&fields, identity)?;
    let attributes = Fields::parse(fields.get(0x420125, 1)?)?;
    attributes.only(ATTRIBUTES)?;
    let state = attributes.number(0x42008d, 5)?;
    if attributes.number(0x420057, 5)? != 2
        || attributes.number(0x420028, 5)? != 3
        || attributes.number(0x42002a, 2)? != 256
        || attributes.number(0x42002c, 2)? & 12 != 12
        || !(state == 2 || (!wrapping && state == 3))
    {
        return Err(KeyProviderFailure::PermissionDenied);
    }
    let digest = Fields::parse(attributes.get(0x420034, 1)?)?;
    digest.only(&[0x420038, 0x420042, 0x420035])?;
    if digest.number(0x420038, 5)? != 6 || digest.number(0x420042, 5)? != 1 {
        return Err(KeyProviderFailure::PermissionDenied);
    }
    let value = digest.get(0x420035, 8)?;
    if value.len() != 32 {
        return Err(KeyProviderFailure::ContextMismatch);
    }
    let pinned = identity
        .version()
        .strip_prefix("sha256:")
        .ok_or(KeyProviderFailure::InvalidConfiguration)?
        .as_bytes();
    for (byte, pair) in value.iter().zip(pinned.chunks_exact(2)) {
        let hex = |n| if n < 10 { b'0' + n } else { b'a' + n - 10 };
        if pair != [hex(byte >> 4), hex(byte & 15)] {
            return Err(KeyProviderFailure::WrongKey);
        }
    }
    Ok(())
}
fn parameters(random: bool, out: &mut Vec<u8>) -> Result<(), KeyProviderFailure> {
    let mut value = Vec::with_capacity(96);
    number(0x420011, 5, 9, &mut value)?;
    number(0x420028, 5, 3, &mut value)?;
    number(0x4200cd, 2, 96, &mut value)?;
    number(0x4200ce, 2, 16, &mut value)?;
    if random {
        item(0x4200c5, 6, &1u64.to_be_bytes(), &mut value)?;
    }
    item(0x42002b, 1, &value, out)
}
pub(super) fn encrypt_request(
    plaintext: &[u8],
    context: EnvelopeContext,
    identity: &ProviderKeyUri,
) -> Result<Zeroizing<Vec<u8>>, KeyProviderFailure> {
    if plaintext.is_empty() || plaintext.len() > 1024 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    let mut result = Zeroizing::new(Vec::with_capacity(4096));
    uid(identity, &mut result)?;
    parameters(true, &mut result)?;
    item(DATA, 8, plaintext, &mut result)?;
    item(AAD, 8, &context.encode(identity), &mut result)?;
    Ok(result)
}
type CiphertextParts<'a> = (&'a [u8], &'a [u8], &'a [u8]);
fn ciphertext(bytes: &[u8]) -> Result<CiphertextParts<'_>, KeyProviderFailure> {
    if bytes.len() < 30 || bytes.len() > 1053 || bytes.first() != Some(&1) {
        return Err(KeyProviderFailure::ContextMismatch);
    }
    Ok((
        bytes
            .get(1..13)
            .ok_or(KeyProviderFailure::ContextMismatch)?,
        bytes
            .get(13..29)
            .ok_or(KeyProviderFailure::ContextMismatch)?,
        bytes.get(29..).ok_or(KeyProviderFailure::ContextMismatch)?,
    ))
}
pub(super) fn decrypt_request(
    bytes: &[u8],
    context: EnvelopeContext,
    identity: &ProviderKeyUri,
) -> Result<Zeroizing<Vec<u8>>, KeyProviderFailure> {
    let (iv, tag, data) = ciphertext(bytes)?;
    let mut result = Zeroizing::new(Vec::with_capacity(4096));
    uid(identity, &mut result)?;
    parameters(false, &mut result)?;
    item(DATA, 8, data, &mut result)?;
    item(IV, 8, iv, &mut result)?;
    item(TAG, 8, tag, &mut result)?;
    item(AAD, 8, &context.encode(identity), &mut result)?;
    Ok(result)
}
pub(super) fn encrypted_response(
    bytes: &[u8],
    identity: &ProviderKeyUri,
) -> Result<Vec<u8>, KeyProviderFailure> {
    let fields = Fields::parse(bytes)?;
    fields.only(&[UID, DATA, IV, TAG])?;
    receipt(&fields, identity)?;
    let data = fields.get(DATA, 8)?;
    let iv = fields.get(IV, 8)?;
    let tag = fields.get(TAG, 8)?;
    if data.is_empty() || data.len() > 1024 || iv.len() != 12 || tag.len() != 16 {
        return Err(KeyProviderFailure::ContextMismatch);
    }
    let mut result = Vec::with_capacity(29 + data.len());
    result.push(1);
    result.extend_from_slice(iv);
    result.extend_from_slice(tag);
    result.extend_from_slice(data);
    Ok(result)
}
pub(super) fn decrypted_response(
    bytes: &[u8],
    identity: &ProviderKeyUri,
) -> Result<SecretWrappedKeyPayload, KeyProviderFailure> {
    let fields = Fields::parse(bytes)?;
    fields.only(&[UID, DATA])?;
    receipt(&fields, identity)?;
    let data = fields.get(DATA, 8)?;
    if data.is_empty() || data.len() > 1024 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    SecretWrappedKeyPayload::from_provider_plaintext(data.to_vec())
}
