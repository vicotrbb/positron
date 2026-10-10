//! Deterministic Protobuf schema and domain-separated Ed25519 payload authentication.
use super::super::codec::{SecretRootKey, encode_file_v1, parse_file_v1};
use super::super::{LocalKeyCreationTime, LocalKeyId};
use super::*;
use crate::data_protection::backend::RecoveryCryptoPurpose;
use crate::data_protection::key_envelope::{encode_bytes_field, encode_varint_field};
use crate::data_protection::{CryptoBackend, RustCryptoBackend};
use subtle::ConstantTimeEq;

pub(super) fn encode(metadata: &RecoveryMetadata, root: &[u8]) -> Zeroizing<Vec<u8>> {
    encode_with_system(metadata, root, None)
}

pub(super) fn encode_with_system(
    metadata: &RecoveryMetadata,
    root: &[u8],
    system: Option<(BootstrapKeyIdentity, u64, &[u8])>,
) -> Zeroizing<Vec<u8>> {
    let mut payload = Zeroizing::new(Vec::with_capacity(2048));
    let pin = metadata.identity;
    encode_varint_field(1, if system.is_some() { 2 } else { 1 }, &mut payload);
    encode_bytes_field(2, &pin.instance.to_bytes(), &mut payload);
    encode_bytes_field(3, &pin.root.key_id(), &mut payload);
    encode_varint_field(4, pin.root.created_at_unix_seconds(), &mut payload);
    encode_bytes_field(5, &pin.root.fingerprint(), &mut payload);
    encode_bytes_field(6, root, &mut payload);
    encode_varint_field(7, 1, &mut payload); // local-file provider
    encode_varint_field(8, system.map_or(1, |(_, epoch, _)| epoch), &mut payload);
    encode_bytes_field(9, b"local-root-recovery", &mut payload);
    encode_varint_field(10, metadata.created, &mut payload);
    encode_bytes_field(11, &pin.integrity.public_key(), &mut payload);
    encode_bytes_field(12, &pin.integrity.fingerprint(), &mut payload);
    for recipient in &metadata.recipients {
        encode_bytes_field(13, recipient.as_bytes(), &mut payload);
    }
    if let Some((anchor, _, envelope)) = system {
        encode_bytes_field(14, &anchor.key_id(), &mut payload);
        encode_bytes_field(15, &anchor.fingerprint(), &mut payload);
        encode_varint_field(16, anchor.created_at_unix_seconds(), &mut payload);
        encode_bytes_field(17, envelope, &mut payload);
    }
    payload
}
pub(super) fn signed(
    payload: &[u8],
    seed: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, RecoveryFailure> {
    let signature = RustCryptoBackend
        .sign_recovery(RecoveryCryptoPurpose::LocalRootPayloadV1, seed, payload)
        .map_err(|_| RecoveryFailure::Authentication)?;
    let mut envelope = Zeroizing::new(Vec::with_capacity(4096));
    encode_bytes_field(1, payload, &mut envelope);
    encode_bytes_field(2, &signature, &mut envelope);
    Ok(envelope)
}
pub(super) fn verify_signed(
    bytes: &[u8],
    pin: BootstrapIntegrityIdentity,
) -> Result<&[u8], RecoveryFailure> {
    let mut cursor = Cursor(bytes);
    let payload = cursor.bytes(1)?;
    let signature = cursor.bytes(2)?;
    if !cursor.0.is_empty() || signature.len() != 64 {
        return Err(RecoveryFailure::Authentication);
    }
    RustCryptoBackend
        .verify_recovery(
            RecoveryCryptoPurpose::LocalRootPayloadV1,
            pin.public_key(),
            payload,
            signature,
        )
        .map_err(|_| RecoveryFailure::Authentication)?;
    Ok(payload)
}
pub(super) fn decode(
    bytes: &[u8],
    pin: RecoveryIdentity,
) -> Result<(RecoveryMetadata, BootstrapKeyCustody), RecoveryFailure> {
    let mut cursor = Cursor(bytes);
    let version = cursor.integer(1)?;
    if !matches!(version, 1 | 2) {
        return Err(RecoveryFailure::Authentication);
    }
    cursor.bytes(2)?;
    cursor.bytes(3)?;
    cursor.integer(4)?;
    cursor.bytes(5)?;
    let root = cursor.bytes(6)?;
    if root.len() != 32 {
        return Err(RecoveryFailure::Authentication);
    }
    cursor.integer(7)?;
    let root_epoch = cursor.integer(8)?;
    cursor.bytes(9)?;
    let created = cursor.integer(10)?;
    cursor.bytes(11)?;
    cursor.bytes(12)?;
    let mut recipients = Vec::with_capacity(16);
    while cursor.0.first().copied() == Some((13 << 3) | 2) {
        if recipients.len() == 16 {
            return Err(RecoveryFailure::LimitExceeded);
        }
        let recipient = cursor.bytes(13)?;
        if recipient.len() > 62 {
            return Err(RecoveryFailure::Authentication);
        }
        recipients.push(
            std::str::from_utf8(recipient)
                .map_err(|_| RecoveryFailure::Authentication)?
                .to_owned(),
        );
    }
    let system = if version == 2 {
        let key_id = cursor
            .bytes(14)?
            .try_into()
            .map_err(|_| RecoveryFailure::Authentication)?;
        let fingerprint = cursor
            .bytes(15)?
            .try_into()
            .map_err(|_| RecoveryFailure::Authentication)?;
        let created = cursor.integer(16)?;
        let anchor = BootstrapKeyIdentity::from_parts(key_id, fingerprint, created)
            .map_err(|_| RecoveryFailure::Authentication)?;
        let envelope = cursor.bytes(17)?;
        if envelope.len() > 1024 {
            return Err(RecoveryFailure::LimitExceeded);
        }
        Some((anchor, root_epoch, envelope))
    } else {
        None
    };
    if !cursor.0.is_empty() || created == 0 || recipients.is_empty() {
        return Err(RecoveryFailure::Authentication);
    }
    if recipients != ["scrypt".to_owned()] {
        let canonical = RecoveryRecipients::parse(&recipients)?;
        if canonical.identities != recipients {
            return Err(RecoveryFailure::Authentication);
        }
    }
    let metadata = RecoveryMetadata {
        payload_version: u8::try_from(version).map_err(|_| RecoveryFailure::Authentication)?,
        identity: pin,
        created,
        recipients,
    };
    let expected = encode_with_system(&metadata, root, system);
    if !bool::from(expected.as_slice().ct_eq(bytes)) {
        return Err(RecoveryFailure::Authentication);
    }
    let key = SecretRootKey::from_owned(Box::new(
        root.try_into()
            .map_err(|_| RecoveryFailure::Authentication)?,
    ));
    let encoded = encode_file_v1(
        LocalKeyId::new(pin.root.key_id()).map_err(|_| RecoveryFailure::Authentication)?,
        LocalKeyCreationTime::from_unix_seconds(pin.root.created_at_unix_seconds()),
        key,
    )
    .map_err(|_| RecoveryFailure::Authentication)?;
    let custody = BootstrapKeyCustody::from_verified(
        parse_file_v1(encoded).map_err(|_| RecoveryFailure::Authentication)?,
    );
    if custody.identity() != pin.root {
        return Err(RecoveryFailure::Authentication);
    }
    let custody = if let Some((anchor, root_epoch, envelope)) = system {
        super::super::root_rewrap::open_system(custody, pin.instance, anchor, root_epoch, envelope)
            .map_err(|_| RecoveryFailure::Authentication)?
    } else {
        custody
    };
    Ok((metadata, custody))
}
struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn varint(&mut self) -> Result<u64, RecoveryFailure> {
        let mut value = 0u64;
        for shift in (0..70).step_by(7) {
            let (&byte, tail) = self
                .0
                .split_first()
                .ok_or(RecoveryFailure::Authentication)?;
            self.0 = tail;
            if shift == 63 && byte > 1 {
                return Err(RecoveryFailure::Authentication);
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                if shift != 0 && byte == 0 {
                    return Err(RecoveryFailure::Authentication);
                }
                return Ok(value);
            }
        }
        Err(RecoveryFailure::Authentication)
    }
    fn integer(&mut self, field: u8) -> Result<u64, RecoveryFailure> {
        if self.varint()? != u64::from(field) << 3 {
            return Err(RecoveryFailure::Authentication);
        }
        self.varint()
    }
    fn bytes(&mut self, field: u8) -> Result<&'a [u8], RecoveryFailure> {
        if self.varint()? != (u64::from(field) << 3) | 2 {
            return Err(RecoveryFailure::Authentication);
        }
        let length = usize::try_from(self.varint()?).map_err(|_| RecoveryFailure::LimitExceeded)?;
        let (value, tail) = self
            .0
            .split_at_checked(length)
            .ok_or(RecoveryFailure::Authentication)?;
        self.0 = tail;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_protobuf_tags_cross_single_byte_boundary_without_integer_overflow() {
        let mut wire = Vec::new();
        encode_varint_field(16, u64::MAX, &mut wire);
        encode_bytes_field(17, &[0xaa, 0xbb, 0xcc], &mut wire);
        assert_eq!(
            wire,
            [
                0x80, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x8a, 0x01,
                0x03, 0xaa, 0xbb, 0xcc
            ]
        );
        let mut cursor = Cursor(&wire);
        assert_eq!(cursor.integer(16), Ok(u64::MAX));
        assert_eq!(cursor.bytes(17), Ok([0xaa, 0xbb, 0xcc].as_slice()));
        assert!(cursor.0.is_empty());
        for prefix in 0..12 {
            assert!(Cursor(&wire[..prefix]).integer(16).is_err());
        }
        for rejected in [
            vec![0x80, 0x00, 1],       // noncanonical tag
            vec![0x80, 0x01, 0x80, 0], // noncanonical integer
            vec![0x82, 0x01, 0],       // wrong wire type
            vec![
                0x80, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2,
            ],
            vec![
                0x80, 0x01, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
            ],
        ] {
            assert_eq!(
                Cursor(&rejected).integer(16),
                Err(RecoveryFailure::Authentication)
            );
        }
        let mut longest_tag = Vec::new();
        encode_varint_field(u8::MAX, 1, &mut longest_tag);
        assert_eq!(longest_tag, [0xf8, 0x0f, 1]);
        assert_eq!(Cursor(&longest_tag).integer(u8::MAX), Ok(1));
    }
}
