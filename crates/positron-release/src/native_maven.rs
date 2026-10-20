//! Maven Central detached OpenPGP verification under an installed certificate.
use crate::ReleaseError;
use pgp::{
    armor::{BlockType, Dearmor},
    composed::{Deserializable, DetachedSignature, SignedPublicKey},
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    packet::{Packet, PacketParser, Signature, SignatureType, SubpacketData},
    types::{Duration, EddsaLegacyPublicParams, KeyDetails, KeyVersion, PublicParams},
};
use rsa::traits::PublicKeyParts;
use serde_json::Value;
use std::io::Read;

const MAX_NATIVE_BYTES: usize = 65_536;

/// This profile uses an explicitly installed signing primary key. Subkey-based
/// certificates are refused instead of approximating OpenPGP certification policy.
pub(crate) fn verify(
    root: &Value,
    proof: &Value,
    contents: &[u8],
    now: u64,
) -> Result<(), ReleaseError> {
    let key: SignedPublicKey = armored(field(root, "public_key")?, BlockType::PublicKey)?;
    let detached: DetachedSignature = armored(field(proof, "signature")?, BlockType::Signature)?;
    verify_signature(key, detached, contents, now)
}

/// The RPM signature packet is binary, but uses precisely the same certificate
/// authorization, algorithm, revocation, expiry, and signer policy as Maven.
pub(crate) fn verify_binary(
    root: &Value,
    bytes: &[u8],
    contents: &[u8],
    now: u64,
) -> Result<(), ReleaseError> {
    if bytes.len() > MAX_NATIVE_BYTES {
        return Err(ReleaseError::LimitExceeded);
    }
    let key: SignedPublicKey = armored(field(root, "public_key")?, BlockType::PublicKey)?;
    let mut packets = PacketParser::new(bytes);
    let signature = match packets.next() {
        Some(Ok(Packet::Signature(signature))) => signature,
        _ => return Err(ReleaseError::Invalid),
    };
    if !packets.into_inner().is_empty() {
        return Err(ReleaseError::Invalid);
    }
    verify_signature(key, DetachedSignature::new(signature), contents, now)
}

fn verify_signature(
    key: SignedPublicKey,
    detached: DetachedSignature,
    contents: &[u8],
    now: u64,
) -> Result<(), ReleaseError> {
    if !matches!(key.version(), KeyVersion::V4 | KeyVersion::V6)
        || !key.public_subkeys.is_empty()
        || !key.details.user_attributes.is_empty()
        || detached.signature.typ() != Some(SignatureType::Binary)
    {
        return Err(ReleaseError::Unsupported);
    }
    let eligible = match (key.algorithm(), key.public_params()) {
        (PublicKeyAlgorithm::Ed25519, PublicParams::Ed25519(_))
        | (
            PublicKeyAlgorithm::EdDSALegacy,
            PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 { .. }),
        ) => true,
        (PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSASign, PublicParams::RSA(parameters)) => {
            (2048..=8192).contains(&parameters.key.n().bits())
        },
        _ => false,
    };
    if !eligible {
        return Err(ReleaseError::Unsupported);
    }
    key.verify_bindings()
        .map_err(|_| ReleaseError::Authentication)?;
    if !key.details.revocation_signatures.is_empty() {
        return Err(ReleaseError::Revoked);
    }
    let key_created = u64::from(key.created_at().as_secs());
    if key_created > now {
        return Err(ReleaseError::Authentication);
    }
    let mut current: Option<(&Signature, u64)> = None;
    // These are all self-signatures: verify_bindings rejects third-party
    // certifications rather than trusting their flags or expiry metadata.
    for signature in key.details.direct_signatures.iter().chain(
        key.details
            .users
            .iter()
            .flat_map(|user| user.signatures.iter()),
    ) {
        let created = signature
            .created()
            .map(|time| u64::from(time.as_secs()))
            .ok_or(ReleaseError::Authentication)?;
        if created <= now && current.is_none_or(|(_, previous)| created > previous) {
            current = Some((signature, created));
        } else if current.is_some_and(|(previous, time)| time == created && previous != signature) {
            return Err(ReleaseError::Authentication);
        }
    }
    let (metadata, _) = current.ok_or(ReleaseError::Authentication)?;
    let metadata_created = signature_policy(metadata, now)?;
    if metadata_created < key_created
        || !metadata.key_flags().sign()
        || expired(key_created, metadata.key_expiration_time(), now)
        || (key.version() == KeyVersion::V6 && metadata.typ() != Some(SignatureType::Key))
    {
        return Err(ReleaseError::Authentication);
    }
    let signature_created = signature_policy(&detached.signature, now)?;
    if signature_created < key_created
        || detached
            .signature
            .issuer_fingerprint()
            .iter()
            .any(|fingerprint| **fingerprint != key.fingerprint())
        || detached
            .signature
            .issuer_key_id()
            .iter()
            .any(|id| **id != key.legacy_key_id())
    {
        return Err(ReleaseError::Authentication);
    }
    detached
        .verify(&key.primary_key, contents)
        .map_err(|_| ReleaseError::Authentication)
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str, ReleaseError> {
    let object = value.as_object().ok_or(ReleaseError::Invalid)?;
    if object.len() != 1 {
        return Err(ReleaseError::Invalid);
    }
    let text = object
        .get(name)
        .and_then(Value::as_str)
        .ok_or(ReleaseError::Invalid)?;
    if text.len() > MAX_NATIVE_BYTES {
        return Err(ReleaseError::LimitExceeded);
    }
    Ok(text)
}

fn armored<T: Deserializable>(text: &str, kind: BlockType) -> Result<T, ReleaseError> {
    let text = text.trim();
    let begin = format!("-----BEGIN {kind}-----");
    let end = format!("-----END {kind}-----");
    if !text.starts_with(&begin)
        || !text.ends_with(&end)
        || text.matches("-----BEGIN ").count() != 1
        || text.matches("-----END ").count() != 1
    {
        return Err(ReleaseError::Invalid);
    }
    let mut reader = Dearmor::new(text.as_bytes());
    let mut decoded = Vec::new();
    reader
        .read_to_end(&mut decoded)
        .map_err(|_| ReleaseError::Invalid)?;
    if reader.typ != Some(kind) {
        return Err(ReleaseError::Invalid);
    }
    // The high-level convenience parser intentionally skips some malformed or
    // unsupported packets. This trust boundary must preserve those failures.
    let mut remaining = decoded.as_slice();
    let mut packets = Vec::new();
    while !remaining.is_empty() {
        let mut parser = PacketParser::new(remaining);
        packets.push(
            parser
                .next()
                .ok_or(ReleaseError::Invalid)?
                .map_err(|_| ReleaseError::Invalid)?,
        );
        remaining = parser.into_inner();
    }
    if packets.iter().any(|packet| match kind {
        BlockType::PublicKey => !matches!(
            packet,
            Packet::PublicKey(_) | Packet::Signature(_) | Packet::UserId(_)
        ),
        BlockType::Signature => !matches!(packet, Packet::Signature(_)),
        _ => true,
    }) {
        return Err(ReleaseError::Unsupported);
    }
    if kind == BlockType::PublicKey {
        let mut parts = packets.iter();
        if !matches!(parts.next(), Some(Packet::PublicKey(_))) {
            return Err(ReleaseError::Unsupported);
        }
        let mut user = false;
        let mut signed = true;
        for packet in parts {
            match packet {
                Packet::UserId(_) if signed => {
                    user = true;
                    signed = false;
                },
                Packet::Signature(signature)
                    if (user && signature.is_certification())
                        || (!user
                            && matches!(
                                signature.typ(),
                                Some(SignatureType::Key | SignatureType::KeyRevocation)
                            )) =>
                {
                    signed = true;
                },
                _ => return Err(ReleaseError::Unsupported),
            }
        }
        if !signed {
            return Err(ReleaseError::Unsupported);
        }
    }
    let mut parsed = T::from_packets(packets.into_iter().map(Ok).peekable());
    let value = parsed
        .next()
        .ok_or(ReleaseError::Invalid)?
        .map_err(|_| ReleaseError::Invalid)?;
    if parsed.next().is_some() {
        return Err(ReleaseError::Invalid);
    }
    Ok(value)
}

fn signature_policy(signature: &Signature, now: u64) -> Result<u64, ReleaseError> {
    if !matches!(
        signature.hash_alg(),
        Some(
            HashAlgorithm::Sha224
                | HashAlgorithm::Sha256
                | HashAlgorithm::Sha384
                | HashAlgorithm::Sha512
        )
    ) {
        return Err(ReleaseError::Unsupported);
    }
    let config = signature.config().ok_or(ReleaseError::Unsupported)?;
    let mut creation = 0;
    let mut signature_expiry = 0;
    let mut key_expiry = 0;
    let mut flags = 0;
    for subpacket in config.hashed_subpackets() {
        match &subpacket.data {
            SubpacketData::SignatureCreationTime(_) => creation += 1,
            SubpacketData::SignatureExpirationTime(_) => signature_expiry += 1,
            SubpacketData::KeyExpirationTime(_) => key_expiry += 1,
            SubpacketData::KeyFlags(_) => flags += 1,
            _ => (),
        }
        if subpacket.is_critical
            && !matches!(
                &subpacket.data,
                SubpacketData::SignatureCreationTime(_)
                    | SubpacketData::SignatureExpirationTime(_)
                    | SubpacketData::KeyExpirationTime(_)
                    | SubpacketData::KeyFlags(_)
                    | SubpacketData::IssuerKeyId(_)
                    | SubpacketData::IssuerFingerprint(_)
                    | SubpacketData::RevocationReason(_, _)
            )
        {
            return Err(ReleaseError::Unsupported);
        }
    }
    let created = signature
        .created()
        .map(|time| u64::from(time.as_secs()))
        .ok_or(ReleaseError::Authentication)?;
    if creation != 1
        || signature_expiry > 1
        || key_expiry > 1
        || flags > 1
        || created > now
        || expired(created, signature.signature_expiration_time(), now)
    {
        return Err(ReleaseError::Authentication);
    }
    Ok(created)
}

fn expired(created: u64, lifetime: Option<Duration>, now: u64) -> bool {
    lifetime.is_some_and(|duration| {
        duration.as_secs() != 0
            && created
                .checked_add(u64::from(duration.as_secs()))
                .is_none_or(|expiry| now >= expiry)
    })
}

#[cfg(test)]
mod tests;
