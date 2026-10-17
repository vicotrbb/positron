//! Sigstore v0.3 public-key bundles with DSSE in-toto publication provenance.
use crate::{construction::sha256, inventory::hex, *};
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde_json::Value;

pub(crate) fn verify_publication(
    bytes: &[u8],
    artifact: &Artifact,
    digest: &str,
    manifest: &[u8; 32],
    trust: &VerifiedTrust,
    files: &crate::files::Bundle,
    inventory: &ReleaseInventory,
) -> Result<(), ReleaseError> {
    let bundle: Value = crate::trust::decode(bytes, 1_048_576)?;
    if string(&bundle, "/mediaType")? != "application/vnd.dev.sigstore.bundle.v0.3+json"
        || bundle.get("messageSignature").is_some()
        || bundle
            .pointer("/verificationMaterial/certificate")
            .is_some()
    {
        return Err(ReleaseError::Unsupported);
    }
    let hint = string(&bundle, "/verificationMaterial/publicKey/hint")?;
    let key = trust.publisher_key(hint)?;
    let envelope = bundle.get("dsseEnvelope").ok_or(ReleaseError::Invalid)?;
    let payload_type = string(envelope, "/payloadType")?;
    if payload_type != "application/vnd.in-toto+json" {
        return Err(ReleaseError::Unsupported);
    }
    let payload = base64(string(envelope, "/payload")?)?;
    let signatures = envelope
        .get("signatures")
        .and_then(Value::as_array)
        .ok_or(ReleaseError::Invalid)?;
    if signatures.len() != 1 {
        return Err(ReleaseError::Invalid);
    }
    let signature = signatures.first().ok_or(ReleaseError::Invalid)?;
    let signature_text = string(signature, "/sig")?;
    let signature = base64(signature_text)?;
    let mut pae = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes();
    pae.extend(&payload);
    verify_signature(&key, &pae, &signature)?;
    let statement: Value = serde_json::from_slice(&payload).map_err(|_| ReleaseError::Invalid)?;
    if string(&statement, "/_type")? != "https://in-toto.io/Statement/v1"
        || string(&statement, "/predicateType")? != "https://slsa.dev/provenance/v1"
        || string(&statement, "/predicate/buildDefinition/buildType")?
            != "https://positron.dev/publication/v1"
        || string(
            &statement,
            "/predicate/buildDefinition/externalParameters/registry",
        )? != artifact.publication.registry
        || string(
            &statement,
            "/predicate/buildDefinition/externalParameters/immutable_identity",
        )? != artifact.publication.immutable_identity
    {
        return Err(ReleaseError::IdentityMismatch);
    }
    let subjects = statement
        .get("subject")
        .and_then(Value::as_array)
        .ok_or(ReleaseError::Invalid)?;
    for (name, expected) in [
        (artifact.file.as_str(), digest),
        ("positron-release-manifest", hex(manifest).as_str()),
    ] {
        if !subjects.iter().any(|subject| {
            subject.get("name").and_then(Value::as_str) == Some(name)
                && subject.pointer("/digest/sha256").and_then(Value::as_str) == Some(expected)
        }) {
            return Err(ReleaseError::IdentityMismatch);
        }
    }
    if matches!(artifact.surface, Surface::OciImage | Surface::OciIndex) {
        verify_cosign(&statement, artifact, digest, manifest, &key)?;
    } else {
        crate::native_publication::verify_native(
            statement
                .pointer("/predicate/buildDefinition/externalParameters/native")
                .ok_or(ReleaseError::Authentication)?,
            artifact,
            inventory,
            files,
            trust,
        )?;
    }
    let entries = bundle
        .pointer("/verificationMaterial/tlogEntries")
        .and_then(Value::as_array)
        .ok_or(ReleaseError::Authentication)?;
    if entries.is_empty() || entries.len() > 8 {
        return Err(ReleaseError::Authentication);
    }
    // Every supplied proof must authenticate this exact signature and payload, never an unrelated log leaf.
    for entry in entries {
        crate::transparency::verify_entry(entry, &payload, signature_text, &key, trust)?;
    }
    Ok(())
}
fn verify_cosign(
    statement: &Value,
    artifact: &Artifact,
    digest: &str,
    manifest: &[u8; 32],
    key: &[u8; 32],
) -> Result<(), ReleaseError> {
    let proof = statement
        .pointer("/predicate/buildDefinition/externalParameters/cosign")
        .ok_or(ReleaseError::Authentication)?;
    let payload = base64(string(proof, "/payload")?)?;
    verify_signature(key, &payload, &base64(string(proof, "/signature")?)?)?;
    let payload: Value = serde_json::from_slice(&payload).map_err(|_| ReleaseError::Invalid)?;
    if string(&payload, "/critical/type")? != "cosign container image signature"
        || string(&payload, "/critical/identity/docker-reference")?
            != artifact.publication.registry.trim_start_matches("https://")
        || string(&payload, "/critical/image/docker-manifest-digest")? != format!("sha256:{digest}")
        || string(&payload, "/optional/positron-release-manifest")? != hex(manifest)
    {
        return Err(ReleaseError::IdentityMismatch);
    }
    Ok(())
}
pub(crate) fn string<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, ReleaseError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or(ReleaseError::Invalid)
}
pub(crate) fn base64(value: &str) -> Result<Vec<u8>, ReleaseError> {
    if value.len() > 1_048_576 {
        return Err(ReleaseError::LimitExceeded);
    }
    STANDARD.decode(value).map_err(|_| ReleaseError::Invalid)
}
pub(crate) fn verify_signature(
    key: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ReleaseError> {
    UnparsedPublicKey::new(&ED25519, key)
        .verify(message, signature)
        .map_err(|_| ReleaseError::Authentication)
}
pub(crate) fn spki(key: &[u8; 32]) -> Vec<u8> {
    let mut bytes = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    bytes.extend(key);
    bytes
}
pub(crate) fn key_hint(key: &[u8; 32]) -> String {
    hex(&sha256(&spki(key)))
}
