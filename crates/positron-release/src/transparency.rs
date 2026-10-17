//! Offline Rekor DSSE entry, signed entry timestamp, signed checkpoint, and RFC 6962 audit path.
use crate::{
    construction::sha256,
    inventory::hex,
    publication::{base64, spki, string, verify_signature},
    *,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

pub(crate) fn verify_entry(
    entry: &Value,
    payload: &[u8],
    signature: &str,
    publisher: &[u8; 32],
    trust: &VerifiedTrust,
) -> Result<(), ReleaseError> {
    if string(entry, "/kindVersion/kind")? != "dsse"
        || string(entry, "/kindVersion/version")? != "0.0.1"
    {
        return Err(ReleaseError::Unsupported);
    }
    let log_id = base64(string(entry, "/logId/keyId")?)?;
    let key = trust.log_key(&log_id)?;
    let integrated = number(entry, "/integratedTime")?;
    if integrated > trust.now() || integrated == 0 {
        return Err(ReleaseError::StaleTrust);
    }
    trust.authorize_at(&key, KeyPurpose::Transparency, integrated)?;
    trust.authorize_at(publisher, KeyPurpose::Publisher, integrated)?;
    let body_text = string(entry, "/canonicalizedBody")?;
    let body = base64(body_text)?;
    let document: Value = serde_json::from_slice(&body).map_err(|_| ReleaseError::Invalid)?;
    if serde_json::to_vec(&document).map_err(|_| ReleaseError::Invalid)? != body
        || string(&document, "/kind")? != "dsse"
        || string(&document, "/apiVersion")? != "0.0.1"
        || string(&document, "/spec/payloadHash/algorithm")? != "sha256"
        || string(&document, "/spec/payloadHash/value")? != hex(&sha256(payload))
    {
        return Err(ReleaseError::IdentityMismatch);
    }
    let signatures = document
        .pointer("/spec/signatures")
        .and_then(Value::as_array)
        .ok_or(ReleaseError::Invalid)?;
    if signatures.len() != 1 {
        return Err(ReleaseError::Invalid);
    }
    let record = signatures.first().ok_or(ReleaseError::Invalid)?;
    if string(record, "/signature")? != signature {
        return Err(ReleaseError::IdentityMismatch);
    }
    let pem = base64(string(record, "/verifier")?)?;
    let pem = std::str::from_utf8(&pem).map_err(|_| ReleaseError::Invalid)?;
    let der = pem
        .strip_prefix("-----BEGIN PUBLIC KEY-----\n")
        .and_then(|pem| pem.strip_suffix("-----END PUBLIC KEY-----\n"))
        .ok_or(ReleaseError::Unsupported)?
        .lines()
        .collect::<String>();
    if base64(&der)? != spki(publisher) {
        return Err(ReleaseError::IdentityMismatch);
    }
    let set = serde_json::to_vec(&json!({"body":body_text,"integratedTime":integrated,"logID":hex(&log_id),"logIndex":number(entry,"/logIndex")?})).map_err(|_|ReleaseError::Invalid)?;
    verify_signature(
        &key,
        &set,
        &base64(string(entry, "/inclusionPromise/signedEntryTimestamp")?)?,
    )?;
    let proof = entry
        .get("inclusionProof")
        .ok_or(ReleaseError::Authentication)?;
    let size = number(proof, "/treeSize")?;
    let index = number(proof, "/logIndex")?;
    if size == 0 || index >= size {
        return Err(ReleaseError::Invalid);
    }
    let root = digest(string(proof, "/rootHash")?)?;
    verify_checkpoint(
        string(proof, "/checkpoint/envelope")?,
        size,
        &root,
        &key,
        &log_id,
    )?;
    let hashes = proof
        .get("hashes")
        .and_then(Value::as_array)
        .ok_or(ReleaseError::Invalid)?;
    if hashes.len() > 64 {
        return Err(ReleaseError::LimitExceeded);
    }
    let siblings = hashes
        .iter()
        .map(|value| digest(value.as_str().ok_or(ReleaseError::Invalid)?))
        .collect::<Result<Vec<_>, _>>()?;
    verify_transparency_inclusion(&body, index, size, &siblings, root)
}

/// Check the RFC 6962 SHA-256 inclusion path against an already authenticated root.
pub fn verify_transparency_inclusion(
    leaf_bytes: &[u8],
    index: u64,
    size: u64,
    siblings: &[[u8; 32]],
    root: [u8; 32],
) -> Result<(), ReleaseError> {
    if leaf_bytes.len() > 1_048_576 || siblings.len() > 64 {
        return Err(ReleaseError::LimitExceeded);
    }
    if size == 0 || index >= size {
        return Err(ReleaseError::Invalid);
    }
    let mut bytes = vec![0];
    bytes.extend(leaf_bytes);
    let mut hash = sha256(&bytes);
    let mut leaf = index;
    let mut last = size - 1;
    for sibling in siblings {
        if last == 0 {
            return Err(ReleaseError::Invalid);
        }
        let sibling = *sibling;
        let mut message = vec![1];
        if leaf & 1 == 1 || leaf == last {
            message.extend(sibling);
            message.extend(hash);
            while leaf & 1 == 0 && leaf != 0 {
                leaf >>= 1;
                last >>= 1;
            }
        } else {
            message.extend(hash);
            message.extend(sibling);
        }
        hash = sha256(&message);
        leaf >>= 1;
        last >>= 1;
    }
    if last != 0 || hash != root {
        return Err(ReleaseError::Authentication);
    }
    Ok(())
}
fn verify_checkpoint(
    envelope: &str,
    size: u64,
    root: &[u8; 32],
    key: &[u8; 32],
    log_id: &[u8],
) -> Result<(), ReleaseError> {
    let (text, signatures) = envelope.split_once("\n\n").ok_or(ReleaseError::Invalid)?;
    let mut lines = text.lines();
    let origin = lines.next().ok_or(ReleaseError::Invalid)?;
    if origin.is_empty()
        || origin.len() > 256
        || lines.next() != Some(size.to_string().as_str())
        || lines.next() != Some(STANDARD.encode(root).as_str())
        || lines.next().is_some()
    {
        return Err(ReleaseError::IdentityMismatch);
    }
    let message = format!("{text}\n");
    let mut accepted = false;
    for line in signatures.lines() {
        let line = line.strip_prefix("— ").ok_or(ReleaseError::Invalid)?;
        let (_, encoded) = line.split_once(' ').ok_or(ReleaseError::Invalid)?;
        let bytes = base64(encoded)?;
        if bytes.get(..4) == log_id.get(..4)
            && verify_signature(
                key,
                message.as_bytes(),
                bytes.get(4..).ok_or(ReleaseError::Invalid)?,
            )
            .is_ok()
        {
            accepted = true;
        }
    }
    if !accepted {
        return Err(ReleaseError::Authentication);
    }
    Ok(())
}
fn digest(value: &str) -> Result<[u8; 32], ReleaseError> {
    base64(value)?.try_into().map_err(|_| ReleaseError::Invalid)
}
fn number(value: &Value, pointer: &str) -> Result<u64, ReleaseError> {
    let value = string(value, pointer)?;
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(ReleaseError::Invalid);
    }
    value.parse().map_err(|_| ReleaseError::Invalid)
}
