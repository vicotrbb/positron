use crate::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::Digest;
pub(super) fn md5(bytes: &[u8]) -> String {
    STANDARD.encode(md5::Md5::digest(bytes))
}
pub(super) fn escape(input: &str) -> String {
    input
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
pub(super) fn header<'a>(
    headers: &'a http::HeaderMap,
    name: &str,
) -> Result<&'a str, RepositoryFailure> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .ok_or(RepositoryFailure::CorruptState)
}
pub(super) fn etag(headers: &http::HeaderMap) -> Result<String, RepositoryFailure> {
    let value = header(headers, "etag")?;
    if value.len() > 256
        || !value.starts_with('"')
        || !value.ends_with('"')
        || !value.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(RepositoryFailure::CorruptState);
    }
    Ok(value.into())
}
pub(super) fn failure(
    reply: &google_cloud_auth::native::Response,
    mutation: bool,
) -> RepositoryFailure {
    match reply.status.as_u16() {
        401 | 403 => RepositoryFailure::PermissionDenied,
        404 => RepositoryFailure::NotFound,
        409 => RepositoryFailure::PreconditionFailed,
        412 => RepositoryFailure::PreconditionFailed,
        400 if reply
            .headers
            .get("x-ms-error-code")
            .is_some_and(|v| v == "Md5Mismatch") =>
        {
            RepositoryFailure::ChecksumMismatch
        },
        429 | 503 => RepositoryFailure::Throttled {
            retry_after_millis: reply
                .headers
                .get("x-ms-retry-after-ms")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| {
                    reply
                        .headers
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok())
                        .map(|s| s.saturating_mul(1000))
                })
                .unwrap_or(1000)
                .clamp(1, 60000) as u32,
        },
        500..=599 if mutation => RepositoryFailure::OutcomeUnknown,
        500..=599 => RepositoryFailure::StorageUnavailable,
        _ => RepositoryFailure::CorruptState,
    }
}
pub(super) fn protection(headers: &http::HeaderMap) -> Result<ObjectProtection, RepositoryFailure> {
    let mut result = ObjectProtection::unobservable();
    if let Some(value) = headers.get("x-ms-legal-hold") {
        result.legal_hold = PolicyObservation::Observed(
            match value
                .to_str()
                .map_err(|_| RepositoryFailure::CorruptState)?
            {
                "true" => true,
                "false" => false,
                _ => return Err(RepositoryFailure::CorruptState),
            },
        );
    }
    if let Some(value) = headers.get("x-ms-immutability-policy-until-date") {
        let value = value
            .to_str()
            .map_err(|_| RepositoryFailure::CorruptState)?;
        let date =
            time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc2822)
                .map_err(|_| RepositoryFailure::CorruptState)?;
        result.retention = PolicyObservation::Observed(ObjectRetention {
            mode: RetentionMode::ProviderEnforced,
            retain_until_unix_seconds: u64::try_from(date.unix_timestamp())
                .map_err(|_| RepositoryFailure::CorruptState)?,
        });
    }
    Ok(result)
}
#[derive(Debug)]
pub(super) struct Node {
    pub name: String,
    pub text: String,
    pub children: Vec<Node>,
}
impl Node {
    pub fn child(&self, name: &str) -> Result<Option<&Self>, RepositoryFailure> {
        let mut children = self.children.iter().filter(|n| n.name == name);
        let value = children.next();
        if children.next().is_some() {
            return Err(RepositoryFailure::CorruptState);
        }
        Ok(value)
    }
    pub fn required(&self, name: &str) -> Result<&Self, RepositoryFailure> {
        self.child(name)?.ok_or(RepositoryFailure::CorruptState)
    }
}
/// Bounded XML grammar using the already pinned native tokenizer. DTDs,
/// namespaces and entity expansion are rejected; Azure names are ASCII-safe.
pub(super) fn xml(bytes: &[u8]) -> Result<Node, RepositoryFailure> {
    if bytes.len() > 131072 {
        return Err(RepositoryFailure::LimitExceeded);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| RepositoryFailure::CorruptState)?;
    let mut stack: Vec<Node> = Vec::new();
    let mut root = None;
    let mut count = 0;
    for token in xmlparser::Tokenizer::from(text) {
        use xmlparser::{ElementEnd, Token};
        match token.map_err(|_| RepositoryFailure::CorruptState)? {
            Token::Declaration { .. } | Token::Comment { .. } => {},
            Token::ElementStart { prefix, local, .. } => {
                count += 1;
                if count > 4096 || stack.len() >= 16 || !prefix.is_empty() {
                    return Err(RepositoryFailure::LimitExceeded);
                }
                stack.push(Node {
                    name: local.as_str().into(),
                    text: String::new(),
                    children: Vec::new(),
                });
            },
            Token::Attribute { prefix, .. } if prefix.is_empty() => {},
            Token::ElementEnd { end, .. } => {
                let close = match end {
                    ElementEnd::Open => false,
                    ElementEnd::Empty => true,
                    ElementEnd::Close(prefix, name) => {
                        if !prefix.is_empty()
                            || stack.last().is_none_or(|n| n.name != name.as_str())
                        {
                            return Err(RepositoryFailure::CorruptState);
                        }
                        true
                    },
                };
                if close {
                    let node = stack.pop().ok_or(RepositoryFailure::CorruptState)?;
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(node)
                    } else if root.replace(node).is_some() {
                        return Err(RepositoryFailure::CorruptState);
                    }
                }
            },
            Token::Text { text } => {
                if let Some(node) = stack.last_mut() {
                    if text.as_str().contains('&') {
                        return Err(RepositoryFailure::CorruptState);
                    }
                    node.text.push_str(text.as_str());
                } else if !text.as_str().trim().is_empty() {
                    return Err(RepositoryFailure::CorruptState);
                }
            },
            _ => return Err(RepositoryFailure::CorruptState),
        }
    }
    if !stack.is_empty() {
        return Err(RepositoryFailure::CorruptState);
    }
    root.ok_or(RepositoryFailure::CorruptState)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_checksum_and_closed_failure_vectors() {
        assert_eq!(md5(b"abc"), "kAFQmDzST7DWlj99KOF/cg==");
        for (status, mutation, expected) in [
            (401, false, RepositoryFailure::PermissionDenied),
            (404, false, RepositoryFailure::NotFound),
            (412, true, RepositoryFailure::PreconditionFailed),
            (500, true, RepositoryFailure::OutcomeUnknown),
            (500, false, RepositoryFailure::StorageUnavailable),
            (400, false, RepositoryFailure::CorruptState),
        ] {
            let reply = google_cloud_auth::native::Response {
                status: http::StatusCode::from_u16(status).expect("status"),
                headers: http::HeaderMap::new(),
                body: zeroize::Zeroizing::new(b"credential canary".to_vec()),
            };
            assert_eq!(failure(&reply, mutation), expected);
            assert!(!format!("{:?}", failure(&reply, mutation)).contains("canary"));
        }
    }
    #[test]
    fn native_xml_rejects_expansion_namespaces_ambiguity_and_depth() {
        let parsed = xml(
            b"<?xml version=\"1.0\"?><BlockList><CommittedBlocks/><UncommittedBlocks/></BlockList>",
        )
        .expect("native block list");
        assert_eq!(parsed.name, "BlockList");
        for bytes in [
            b"<!DOCTYPE x [<!ENTITY secret SYSTEM 'file:///private'>]><x>&secret;</x>".as_slice(),
            b"<x/><y/>",
            b"<x><y></x>",
            b"<n:x/>",
            b"<x>&amp;</x>",
            b"text",
            b"<x>",
        ] {
            assert!(xml(bytes).is_err(), "{}", String::from_utf8_lossy(bytes));
        }
        let nested = format!("{}{}", "<x>".repeat(17), "</x>".repeat(17));
        assert!(xml(nested.as_bytes()).is_err());
        assert!(xml(&vec![b' '; 131073]).is_err());
        let duplicate = xml(b"<x><a/><a/></x>").expect("XML");
        assert!(duplicate.child("a").is_err());
    }
    #[test]
    fn native_etags_and_protection_are_closed() {
        let mut headers = http::HeaderMap::new();
        assert!(etag(&headers).is_err());
        for value in ["W/\"weak\"", "unquoted", "\"space etag\""] {
            headers.insert("etag", http::HeaderValue::from_str(value).expect("header"));
            assert!(etag(&headers).is_err());
        }
        headers.insert("etag", http::HeaderValue::from_static("\"0x0123\""));
        assert_eq!(etag(&headers).expect("etag"), "\"0x0123\"");
        headers.insert("x-ms-legal-hold", http::HeaderValue::from_static("true"));
        headers.insert(
            "x-ms-immutability-policy-until-date",
            http::HeaderValue::from_static("Tue, 01 Jan 2030 00:00:00 GMT"),
        );
        let result = protection(&headers).expect("protection");
        assert_eq!(result.legal_hold, PolicyObservation::Observed(true));
        assert_eq!(
            result.retention,
            PolicyObservation::Observed(ObjectRetention {
                mode: RetentionMode::ProviderEnforced,
                retain_until_unix_seconds: 1893456000
            })
        );
        headers.insert("x-ms-legal-hold", http::HeaderValue::from_static("maybe"));
        assert!(protection(&headers).is_err());
    }
}
