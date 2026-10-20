//! Narrow RPM v4/gzip profile. No installation or general package interpretation.
use crate::ReleaseError;
use serde_json::Value;
use sha2::{Digest, Sha256};

const MAGIC: &[u8] = b"\x8e\xad\xe8\x01\0\0\0\0";
const MAX_HEADER: usize = 8 << 20;
struct Header<'a> {
    bytes: &'a [u8],
    index: &'a [u8],
    data: &'a [u8],
}
fn word(bytes: &[u8], offset: usize) -> Result<usize, ReleaseError> {
    Ok(u32::from_be_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(ReleaseError::Invalid)?
            .try_into()
            .map_err(|_| ReleaseError::Invalid)?,
    ) as usize)
}
impl<'a> Header<'a> {
    fn parse(bytes: &'a [u8], region: usize) -> Result<Self, ReleaseError> {
        if bytes.get(..8) != Some(MAGIC) {
            return Err(ReleaseError::Invalid);
        }
        let count = word(bytes, 8)?;
        let size = word(bytes, 12)?;
        if !(1..=4096).contains(&count) || size > MAX_HEADER {
            return Err(ReleaseError::LimitExceeded);
        }
        let end = 16 + count * 16;
        let header = Self {
            bytes: bytes.get(..end + size).ok_or(ReleaseError::Invalid)?,
            index: bytes.get(16..end).ok_or(ReleaseError::Invalid)?,
            data: bytes.get(end..end + size).ok_or(ReleaseError::Invalid)?,
        };
        let first = header.index.get(..16).ok_or(ReleaseError::Invalid)?;
        // Refuse dribbles: every index/data byte must be in the signed immutable region.
        if word(first, 0)? != region
            || word(first, 4)? != 7
            || word(first, 12)? != 16
            || word(first, 8)?.checked_add(16) != Some(size)
        {
            return Err(ReleaseError::Invalid);
        }
        let trailer = header
            .data
            .get(size.saturating_sub(16)..)
            .ok_or(ReleaseError::Invalid)?;
        if word(trailer, 0)? != region
            || word(trailer, 4)? != 7
            || word(trailer, 12)? != 16
            || word(trailer, 8)? as u32 != (-(count as i32 * 16)) as u32
        {
            return Err(ReleaseError::Invalid);
        }
        let mut previous = 0;
        let mut decoded = 0usize;
        for entry in header.index.chunks_exact(16) {
            let tag = word(entry, 0)?;
            if tag <= previous {
                return Err(ReleaseError::Invalid);
            }
            previous = tag;
            decoded = decoded
                .checked_add(header.value(entry, tag == region)?.len())
                .ok_or(ReleaseError::LimitExceeded)?;
            if decoded > MAX_HEADER {
                return Err(ReleaseError::LimitExceeded);
            }
        }
        Ok(header)
    }
    fn value(&self, entry: &[u8], region: bool) -> Result<&'a [u8], ReleaseError> {
        let kind = word(entry, 4)?;
        let offset = word(entry, 8)?;
        let count = word(entry, 12)?;
        let data = self
            .data
            .get(..self.data.len().saturating_sub(if region { 0 } else { 16 }))
            .ok_or(ReleaseError::Invalid)?;
        let tail = data.get(offset..).ok_or(ReleaseError::Invalid)?;
        let unit = match kind {
            1 | 2 | 7 => 1,
            3 => 2,
            4 => 4,
            5 => 8,
            6 | 8 | 9 => 0,
            _ => return Err(ReleaseError::Unsupported),
        };
        let size = if unit == 0 {
            if !(1..=16384).contains(&count) || (kind == 6 && count != 1) {
                return Err(ReleaseError::Invalid);
            }
            let mut size = 0;
            for _ in 0..count {
                size += tail
                    .get(size..)
                    .and_then(|bytes| bytes.iter().position(|byte| *byte == 0))
                    .ok_or(ReleaseError::Invalid)?
                    + 1;
            }
            size
        } else {
            if !offset.is_multiple_of(unit) {
                return Err(ReleaseError::Invalid);
            }
            count.checked_mul(unit).ok_or(ReleaseError::LimitExceeded)?
        };
        tail.get(..size).ok_or(ReleaseError::Invalid)
    }
    fn get(&self, tag: usize, kind: usize, count: usize) -> Result<&'a [u8], ReleaseError> {
        let entry = self
            .index
            .chunks_exact(16)
            .find(|entry| word(entry, 0) == Ok(tag))
            .ok_or(ReleaseError::Invalid)?;
        if word(entry, 4)? != kind || word(entry, 12)? != count {
            return Err(ReleaseError::Invalid);
        }
        self.value(entry, false)
    }
    fn text(&self, tag: usize) -> Result<&'a str, ReleaseError> {
        let bytes = self.get(tag, 6, 1)?;
        std::str::from_utf8(bytes.strip_suffix(&[0]).ok_or(ReleaseError::Invalid)?)
            .map_err(|_| ReleaseError::Invalid)
    }
}
pub(crate) struct Package<'a> {
    signature: Header<'a>,
    header: Header<'a>,
    pub(crate) payload: &'a [u8],
    pub(crate) functional: &'a [u8],
    pub(crate) metadata: &'a [u8],
}
pub(crate) fn package(bytes: &[u8]) -> Result<Package<'_>, ReleaseError> {
    if bytes.len() > 64 << 20 {
        return Err(ReleaseError::LimitExceeded);
    }
    if bytes.get(..4) != Some(b"\xed\xab\xee\xdb") {
        return Err(ReleaseError::Invalid);
    }
    let signature = Header::parse(bytes.get(96..).ok_or(ReleaseError::Invalid)?, 62)?;
    let next = 96 + signature.bytes.len();
    let aligned = next.next_multiple_of(8);
    if bytes
        .get(next..aligned)
        .ok_or(ReleaseError::Invalid)?
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(ReleaseError::Invalid);
    }
    let header = Header::parse(bytes.get(aligned..).ok_or(ReleaseError::Invalid)?, 63)?;
    let start = aligned + header.bytes.len();
    if header.text(1124)? != "cpio" || header.text(1125)? != "gzip" {
        return Err(ReleaseError::Unsupported);
    }
    let payload = bytes.get(start..).ok_or(ReleaseError::Invalid)?;
    if !payload.starts_with(&[0x1f, 0x8b]) {
        return Err(ReleaseError::Invalid);
    }
    Ok(Package {
        signature,
        header,
        functional: bytes.get(aligned..).ok_or(ReleaseError::Invalid)?,
        payload,
        metadata: bytes.get(..start).ok_or(ReleaseError::Invalid)?,
    })
}
pub(crate) fn verify(
    root: &Value,
    bytes: &[u8],
    version: &str,
    target: &str,
    subject: &str,
    now: u64,
) -> Result<(), ReleaseError> {
    let package = package(bytes)?;
    let arch = match target {
        "linux-x86_64" => "x86_64",
        "linux-aarch64" => "aarch64",
        _ => return Err(ReleaseError::Unsupported),
    };
    if package.header.text(1000)? != "positron"
        || package.header.text(1001)? != version
        || package.header.text(1002)? != "1"
        || package.header.text(1022)? != arch
        || subject != format!("pkg:rpm/positron@{version}-1?arch={arch}")
    {
        return Err(ReleaseError::IdentityMismatch);
    }
    if package.header.get(5093, 4, 1)? != 8u32.to_be_bytes() {
        return Err(ReleaseError::Unsupported);
    }
    let digest = package.header.get(5092, 8, 1)?;
    let expected = format!("{:x}\0", Sha256::digest(package.payload));
    if digest != expected.as_bytes() {
        return Err(ReleaseError::Authentication);
    }
    let signatures: Vec<_> = package
        .signature
        .index
        .chunks_exact(16)
        .filter(|entry| matches!(word(entry, 0), Ok(267 | 268)))
        .collect();
    let [signature] = signatures.as_slice() else {
        return Err(ReleaseError::Authentication);
    };
    if word(signature, 4)? != 7 {
        return Err(ReleaseError::Invalid);
    }
    crate::native_maven::verify_binary(
        root,
        package.signature.value(signature, false)?,
        package.header.bytes,
        now,
    )
}

/// Return the reproducible RPM v4 main header and compressed payload. The lead
/// and mutable signing header are wrapping layers; scripts and package metadata
/// remain part of these functional bytes. This does not authenticate a package.
pub fn rpm_functional_payload(bytes: &[u8]) -> Result<&[u8], ReleaseError> {
    Ok(package(bytes)?.functional)
}
