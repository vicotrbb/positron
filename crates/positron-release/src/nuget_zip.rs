//! NuGet's unsigned ZIP reconstruction, shared by native signatures and reproducible payload binding.
use crate::{ReleaseError, archive_scan::check_zip_count};
use std::{
    collections::BTreeSet,
    io::{Cursor, Read},
};
pub(crate) struct Package {
    pub unsigned: Vec<u8>,
    pub signature: Vec<u8>,
    pub nuspec: Vec<u8>,
    pub nuspec_name: String,
}
fn invalid() -> ReleaseError {
    ReleaseError::Invalid
}
fn word(bytes: &[u8], offset: usize) -> Result<u16, ReleaseError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}
fn number(bytes: &[u8], offset: usize) -> Result<u32, ReleaseError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}
fn offset(value: u64) -> Result<usize, ReleaseError> {
    usize::try_from(value).map_err(|_| ReleaseError::LimitExceeded)
}
pub(crate) fn package(bytes: &[u8]) -> Result<Package, ReleaseError> {
    if bytes.len() > 67_108_864 {
        return Err(ReleaseError::LimitExceeded);
    }
    let count = check_zip_count(bytes, 16_384)?;
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| invalid())?;
    if archive.len() != count || archive.offset() != 0 {
        return Err(invalid());
    }
    let central = offset(archive.central_directory_start())?;
    let eocd = bytes.len().checked_sub(22).ok_or_else(invalid)?;
    if bytes.get(eocd..eocd + 4) != Some(b"PK\x05\x06")
        || word(bytes, eocd + 20)? != 0
        || number(bytes, eocd + 16)? as usize != central
        || central.checked_add(number(bytes, eocd + 12)? as usize) != Some(eocd)
    {
        return Err(ReleaseError::Unsupported);
    }
    let mut names = BTreeSet::new();
    let mut signature = None;
    let mut nuspec = None;
    for index in 0..archive.len() {
        let mut file = archive.by_index_raw(index).map_err(|_| invalid())?;
        let name = std::str::from_utf8(file.name_raw())
            .map_err(|_| invalid())?
            .to_owned();
        if name.len() > 4096
            || !name.is_ascii()
            || name.starts_with('/')
            || name.contains('\\')
            || name.chars().any(char::is_control)
            || name
                .trim_end_matches('/')
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || !names.insert(name.to_ascii_lowercase())
            || file.encrypted()
            || file
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            return Err(invalid());
        }
        if name == ".signature.p7s" {
            if signature.is_some()
                || file.compression() != zip::CompressionMethod::Stored
                || file.size() > 1_048_576
                || file.compressed_size() != file.size()
            {
                return Err(ReleaseError::Unsupported);
            }
            let local = offset(file.header_start())?;
            let start = offset(file.data_start().ok_or_else(invalid)?)?;
            let cd = offset(file.central_header_start())?;
            let end = start
                .checked_add(offset(file.size())?)
                .ok_or_else(invalid)?;
            let cd_end = cd
                .checked_add(
                    46 + usize::from(word(bytes, cd + 28)?)
                        + usize::from(word(bytes, cd + 30)?)
                        + usize::from(word(bytes, cd + 32)?),
                )
                .ok_or_else(invalid)?;
            if end != central
                || cd_end != eocd
                || bytes.get(local..local + 4) != Some(b"PK\x03\x04")
                || word(bytes, local + 6)? != 0
                || word(bytes, local + 8)? != 0
                || local.checked_add(
                    30 + usize::from(word(bytes, local + 26)?)
                        + usize::from(word(bytes, local + 28)?),
                ) != Some(start)
                || bytes.get(local + 30..local + 30 + usize::from(word(bytes, local + 26)?))
                    != Some(b".signature.p7s")
            {
                return Err(ReleaseError::Unsupported);
            }
            let content = bytes.get(start..end).ok_or_else(invalid)?.to_vec();
            if crc32fast::hash(&content) != file.crc32()
                || number(bytes, local + 14)? != file.crc32()
            {
                return Err(invalid());
            }
            signature = Some((local, cd, cd_end, content));
        } else if !name.contains('/') && name.to_ascii_lowercase().ends_with(".nuspec") {
            if nuspec.is_some() || file.size() > 1_048_576 {
                return Err(invalid());
            }
            let size = file.size();
            let crc = file.crc32();
            let input: Box<dyn Read> = match file.compression() {
                zip::CompressionMethod::Stored => Box::new(&mut file),
                zip::CompressionMethod::DEFLATE => {
                    Box::new(flate2::read::DeflateDecoder::new(&mut file))
                },
                _ => return Err(ReleaseError::Unsupported),
            };
            let mut content = Vec::new();
            input
                .take(1_048_577)
                .read_to_end(&mut content)
                .map_err(|_| invalid())?;
            if content.len() as u64 != size || crc32fast::hash(&content) != crc {
                return Err(invalid());
            }
            nuspec = Some((name, content));
        }
    }
    let (local, cd, cd_end, signature) = signature.ok_or(ReleaseError::Authentication)?;
    let (nuspec_name, nuspec) = nuspec.ok_or(ReleaseError::IdentityMismatch)?;
    let mut unsigned = Vec::with_capacity(bytes.len());
    unsigned.extend(bytes.get(..local).ok_or_else(invalid)?);
    unsigned.extend(bytes.get(central..cd).ok_or_else(invalid)?);
    unsigned.extend(bytes.get(cd_end..).ok_or_else(invalid)?);
    let end = unsigned.len().checked_sub(22).ok_or_else(invalid)?;
    let remaining =
        u16::try_from(count.checked_sub(1).ok_or_else(invalid)?).map_err(|_| invalid())?;
    unsigned
        .get_mut(end + 8..end + 10)
        .ok_or_else(invalid)?
        .copy_from_slice(&remaining.to_le_bytes());
    unsigned
        .get_mut(end + 10..end + 12)
        .ok_or_else(invalid)?
        .copy_from_slice(&remaining.to_le_bytes());
    let size = number(bytes, eocd + 12)?
        .checked_sub(u32::try_from(cd_end - cd).map_err(|_| invalid())?)
        .ok_or_else(invalid)?;
    unsigned
        .get_mut(end + 12..end + 16)
        .ok_or_else(invalid)?
        .copy_from_slice(&size.to_le_bytes());
    unsigned
        .get_mut(end + 16..end + 20)
        .ok_or_else(invalid)?
        .copy_from_slice(&u32::try_from(local).map_err(|_| invalid())?.to_le_bytes());
    Ok(Package {
        unsigned,
        signature,
        nuspec,
        nuspec_name,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    #[test]
    fn native_unsigned_zip_hash_matches_independently_reconstructed_capture() {
        let package = package(include_bytes!("../tests/fixtures/tinyjson.1.0.0.nupkg")).unwrap();
        assert_eq!(package.unsigned.len(), 7178);
        assert_eq!(
            crate::inventory::hex(&Sha256::digest(&package.unsigned)),
            "a7ef45b0819e589570722ed78eb33957cc4b3cf96647a4c6e8c014e40e01a95a"
        );
    }
}
