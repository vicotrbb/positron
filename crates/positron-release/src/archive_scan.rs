//! Bounded content scanning without filesystem extraction. Package-specific security reports remain required.
use crate::{
    files::{Bundle, contains_secret, inspect_reader},
    *,
};
use std::{
    io::{Cursor, Read},
    path::Path,
};
mod packages;
const MAX_ZIP: usize = 67_108_864;
const MAX_MEMBER: u64 = 536_870_912;
struct Budget {
    remaining: u64,
    entries: usize,
}
/// Scan raw bytes and decoded gzip, tar, and ZIP contents for credential forms and explicit canaries.
pub fn scan_release_contents(
    directory: &Path,
    id: &str,
    canaries: &[Vec<u8>],
) -> Result<(), ReleaseError> {
    scan_bundle_contents(&Bundle::open(directory)?, id, canaries)
}
pub(crate) fn scan_bundle_contents(
    bundle: &Bundle,
    id: &str,
    canaries: &[Vec<u8>],
) -> Result<(), ReleaseError> {
    if canaries.len() > 64
        || canaries
            .iter()
            .any(|value| !(8..=128).contains(&value.len()))
    {
        return Err(ReleaseError::Invalid);
    }
    scan(
        bundle.file(id)?,
        canaries,
        0,
        &mut Budget {
            remaining: 8_589_934_592,
            entries: 16_384,
        },
    )
}
fn scan(
    mut reader: impl Read,
    canaries: &[Vec<u8>],
    depth: usize,
    budget: &mut Budget,
) -> Result<(), ReleaseError> {
    if depth > 4 {
        return Err(ReleaseError::LimitExceeded);
    }
    let mut prefix = Vec::new();
    reader
        .by_ref()
        .take(512)
        .read_to_end(&mut prefix)
        .map_err(|_| ReleaseError::Invalid)?;
    if contains_secret(&prefix, canaries) {
        return Err(ReleaseError::SecretDetected);
    }
    let gzip = prefix.starts_with(&[0x1f, 0x8b]);
    let zip = prefix.starts_with(b"PK\x03\x04") || prefix.starts_with(b"PK\x05\x06");
    let tar = prefix.get(257..262) == Some(b"ustar".as_slice());
    let rpm = prefix.starts_with(b"\xed\xab\xee\xdb");
    let ar = prefix.starts_with(b"!<arch>\n");
    let cpio = prefix.starts_with(b"070701") || prefix.starts_with(b"070702");
    let stream = Cursor::new(prefix).chain(reader);
    if rpm {
        let mut bytes = Vec::new();
        stream
            .take((64 << 20) + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ReleaseError::Invalid)?;
        let package = crate::native_rpm::package(&bytes)?;
        let size = inspect_reader(
            package.metadata,
            canaries,
            budget.remaining.min(MAX_MEMBER),
            true,
        )?
        .size;
        budget.remaining = budget
            .remaining
            .checked_sub(size)
            .ok_or(ReleaseError::LimitExceeded)?;
        return scan(
            Box::new(package.payload) as Box<dyn Read>,
            canaries,
            depth + 1,
            budget,
        );
    }
    if ar {
        return packages::ar(stream, canaries, depth, budget);
    }
    if cpio {
        return packages::cpio(stream, canaries, depth, budget);
    }
    if gzip {
        return scan(
            Box::new(flate2::read::MultiGzDecoder::new(stream)) as Box<dyn Read>,
            canaries,
            depth + 1,
            budget,
        );
    }
    if tar {
        let mut archive = tar::Archive::new(stream);
        // Raw iteration must precede our bounds: automatic GNU/PAX expansion
        // reads metadata into unbounded vectors inside the upstream parser.
        for entry in archive
            .entries()
            .map_err(|_| ReleaseError::Invalid)?
            .raw(true)
        {
            budget.entries = budget
                .entries
                .checked_sub(1)
                .ok_or(ReleaseError::LimitExceeded)?;
            let mut entry = entry.map_err(|_| ReleaseError::Invalid)?;
            if entry.size() > MAX_MEMBER
                || entry.size() > budget.remaining
                || entry.path_bytes().len() > 4096
            {
                return Err(ReleaseError::LimitExceeded);
            }
            if contains_secret(&entry.path_bytes(), canaries)
                || contains_secret(entry.header().as_bytes(), canaries)
            {
                return Err(ReleaseError::SecretDetected);
            }
            let kind = entry.header().entry_type();
            if kind.is_gnu_sparse() {
                return Err(ReleaseError::Unsupported);
            }
            if kind.is_gnu_longname()
                || kind.is_gnu_longlink()
                || kind.is_pax_local_extensions()
                || kind.is_pax_global_extensions()
            {
                // Metadata is screened as serialized bytes, never interpreted
                // as another archive or applied to a later header.
                let expected = entry.size();
                let size =
                    inspect_reader(&mut entry, canaries, budget.remaining.min(MAX_MEMBER), true)?
                        .size;
                if size != expected {
                    return Err(ReleaseError::Invalid);
                }
                budget.remaining = budget
                    .remaining
                    .checked_sub(size)
                    .ok_or(ReleaseError::LimitExceeded)?;
            } else {
                scan(
                    Box::new(&mut entry) as Box<dyn Read>,
                    canaries,
                    depth + 1,
                    budget,
                )?;
            }
        }
        let remaining = inspect_reader(
            archive.into_inner(),
            canaries,
            budget.remaining.min(MAX_MEMBER),
            true,
        )?
        .size;
        budget.remaining = budget
            .remaining
            .checked_sub(remaining)
            .ok_or(ReleaseError::LimitExceeded)?;
        return Ok(());
    }
    if zip {
        let mut bytes = Vec::new();
        stream
            .take(MAX_ZIP as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ReleaseError::Invalid)?;
        if bytes.len() > MAX_ZIP {
            return Err(ReleaseError::LimitExceeded);
        }
        let declared = check_zip_count(&bytes, budget.entries)?;
        let mut archive =
            zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| ReleaseError::Invalid)?;
        if archive.len() != declared {
            return Err(ReleaseError::Invalid);
        }
        for index in 0..archive.len() {
            budget.entries = budget
                .entries
                .checked_sub(1)
                .ok_or(ReleaseError::LimitExceeded)?;
            let mut entry = archive
                .by_index_raw(index)
                .map_err(|_| ReleaseError::Invalid)?;
            if entry.size() > MAX_MEMBER || entry.name_raw().len() > 4096 {
                return Err(ReleaseError::LimitExceeded);
            }
            if entry.encrypted() {
                return Err(ReleaseError::Unsupported);
            }
            if contains_secret(entry.name_raw(), canaries) {
                return Err(ReleaseError::SecretDetected);
            }
            let expected_crc = entry.crc32();
            let expected_size = entry.size();
            let method = entry.compression();
            let input: Box<dyn Read> = if method == zip::CompressionMethod::Stored {
                Box::new(&mut entry)
            } else if method == zip::CompressionMethod::DEFLATE {
                Box::new(flate2::read::DeflateDecoder::new(&mut entry))
            } else {
                return Err(ReleaseError::Unsupported);
            };
            let mut checked = CrcReader {
                input,
                hash: crc32fast::Hasher::new(),
                size: 0,
            };
            scan(
                Box::new(&mut checked) as Box<dyn Read>,
                canaries,
                depth + 1,
                budget,
            )?;
            if checked.size != expected_size || checked.hash.finalize() != expected_crc {
                return Err(ReleaseError::Invalid);
            }
        }
        return Ok(());
    }
    let size = inspect_reader(stream, canaries, budget.remaining.min(MAX_MEMBER), true)?.size;
    budget.remaining = budget
        .remaining
        .checked_sub(size)
        .ok_or(ReleaseError::LimitExceeded)?;
    Ok(())
}
struct CrcReader<'a> {
    input: Box<dyn Read + 'a>,
    hash: crc32fast::Hasher,
    size: u64,
}
impl Read for CrcReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let count = self.input.read(bytes)?;
        let read = bytes
            .get(..count)
            .ok_or_else(|| std::io::Error::other("invalid archive read"))?;
        self.hash.update(read);
        self.size = self.size.saturating_add(count as u64);
        Ok(count)
    }
}
pub(crate) fn check_zip_count(bytes: &[u8], maximum: usize) -> Result<usize, ReleaseError> {
    // Bound central-directory allocation before asking the standard parser to index entries.
    let start = bytes.len().saturating_sub(65_557);
    let tail = bytes.get(start..).ok_or(ReleaseError::Invalid)?;
    let offset = tail
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .ok_or(ReleaseError::Invalid)?;
    let end = tail.get(offset..).ok_or(ReleaseError::Invalid)?;
    let word = |position| -> Result<u16, ReleaseError> {
        Ok(u16::from_le_bytes(
            end.get(position..position + 2)
                .ok_or(ReleaseError::Invalid)?
                .try_into()
                .map_err(|_| ReleaseError::Invalid)?,
        ))
    };
    let central_size = u32::from_le_bytes(
        end.get(12..16)
            .ok_or(ReleaseError::Invalid)?
            .try_into()
            .map_err(|_| ReleaseError::Invalid)?,
    );
    if central_size > 8_388_608
        || offset
            .checked_sub(20)
            .and_then(|offset| tail.get(offset..offset + 4))
            == Some(b"PK\x06\x07".as_slice())
    {
        return Err(ReleaseError::Unsupported);
    }
    if word(4)? != 0
        || word(6)? != 0
        || word(8)? != word(10)?
        || usize::from(word(10)?) > maximum
        || word(10)? == u16::MAX
        || end.len() != 22 + usize::from(word(20)?)
    {
        return Err(ReleaseError::LimitExceeded);
    }
    Ok(usize::from(word(10)?))
}
