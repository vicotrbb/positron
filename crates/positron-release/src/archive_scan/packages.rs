//! Streaming package containers; all recursion consumes the enclosing scan budget.
use super::*;

fn exact(reader: &mut impl Read, bytes: &mut [u8]) -> Result<(), ReleaseError> {
    reader.read_exact(bytes).map_err(|_| ReleaseError::Invalid)
}
fn entry(budget: &mut Budget, size: u64) -> Result<(), ReleaseError> {
    budget.entries = budget
        .entries
        .checked_sub(1)
        .ok_or(ReleaseError::LimitExceeded)?;
    if size > MAX_MEMBER || size > budget.remaining {
        return Err(ReleaseError::LimitExceeded);
    }
    Ok(())
}
fn number(bytes: &[u8], radix: u32) -> Result<u64, ReleaseError> {
    u64::from_str_radix(
        std::str::from_utf8(bytes)
            .map_err(|_| ReleaseError::Invalid)?
            .trim(),
        radix,
    )
    .map_err(|_| ReleaseError::Invalid)
}
fn screen(bytes: &[u8], canaries: &[Vec<u8>]) -> Result<(), ReleaseError> {
    if contains_secret(bytes, canaries) {
        return Err(ReleaseError::SecretDetected);
    }
    Ok(())
}
fn member(
    reader: &mut impl Read,
    size: u64,
    canaries: &[Vec<u8>],
    depth: usize,
    budget: &mut Budget,
) -> Result<(), ReleaseError> {
    entry(budget, size)?;
    let mut limited = reader.take(size);
    scan(
        Box::new(&mut limited) as Box<dyn Read>,
        canaries,
        depth + 1,
        budget,
    )?;
    if limited.limit() != 0 {
        return Err(ReleaseError::Invalid);
    }
    Ok(())
}
pub(super) fn ar(
    mut reader: impl Read,
    canaries: &[Vec<u8>],
    depth: usize,
    budget: &mut Budget,
) -> Result<(), ReleaseError> {
    let mut magic = [0; 8];
    exact(&mut reader, &mut magic)?;
    loop {
        let mut header = [0; 60];
        if reader
            .read(header.get_mut(..1).ok_or(ReleaseError::Invalid)?)
            .map_err(|_| ReleaseError::Invalid)?
            == 0
        {
            return Ok(());
        }
        exact(
            &mut reader,
            header.get_mut(1..).ok_or(ReleaseError::Invalid)?,
        )?;
        if header.get(58..) != Some(b"`\n") {
            return Err(ReleaseError::Invalid);
        }
        screen(&header, canaries)?;
        let name = std::str::from_utf8(header.get(..16).ok_or(ReleaseError::Invalid)?)
            .map_err(|_| ReleaseError::Invalid)?
            .trim()
            .trim_end_matches('/');
        if name.is_empty()
            || name.starts_with('#')
            || name.contains('/')
            || [".xz", ".zst", ".bz2", ".lzma"]
                .iter()
                .any(|suffix| name.ends_with(suffix))
        {
            return Err(ReleaseError::Unsupported);
        }
        let size = number(header.get(48..58).ok_or(ReleaseError::Invalid)?, 10)?;
        member(&mut reader, size, canaries, depth, budget)?;
        if !size.is_multiple_of(2) {
            let mut pad = [0];
            exact(&mut reader, &mut pad)?;
            if pad != [b'\n'] {
                return Err(ReleaseError::Invalid);
            }
        }
    }
}
pub(super) fn cpio(
    mut reader: impl Read,
    canaries: &[Vec<u8>],
    depth: usize,
    budget: &mut Budget,
) -> Result<(), ReleaseError> {
    loop {
        let mut header = [0; 110];
        exact(&mut reader, &mut header)?;
        if header.get(..6) != Some(b"070701") {
            return Err(ReleaseError::Unsupported);
        }
        screen(&header, canaries)?;
        let size = number(header.get(54..62).ok_or(ReleaseError::Invalid)?, 16)?;
        let namesize = number(header.get(94..102).ok_or(ReleaseError::Invalid)?, 16)?;
        if !(1..=4096).contains(&namesize) {
            return Err(ReleaseError::LimitExceeded);
        }
        if number(header.get(102..110).ok_or(ReleaseError::Invalid)?, 16)? != 0 {
            return Err(ReleaseError::Invalid);
        }
        let mut name = vec![0; namesize as usize];
        exact(&mut reader, &mut name)?;
        if name.last() != Some(&0)
            || name
                .get(..name.len() - 1)
                .ok_or(ReleaseError::Invalid)?
                .contains(&0)
        {
            return Err(ReleaseError::Invalid);
        }
        screen(&name, canaries)?;
        padding(&mut reader, (110 + namesize) % 4)?;
        if name == b"TRAILER!!!\0" {
            if size != 0 {
                return Err(ReleaseError::Invalid);
            }
            let mut tail = Vec::new();
            reader
                .take(512)
                .read_to_end(&mut tail)
                .map_err(|_| ReleaseError::Invalid)?;
            if tail.len() == 512 || tail.iter().any(|byte| *byte != 0) {
                return Err(ReleaseError::Invalid);
            }
            return Ok(());
        }
        member(&mut reader, size, canaries, depth, budget)?;
        padding(&mut reader, size % 4)?;
    }
}
fn padding(reader: &mut impl Read, remainder: u64) -> Result<(), ReleaseError> {
    let mut bytes = [0; 3];
    let count = ((4 - remainder) % 4) as usize;
    let bytes = bytes.get_mut(..count).ok_or(ReleaseError::Invalid)?;
    exact(reader, bytes)?;
    if bytes.iter().any(|byte| *byte != 0) {
        return Err(ReleaseError::Invalid);
    }
    Ok(())
}
