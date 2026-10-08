use super::*;

pub(crate) struct BoundedArchive {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedArchive {
    pub(crate) const fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl io::Write for BoundedArchive {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let total = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|total| *total <= self.limit)
            .ok_or_else(|| io::Error::other("support bundle archive limit"))?;
        let additional = total.saturating_sub(self.bytes.len());
        self.bytes
            .try_reserve_exact(additional)
            .map_err(|_| io::Error::other("support bundle archive allocation"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn append<W: io::Write>(
    tar: &mut tar::Builder<&mut W>,
    path: &str,
    bytes: &[u8],
) -> io::Result<()> {
    let mut h = tar::Header::new_ustar();
    h.set_size(u64::try_from(bytes.len()).map_err(|_| io::Error::other("large"))?);
    h.set_mode(0o600);
    h.set_mtime(0);
    h.set_uid(0);
    h.set_gid(0);
    h.set_cksum();
    tar.append_data(&mut h, path, bytes)
}
pub(crate) fn blocks(n: usize) -> usize {
    n.saturating_add(BLOCK - 1) / BLOCK * BLOCK
}
pub(crate) fn once(v: &mut Vec<&'static str>, value: &'static str) -> Result<(), ()> {
    if !v.contains(&value) {
        if v.len() == 16 {
            return Err(());
        }
        v.try_reserve_exact(1).map_err(|_| ())?;
        v.push(value);
    }
    Ok(())
}
pub(crate) fn hex(bytes: &[u8]) -> Result<String, ()> {
    let mut s = String::new();
    s.try_reserve_exact(64).map_err(|_| ())?;
    for b in Sha256::digest(bytes) {
        use std::fmt::Write as _;
        write!(&mut s, "{b:02x}").map_err(|_| ())?;
    }
    Ok(s)
}

pub(crate) fn encode_bytes(bytes: &[u8]) -> Result<String, ()> {
    let length = bytes.len().checked_mul(2).ok_or(())?;
    let mut encoded = String::new();
    encoded.try_reserve_exact(length).map_err(|_| ())?;
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").map_err(|_| ())?;
    }
    Ok(encoded)
}

#[cfg(test)]
pub(crate) fn decode_64(value: &str) -> Result<[u8; 64], ()> {
    if value.len() != 128 {
        return Err(());
    }
    let mut result = [0_u8; 64];
    for (slot, pair) in result.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *slot = (hex_digit(pair[0]).ok_or(())? << 4) | hex_digit(pair[1]).ok_or(())?;
    }
    Ok(result)
}

#[cfg(test)]
const fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}
