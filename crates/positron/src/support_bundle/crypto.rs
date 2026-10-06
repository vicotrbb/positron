use std::io::Write;

pub(super) fn encrypt(
    recipients: &[age::x25519::Recipient],
    plaintext: &[u8],
    limit: usize,
) -> Result<Vec<u8>, ()> {
    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|recipient| recipient as _))
            .map_err(|_| ())?;
    let mut ciphertext = BoundedCiphertext::new(limit);
    let mut writer = encryptor.wrap_output(&mut ciphertext).map_err(|_| ())?;
    writer.write_all(plaintext).map_err(|_| ())?;
    writer.finish().map_err(|_| ())?;
    Ok(ciphertext.into_bytes())
}

struct BoundedCiphertext {
    bytes: Vec<u8>,
    limit: usize,
}
impl BoundedCiphertext {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }
    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
impl Write for BoundedCiphertext {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len().saturating_add(bytes.len()) > self.limit {
            return Err(std::io::Error::other("ciphertext limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
