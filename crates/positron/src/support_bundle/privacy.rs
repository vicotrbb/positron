use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

/// Ephemeral keyed mapping. It deliberately exposes only the pseudonym, never
/// the key or reverse map, so values correlate inside one export only.
pub(super) struct Pseudonymizer([u8; 32]);

impl Pseudonymizer {
    pub(super) fn new() -> Self {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Self(key)
    }

    pub(super) fn pseudonymize(&self, value: &str) -> Result<String, ()> {
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&self.0) else {
            return Err(());
        };
        mac.update(value.as_bytes());
        let mut output = String::with_capacity(67);
        output.push_str("id-");
        for byte in mac.finalize().into_bytes() {
            use std::fmt::Write as _;
            write!(&mut output, "{byte:02x}").map_err(|_| ())?;
        }
        Ok(output)
    }
}
