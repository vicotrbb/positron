use crate::RepositoryFailure;
use sha2::{Digest, Sha256};
/// Azure public-cloud Blob REST 2023-11-03 account/container custody.
#[derive(Clone, Eq, PartialEq)]
pub struct AzureBlobTarget {
    account: String,
    container: String,
    prefix: String,
}
impl std::fmt::Debug for AzureBlobTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureBlobTarget")
            .field("commitment", &self.commitment())
            .finish()
    }
}
impl AzureBlobTarget {
    pub fn new(account: &str, container: &str, prefix: &str) -> Result<Self, RepositoryFailure> {
        if !(3..=24).contains(&account.len())
            || !account
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            || !(3..=63).contains(&container.len())
            || !container
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !container
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            || container.contains("--")
            || !container
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || prefix.is_empty()
            || prefix.len() > 512
            || !prefix.ends_with('/')
            || prefix.starts_with('/')
            || !prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.'))
            || prefix
                .strip_suffix('/')
                .is_none_or(|s| s.split('/').any(|p| matches!(p, "" | "." | "..")))
        {
            return Err(RepositoryFailure::InvalidInput);
        }
        Ok(Self {
            account: account.into(),
            container: container.into(),
            prefix: prefix.into(),
        })
    }
    pub const fn api_version(&self) -> &'static str {
        "2023-11-03"
    }
    pub fn account(&self) -> &str {
        &self.account
    }
    pub fn container(&self) -> &str {
        &self.container
    }
    pub fn prefix(&self) -> &str {
        &self.prefix
    }
    pub fn encode_locator(&self) -> String {
        [&*self.account, &*self.container, &*self.prefix].join("\0")
    }
    pub fn decode_locator(value: &str) -> Result<Self, RepositoryFailure> {
        if value.len() > 2048 {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let mut fields = value.split('\0');
        let mut next = || fields.next().ok_or(RepositoryFailure::InvalidInput);
        let result = Self::new(next()?, next()?, next()?);
        if fields.next().is_some() {
            return Err(RepositoryFailure::InvalidInput);
        }
        result
    }
    pub fn commitment(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"positron-azure-blob-target-v1\0");
        hash.update(self.encode_locator().as_bytes());
        hash.finalize().into()
    }
}
