use crate::RepositoryFailure;
use sha2::{Digest, Sha256};

/// Exact GCS JSON API v1 bucket custody. Authentication is separate.
#[derive(Clone, Eq, PartialEq)]
pub struct GoogleCloudStorageTarget {
    bucket: String,
    project: String,
    location: String,
    prefix: String,
}
impl std::fmt::Debug for GoogleCloudStorageTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoogleCloudStorageTarget")
            .field("commitment", &self.commitment())
            .finish()
    }
}
impl GoogleCloudStorageTarget {
    pub fn new(
        bucket: &str,
        project: &str,
        location: &str,
        prefix: &str,
    ) -> Result<Self, RepositoryFailure> {
        let boundary = |value: &str| {
            value
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
                && value
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        };
        if !(3..=222).contains(&bucket.len())
            || (bucket.len() > 63 && !bucket.contains('.'))
            || bucket.split('.').any(|label| label.len() > 63)
            || !boundary(bucket)
            || !bucket.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
            })
            || bucket.contains("..")
            || bucket.starts_with("goog")
            || bucket.contains("google")
            || bucket.parse::<std::net::Ipv4Addr>().is_ok()
            || project.is_empty()
            || project.len() > 20
            || !project.bytes().all(|b| b.is_ascii_digit())
            || project.starts_with('0')
            || project.parse::<u64>().is_err()
            || location.is_empty()
            || location.len() > 64
            || !boundary(location)
            || !location
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
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
            bucket: bucket.into(),
            project: project.into(),
            location: location.into(),
            prefix: prefix.into(),
        })
    }
    pub const fn api_version(&self) -> &'static str {
        "v1"
    }
    pub fn bucket(&self) -> &str {
        &self.bucket
    }
    pub fn project_number(&self) -> &str {
        &self.project
    }
    pub fn location(&self) -> &str {
        &self.location
    }
    pub fn prefix(&self) -> &str {
        &self.prefix
    }
    pub fn encode_locator(&self) -> String {
        [
            &*self.bucket,
            &*self.project,
            &*self.location,
            &*self.prefix,
        ]
        .join("\0")
    }
    pub fn decode_locator(value: &str) -> Result<Self, RepositoryFailure> {
        if value.len() > 2048 {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let mut fields = value.split('\0');
        let mut next = || fields.next().ok_or(RepositoryFailure::InvalidInput);
        let result = Self::new(next()?, next()?, next()?, next()?);
        if fields.next().is_some() {
            return Err(RepositoryFailure::InvalidInput);
        }
        result
    }
    pub fn commitment(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"positron-google-cloud-storage-target-v1\0");
        hash.update(self.encode_locator().as_bytes());
        hash.finalize().into()
    }
}
