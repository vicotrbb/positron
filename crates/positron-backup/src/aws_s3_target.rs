use crate::RepositoryFailure;
use sha2::{Digest, Sha256};

/// One AWS general-purpose bucket, never an arbitrary S3-compatible endpoint.
/// Native credentials are resolved separately and never form part of this value.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsS3Target {
    bucket: String,
    region: String,
    endpoint: String,
    owner: String,
    prefix: String,
}
impl std::fmt::Debug for AwsS3Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsS3Target")
            .field("api_version", &self.api_version())
            .field("commitment", &self.commitment())
            .finish()
    }
}
// Standard regional endpoints pinned to the AWS S3 endpoint reference and
// aws-sdk-s3 1.152.0 partition metadata (API 2006-03-01).
// https://docs.aws.amazon.com/general/latest/gr/s3.html
const REGIONS: &[&str] = &[
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "af-south-1",
    "ap-east-1",
    "ap-east-2",
    "ap-south-1",
    "ap-south-2",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-southeast-3",
    "ap-southeast-4",
    "ap-southeast-5",
    "ap-southeast-6",
    "ap-southeast-7",
    "ca-central-1",
    "ca-west-1",
    "eu-central-1",
    "eu-central-2",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-south-1",
    "eu-south-2",
    "eu-north-1",
    "il-central-1",
    "mx-central-1",
    "me-south-1",
    "me-central-1",
    "sa-east-1",
    "us-gov-east-1",
    "us-gov-west-1",
    "cn-north-1",
    "cn-northwest-1",
];
impl AwsS3Target {
    /// Non-secret canonical target bytes for the existing durable operation.
    pub fn encode_locator(&self) -> String {
        [
            self.bucket(),
            self.region(),
            self.endpoint(),
            self.expected_owner(),
            self.prefix(),
        ]
        .join("\0")
    }
    pub fn decode_locator(locator: &str) -> Result<Self, RepositoryFailure> {
        if locator.len() > 2048 {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let mut fields = locator.split('\0');
        let bucket = fields.next().ok_or(RepositoryFailure::InvalidInput)?;
        let region = fields.next().ok_or(RepositoryFailure::InvalidInput)?;
        let endpoint = fields.next().ok_or(RepositoryFailure::InvalidInput)?;
        let owner = fields.next().ok_or(RepositoryFailure::InvalidInput)?;
        let prefix = fields.next().ok_or(RepositoryFailure::InvalidInput)?;
        if fields.next().is_some() {
            return Err(RepositoryFailure::InvalidInput);
        }
        Self::new(bucket, region, endpoint, owner, prefix)
    }
    pub fn new(
        bucket: &str,
        region: &str,
        endpoint: &str,
        owner: &str,
        prefix: &str,
    ) -> Result<Self, RepositoryFailure> {
        let alphanumeric = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
        if !(3..=63).contains(&bucket.len())
            || !bucket
                .bytes()
                .all(|byte| alphanumeric(byte) || matches!(byte, b'-' | b'.'))
            || !bucket
                .as_bytes()
                .first()
                .is_some_and(|byte| alphanumeric(*byte))
            || !bucket
                .as_bytes()
                .last()
                .is_some_and(|byte| alphanumeric(*byte))
            || bucket.contains("..")
            || bucket.contains(".-")
            || bucket.contains("-.")
            || bucket.parse::<std::net::Ipv4Addr>().is_ok()
            || ["xn--", "sthree-", "amzn-s3-demo-"]
                .iter()
                .any(|value| bucket.starts_with(value))
            || ["-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"]
                .iter()
                .any(|value| bucket.ends_with(value))
            || !REGIONS.contains(&region)
            || owner.len() != 12
            || !owner.bytes().all(|byte| byte.is_ascii_digit())
            || owner == "000000000000"
            || prefix.is_empty()
            || prefix.len() > 512
            || !prefix.ends_with('/')
            || prefix.starts_with('/')
            || !prefix.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.')
            })
            || prefix
                .strip_suffix('/')
                .is_none_or(|value| value.split('/').any(|part| matches!(part, "" | "." | "..")))
        {
            return Err(RepositoryFailure::InvalidInput);
        }
        let suffix = if region.starts_with("cn-") {
            "amazonaws.com.cn"
        } else {
            "amazonaws.com"
        };
        if endpoint != format!("https://s3.{region}.{suffix}") {
            return Err(RepositoryFailure::InvalidInput);
        }
        Ok(Self {
            bucket: bucket.into(),
            region: region.into(),
            endpoint: endpoint.into(),
            owner: owner.into(),
            prefix: prefix.into(),
        })
    }
    pub const fn api_version(&self) -> &'static str {
        "2006-03-01"
    }
    pub fn bucket(&self) -> &str {
        &self.bucket
    }
    pub fn region(&self) -> &str {
        &self.region
    }
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
    pub fn expected_owner(&self) -> &str {
        &self.owner
    }
    pub fn prefix(&self) -> &str {
        &self.prefix
    }
    pub fn commitment(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"positron-aws-s3-target-v1\0");
        for field in [
            self.api_version(),
            self.bucket(),
            self.region(),
            self.endpoint(),
            self.expected_owner(),
            self.prefix(),
        ] {
            hash.update(field.as_bytes());
            hash.update([0]);
        }
        hash.finalize().into()
    }
}
