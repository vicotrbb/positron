use crate::RepositoryFailure;
use sha2::{Digest, Sha256};
use std::{os::unix::ffi::OsStrExt, path::Path};

/// Immutable instance authorization and namespace binding. The native path is
/// committed rather than copied into durable control state or diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryIdentity {
    repository: [u8; 16],
    instance: [u8; 16],
    integrity_fingerprint: [u8; 32],
    prefix: [u8; 32],
    aws_s3: bool,
}
impl RepositoryIdentity {
    pub fn local(
        repository: [u8; 16],
        instance: [u8; 16],
        integrity_fingerprint: [u8; 32],
        prefix: &Path,
    ) -> Result<Self, RepositoryFailure> {
        if repository == [0; 16] || instance == [0; 16] || integrity_fingerprint == [0; 32] {
            return Err(RepositoryFailure::InvalidInput);
        }
        let canonical = prefix
            .canonicalize()
            .map_err(|_| RepositoryFailure::StorageUnavailable)?;
        let bytes = canonical.as_os_str().as_bytes();
        if bytes.len() > 4096 {
            return Err(RepositoryFailure::LimitExceeded);
        }
        Ok(Self {
            repository,
            instance,
            integrity_fingerprint,
            prefix: Sha256::digest(bytes).into(),
            aws_s3: false,
        })
    }
    pub fn aws_s3(
        repository: [u8; 16],
        instance: [u8; 16],
        integrity_fingerprint: [u8; 32],
        target: &crate::AwsS3Target,
    ) -> Result<Self, RepositoryFailure> {
        if repository == [0; 16] || instance == [0; 16] || integrity_fingerprint == [0; 32] {
            return Err(RepositoryFailure::InvalidInput);
        }
        Ok(Self {
            repository,
            instance,
            integrity_fingerprint,
            prefix: target.commitment(),
            aws_s3: true,
        })
    }
    pub const fn provider_kind(&self) -> &'static str {
        if self.aws_s3 {
            "awsS3"
        } else {
            "localFilesystem"
        }
    }
    pub const fn repository_id(&self) -> [u8; 16] {
        self.repository
    }
    pub const fn instance_id(&self) -> [u8; 16] {
        self.instance
    }
    pub const fn integrity_fingerprint(&self) -> [u8; 32] {
        self.integrity_fingerprint
    }
    pub const fn prefix_commitment(&self) -> [u8; 32] {
        self.prefix
    }
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(108);
        bytes.extend_from_slice(if self.aws_s3 {
            b"POSS3I01"
        } else {
            b"POSREP01"
        });
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&self.repository);
        bytes.extend_from_slice(&self.instance);
        bytes.extend_from_slice(&self.integrity_fingerprint);
        bytes.extend_from_slice(&self.prefix);
        bytes
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, RepositoryFailure> {
        if bytes.len() != 108
            || !matches!(
                bytes.get(..12),
                Some(b"POSREP01\0\0\0\x01" | b"POSS3I01\0\0\0\x01")
            )
        {
            return Err(RepositoryFailure::CorruptState);
        }
        fn field<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N], RepositoryFailure> {
            bytes
                .get(start..start + N)
                .and_then(|slice| slice.try_into().ok())
                .ok_or(RepositoryFailure::CorruptState)
        }
        let result = Self {
            repository: field(bytes, 12)?,
            instance: field(bytes, 28)?,
            integrity_fingerprint: field(bytes, 44)?,
            prefix: field(bytes, 76)?,
            aws_s3: bytes.get(..8) == Some(b"POSS3I01"),
        };
        if result.repository == [0; 16]
            || result.instance == [0; 16]
            || result.integrity_fingerprint == [0; 32]
        {
            return Err(RepositoryFailure::CorruptState);
        }
        Ok(result)
    }
}
