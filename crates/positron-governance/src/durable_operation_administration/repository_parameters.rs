//! Exact bounded native Repository parameters, atomically accepted by Administration.
use super::DurableOperationFailure;
use sha2::{Digest, Sha256};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryAction {
    Initialize,
    Verify,
    Doctor,
}
impl RepositoryAction {
    pub(super) const fn code(self) -> u8 {
        match self {
            Self::Initialize => 1,
            Self::Verify => 2,
            Self::Doctor => 3,
        }
    }
    fn from_code(code: u8) -> Result<Self, DurableOperationFailure> {
        match code {
            1 => Ok(Self::Initialize),
            2 => Ok(Self::Verify),
            3 => Ok(Self::Doctor),
            _ => Err(DurableOperationFailure::PersistenceUnavailable),
        }
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RepositoryOperationParameters {
    provider: RepositoryProviderKind,
    action: RepositoryAction,
    locator: [u8; 2048],
    locator_len: u16,
    repository: [u8; 16],
    fingerprint: [u8; 32],
    prefix: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryProviderKind {
    LocalFilesystem,
    AwsS3,
}
impl RepositoryProviderKind {
    fn code(self) -> u8 {
        match self {
            Self::LocalFilesystem => 1,
            Self::AwsS3 => 2,
        }
    }
}
impl std::fmt::Debug for RepositoryOperationParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepositoryOperationParameters")
            .field("action", &self.action)
            .field("repository", &self.repository)
            .finish_non_exhaustive()
    }
}
impl RepositoryOperationParameters {
    pub fn aws_s3(
        action: RepositoryAction,
        locator: &str,
        repository: [u8; 16],
        fingerprint: [u8; 32],
        prefix: [u8; 32],
    ) -> Result<Self, DurableOperationFailure> {
        let mut fields = locator.split('\0');
        for _ in 0..5 {
            if fields.next().is_none_or(str::is_empty) {
                return Err(DurableOperationFailure::InvalidInput);
            }
        }
        if fields.next().is_some() {
            return Err(DurableOperationFailure::InvalidInput);
        }
        Self::bounded(
            RepositoryProviderKind::AwsS3,
            action,
            locator,
            repository,
            fingerprint,
            prefix,
        )
    }
    pub const fn provider_kind(self) -> RepositoryProviderKind {
        self.provider
    }
    pub fn local(
        action: RepositoryAction,
        locator: &str,
        repository: [u8; 16],
        fingerprint: [u8; 32],
        prefix: [u8; 32],
    ) -> Result<Self, DurableOperationFailure> {
        if locator.len() > 2048
            || !locator.starts_with('/')
            || locator.contains('\0')
            || locator.split('/').any(|part| matches!(part, "." | ".."))
        {
            return Err(DurableOperationFailure::InvalidInput);
        }
        Self::bounded(
            RepositoryProviderKind::LocalFilesystem,
            action,
            locator,
            repository,
            fingerprint,
            prefix,
        )
    }
    fn bounded(
        provider: RepositoryProviderKind,
        action: RepositoryAction,
        locator: &str,
        repository: [u8; 16],
        fingerprint: [u8; 32],
        prefix: [u8; 32],
    ) -> Result<Self, DurableOperationFailure> {
        if locator.is_empty()
            || locator.len() > 2048
            || repository == [0; 16]
            || fingerprint == [0; 32]
            || prefix == [0; 32]
        {
            return Err(DurableOperationFailure::InvalidInput);
        }
        let mut bytes = [0; 2048];
        bytes
            .get_mut(..locator.len())
            .ok_or(DurableOperationFailure::InvalidInput)?
            .copy_from_slice(locator.as_bytes());
        Ok(Self {
            provider,
            action,
            locator: bytes,
            locator_len: u16::try_from(locator.len())
                .map_err(|_| DurableOperationFailure::InvalidInput)?,
            repository,
            fingerprint,
            prefix,
        })
    }
    pub const fn action(self) -> RepositoryAction {
        self.action
    }
    pub fn locator(&self) -> Result<&str, DurableOperationFailure> {
        std::str::from_utf8(
            self.locator
                .get(..usize::from(self.locator_len))
                .ok_or(DurableOperationFailure::PersistenceUnavailable)?,
        )
        .map_err(|_| DurableOperationFailure::PersistenceUnavailable)
    }
    pub const fn repository_id(self) -> [u8; 16] {
        self.repository
    }
    pub const fn integrity_fingerprint(self) -> [u8; 32] {
        self.fingerprint
    }
    pub const fn prefix_commitment(self) -> [u8; 32] {
        self.prefix
    }
    pub fn intent_digest(self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(2132);
        bytes.extend_from_slice(b"positron.repository.operation.v1\0");
        self.encode(&mut bytes);
        Sha256::digest(bytes).into()
    }
    pub(super) fn encode(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&[self.provider.code(), self.action.code()]);
        bytes.extend_from_slice(&self.repository);
        bytes.extend_from_slice(&self.fingerprint);
        bytes.extend_from_slice(&self.prefix);
        bytes.extend_from_slice(&self.locator_len.to_be_bytes());
        if let Some(locator) = self.locator.get(..usize::from(self.locator_len)) {
            bytes.extend_from_slice(locator);
        }
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, DurableOperationFailure> {
        let mut offset = 0;
        let provider = match super::codec::take_byte(bytes, &mut offset)? {
            1 => RepositoryProviderKind::LocalFilesystem,
            2 => RepositoryProviderKind::AwsS3,
            _ => return Err(DurableOperationFailure::PersistenceUnavailable),
        };
        let action = RepositoryAction::from_code(super::codec::take_byte(bytes, &mut offset)?)?;
        let repository = super::codec::take_array(bytes, &mut offset)?;
        let fingerprint = super::codec::take_array(bytes, &mut offset)?;
        let prefix = super::codec::take_array(bytes, &mut offset)?;
        let length = usize::from(u16::from_be_bytes(super::codec::take_array(
            bytes,
            &mut offset,
        )?));
        let end = offset
            .checked_add(length)
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        if end != bytes.len() {
            return Err(DurableOperationFailure::PersistenceUnavailable);
        }
        let locator = std::str::from_utf8(
            bytes
                .get(offset..end)
                .ok_or(DurableOperationFailure::PersistenceUnavailable)?,
        )
        .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
        match provider {
            RepositoryProviderKind::LocalFilesystem => {
                Self::local(action, locator, repository, fingerprint, prefix)
            },
            RepositoryProviderKind::AwsS3 => {
                Self::aws_s3(action, locator, repository, fingerprint, prefix)
            },
        }
        .map_err(|_| DurableOperationFailure::PersistenceUnavailable)
    }
}
