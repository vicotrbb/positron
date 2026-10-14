use crate::RepositoryFailure;
use sha2::{Digest, Sha256};
pub const MAX_REGISTRY_HEAD_BYTES: usize = 65536;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectVersion(pub(crate) [u8; 32]);
impl ObjectVersion {
    pub const fn from_checksum(checksum: [u8; 32]) -> Self {
        Self(checksum)
    }
    pub const fn checksum(self) -> [u8; 32] {
        self.0
    }
}
#[derive(Clone, Eq, PartialEq)]
pub struct RegistryHead {
    pub(crate) version: ObjectVersion,
    pub(crate) bytes: Vec<u8>,
}
impl std::fmt::Debug for RegistryHead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryHead")
            .field("version", &self.version)
            .field("size", &self.bytes.len())
            .finish()
    }
}
impl RegistryHead {
    pub const fn version(&self) -> ObjectVersion {
        self.version
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryHeadChange {
    pub(crate) expected: Option<ObjectVersion>,
    pub(crate) successor: RegistryHead,
}
impl RegistryHeadChange {
    pub fn new(expected: Option<ObjectVersion>, bytes: Vec<u8>) -> Result<Self, RepositoryFailure> {
        if bytes.is_empty() {
            return Err(RepositoryFailure::InvalidInput);
        }
        if bytes.len() > MAX_REGISTRY_HEAD_BYTES {
            return Err(RepositoryFailure::LimitExceeded);
        }
        Ok(Self {
            expected,
            successor: RegistryHead {
                version: ObjectVersion(Sha256::digest(&bytes).into()),
                bytes,
            },
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CasOutcome {
    Published(ObjectVersion),
    Conflict(Option<ObjectVersion>),
}

/// Provider object selector for a mutable head. Its bytes carry no registry
/// semantics; diagnostic heads use a fresh independently owned selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeadSlot([u8; 32]);
impl HeadSlot {
    pub const fn from_checksum(checksum: [u8; 32]) -> Self {
        Self(checksum)
    }
    pub fn registry() -> Self {
        Self(Sha256::digest(b"positron registry head v1").into())
    }
    pub(crate) fn name(self) -> String {
        let mut name = String::from("h-");
        for byte in self.0 {
            name.push_str(&format!("{byte:02x}"));
        }
        name
    }
}
