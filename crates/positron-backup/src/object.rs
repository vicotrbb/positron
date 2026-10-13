use crate::RepositoryFailure;
use sha2::{Digest, Sha256};

pub const MAX_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_RANGE_BYTES: u64 = 4 * 1024 * 1024;
/// Content identity of an already encrypted/authenticated backup object.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ObjectId([u8; 32]);
impl ObjectId {
    pub const fn from_checksum(checksum: [u8; 32]) -> Self {
        Self(checksum)
    }
    pub const fn checksum(self) -> [u8; 32] {
        self.0
    }
    pub(crate) fn name(self) -> String {
        let mut name = String::from("o-");
        for byte in self.0 {
            name.push_str(&format!("{byte:02x}"));
        }
        name
    }
}
#[derive(Clone, Eq, PartialEq)]
pub struct ImmutableObject {
    id: ObjectId,
    bytes: Vec<u8>,
}
impl std::fmt::Debug for ImmutableObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImmutableObject")
            .field("id", &self.id)
            .field("size", &self.bytes.len())
            .finish()
    }
}
impl ImmutableObject {
    pub fn new(bytes: Vec<u8>) -> Result<Self, RepositoryFailure> {
        if bytes.len() as u64 > MAX_OBJECT_BYTES {
            return Err(RepositoryFailure::LimitExceeded);
        }
        Ok(Self {
            id: ObjectId(Sha256::digest(&bytes).into()),
            bytes,
        })
    }
    pub const fn id(&self) -> ObjectId {
        self.id
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectMetadata {
    pub(crate) size: u64,
    pub(crate) checksum: [u8; 32],
}
impl ObjectMetadata {
    pub const fn size(self) -> u64 {
        self.size
    }
    pub const fn checksum(self) -> [u8; 32] {
        self.checksum
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectRange {
    pub(crate) object: ObjectId,
    pub(crate) offset: u64,
    pub(crate) length: u64,
}
impl ObjectRange {
    pub fn new(object: ObjectId, offset: u64, length: u64) -> Result<Self, RepositoryFailure> {
        if length > MAX_RANGE_BYTES
            || offset
                .checked_add(length)
                .is_none_or(|end| end > MAX_OBJECT_BYTES)
        {
            return Err(RepositoryFailure::LimitExceeded);
        }
        Ok(Self {
            object,
            offset,
            length,
        })
    }
}
#[derive(Clone, Eq, PartialEq)]
pub struct ChecksummedBytes {
    pub(crate) bytes: Vec<u8>,
    pub(crate) checksum: [u8; 32],
}
impl std::fmt::Debug for ChecksummedBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChecksummedBytes")
            .field("size", &self.bytes.len())
            .field("checksum", &self.checksum)
            .finish()
    }
}
impl ChecksummedBytes {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub const fn checksum(&self) -> [u8; 32] {
        self.checksum
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PutOutcome {
    Created,
    AlreadyPresent,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteOutcome {
    Deleted,
    AlreadyAbsent,
}
