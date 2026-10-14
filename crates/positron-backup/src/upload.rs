use crate::{MAX_OBJECT_BYTES, MAX_RANGE_BYTES, ObjectId, PutOutcome, RepositoryFailure};
use sha2::{Digest, Sha256};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadId(pub(crate) [u8; 32]);
impl UploadId {
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
    pub(crate) fn name(self) -> String {
        let mut name = String::from("u-");
        for byte in self.0 {
            name.push_str(&format!("{byte:02x}"));
        }
        name
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadPlan {
    pub(crate) object: ObjectId,
    pub(crate) size: u64,
}
impl UploadPlan {
    pub fn new(object: ObjectId, size: u64) -> Result<Self, RepositoryFailure> {
        if size == 0 {
            return Err(RepositoryFailure::InvalidInput);
        }
        if size > MAX_OBJECT_BYTES {
            return Err(RepositoryFailure::LimitExceeded);
        }
        Ok(Self { object, size })
    }
    pub fn id(self) -> UploadId {
        let mut hash = Sha256::new();
        hash.update(b"positron-upload-v1");
        hash.update(self.object.checksum());
        hash.update(self.size.to_be_bytes());
        UploadId(hash.finalize().into())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadState {
    pub(crate) plan: UploadPlan,
    pub(crate) written: u64,
    pub(crate) checksum: [u8; 32],
}
impl UploadState {
    pub fn id(self) -> UploadId {
        self.plan.id()
    }
    pub const fn object(self) -> ObjectId {
        self.plan.object
    }
    pub const fn total_size(self) -> u64 {
        self.plan.size
    }
    pub const fn uploaded_bytes(self) -> u64 {
        self.written
    }
    pub const fn complete(self) -> bool {
        self.written == self.plan.size
    }
}
#[derive(Clone, Eq, PartialEq)]
pub struct UploadPart {
    pub(crate) state: UploadState,
    pub(crate) bytes: Vec<u8>,
}
impl std::fmt::Debug for UploadPart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UploadPart")
            .field("state", &self.state)
            .field("size", &self.bytes.len())
            .finish()
    }
}
impl UploadPart {
    pub fn new(state: UploadState, bytes: Vec<u8>) -> Result<Self, RepositoryFailure> {
        if bytes.is_empty() {
            return Err(RepositoryFailure::InvalidInput);
        }
        if bytes.len() as u64 > MAX_RANGE_BYTES {
            return Err(RepositoryFailure::LimitExceeded);
        }
        if state
            .written
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > state.plan.size)
        {
            return Err(RepositoryFailure::InvalidInput);
        }
        Ok(Self { state, bytes })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadOutcome {
    Pending(UploadState),
    Complete(PutOutcome),
}
