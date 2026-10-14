//! Backup-only Repository boundary and native local filesystem adapter.
mod doctor;
mod identity;
mod listing;
mod local;
mod object;
mod registry;
mod upload;

pub use doctor::{DoctorPlan, DoctorReport, doctor};
pub use identity::RepositoryIdentity;
pub use listing::{ListCursor, ListEntry, ListKind, ListPage, ListRequest};
pub use local::LocalRepository;
#[cfg(feature = "test-support")]
pub use local::{LocalFault, LocalFaultEffect, LocalFaultPoint};
pub use object::{
    ChecksummedBytes, DeleteOutcome, ImmutableObject, MAX_OBJECT_BYTES, MAX_RANGE_BYTES, ObjectId,
    ObjectMetadata, ObjectRange, PutOutcome,
};
pub use registry::{
    CasOutcome, HeadSlot, MAX_REGISTRY_HEAD_BYTES, ObjectVersion, RegistryHead, RegistryHeadChange,
};
pub use upload::{UploadId, UploadOutcome, UploadPart, UploadPlan, UploadState};

/// Safe closed failures. Provider errors and native credential values never
/// become diagnostic strings or control-flow inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryFailure {
    InvalidInput,
    IdentityMismatch,
    ForeignPrefix,
    PermissionDenied,
    NotFound,
    AlreadyExists,
    PreconditionFailed,
    Busy,
    ChecksumMismatch,
    CorruptState,
    StorageUnavailable,
    OutcomeUnknown,
    LimitExceeded,
    Interrupted,
    Throttled { retry_after_millis: u32 },
}
impl std::fmt::Display for RepositoryFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "repository failure: {self:?}")
    }
}
impl std::error::Error for RepositoryFailure {}

#[async_trait::async_trait]
pub trait Repository: Send + Sync {
    async fn list(&self, request: ListRequest) -> Result<ListPage, RepositoryFailure>;
    async fn begin_upload(&self, plan: UploadPlan) -> Result<UploadState, RepositoryFailure>;
    async fn inspect_upload(&self, id: UploadId) -> Result<Option<UploadState>, RepositoryFailure>;
    async fn resume_upload(&self, part: UploadPart) -> Result<UploadOutcome, RepositoryFailure>;
    async fn abort_upload(&self, id: UploadId) -> Result<DeleteOutcome, RepositoryFailure>;
    async fn identify(&self) -> Result<RepositoryIdentity, RepositoryFailure>;
    async fn head(&self, object: ObjectId) -> Result<ObjectMetadata, RepositoryFailure>;
    async fn read_range(&self, range: ObjectRange) -> Result<ChecksummedBytes, RepositoryFailure>;
    async fn put_if_absent(&self, object: ImmutableObject)
    -> Result<PutOutcome, RepositoryFailure>;
    async fn delete(&self, object: ObjectId) -> Result<DeleteOutcome, RepositoryFailure>;
    async fn registry_head_at(
        &self,
        slot: HeadSlot,
    ) -> Result<Option<RegistryHead>, RepositoryFailure>;
    async fn delete_head_if_version(
        &self,
        slot: HeadSlot,
        expected: ObjectVersion,
    ) -> Result<DeleteOutcome, RepositoryFailure>;
    async fn compare_and_swap_head_at(
        &self,
        slot: HeadSlot,
        change: RegistryHeadChange,
    ) -> Result<CasOutcome, RepositoryFailure>;
}

#[cfg(all(fuzzing, feature = "test-support"))]
mod fuzzing;
#[cfg(all(fuzzing, feature = "test-support"))]
pub use fuzzing::fuzz_repository_stateful;
