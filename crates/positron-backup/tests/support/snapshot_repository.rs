//! Deterministic lost-delete-acknowledgement adapter over the real Repository.
use positron_backup::*;
use std::sync::atomic::{AtomicBool, Ordering};
pub struct LostDeleteAcknowledgement<'a> {
    inner: &'a dyn Repository,
    lose_once: AtomicBool,
}
impl<'a> LostDeleteAcknowledgement<'a> {
    pub fn new(inner: &'a dyn Repository) -> Self {
        Self {
            inner,
            lose_once: AtomicBool::new(true),
        }
    }
}
#[async_trait::async_trait]
impl Repository for LostDeleteAcknowledgement<'_> {
    async fn storage_policy(&self) -> Result<RepositoryPolicy, RepositoryFailure> {
        self.inner.storage_policy().await
    }
    async fn list(&self, request: ListRequest) -> Result<ListPage, RepositoryFailure> {
        self.inner.list(request).await
    }
    async fn begin_upload(&self, plan: UploadPlan) -> Result<UploadState, RepositoryFailure> {
        self.inner.begin_upload(plan).await
    }
    async fn inspect_upload(&self, id: UploadId) -> Result<Option<UploadState>, RepositoryFailure> {
        self.inner.inspect_upload(id).await
    }
    async fn resume_upload(&self, part: UploadPart) -> Result<UploadOutcome, RepositoryFailure> {
        self.inner.resume_upload(part).await
    }
    async fn abort_upload(&self, id: UploadId) -> Result<DeleteOutcome, RepositoryFailure> {
        self.inner.abort_upload(id).await
    }
    async fn identify(&self) -> Result<RepositoryIdentity, RepositoryFailure> {
        self.inner.identify().await
    }
    async fn object_size_hint(&self, object: ObjectId) -> Result<u64, RepositoryFailure> {
        self.inner.object_size_hint(object).await
    }
    async fn head(&self, object: ObjectId) -> Result<ObjectMetadata, RepositoryFailure> {
        self.inner.head(object).await
    }
    async fn read_range(&self, range: ObjectRange) -> Result<ChecksummedBytes, RepositoryFailure> {
        self.inner.read_range(range).await
    }
    async fn put_if_absent(
        &self,
        object: ImmutableObject,
    ) -> Result<PutOutcome, RepositoryFailure> {
        self.inner.put_if_absent(object).await
    }
    async fn delete(&self, object: ObjectId) -> Result<DeleteOutcome, RepositoryFailure> {
        let outcome = self.inner.delete(object).await?;
        if self.lose_once.swap(false, Ordering::AcqRel) {
            Err(RepositoryFailure::OutcomeUnknown)
        } else {
            Ok(outcome)
        }
    }
    async fn registry_head_at(
        &self,
        slot: HeadSlot,
    ) -> Result<Option<RegistryHead>, RepositoryFailure> {
        self.inner.registry_head_at(slot).await
    }
    async fn delete_head_if_version(
        &self,
        slot: HeadSlot,
        expected: ObjectVersion,
    ) -> Result<DeleteOutcome, RepositoryFailure> {
        self.inner.delete_head_if_version(slot, expected).await
    }
    async fn compare_and_swap_head_at(
        &self,
        slot: HeadSlot,
        change: RegistryHeadChange,
    ) -> Result<CasOutcome, RepositoryFailure> {
        self.inner.compare_and_swap_head_at(slot, change).await
    }
}
