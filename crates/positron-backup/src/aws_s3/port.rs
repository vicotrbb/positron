use super::AwsS3Repository;
use crate::*;

#[async_trait::async_trait]
impl Repository for AwsS3Repository {
    async fn storage_policy(&self) -> Result<RepositoryPolicy, RepositoryFailure> {
        Self::storage_policy(self).await
    }
    async fn identify(&self) -> Result<RepositoryIdentity, RepositoryFailure> {
        self.attach().await
    }
    async fn list(&self, request: ListRequest) -> Result<ListPage, RepositoryFailure> {
        Self::list(self, request).await
    }
    async fn begin_upload(&self, plan: UploadPlan) -> Result<UploadState, RepositoryFailure> {
        Self::begin_upload(self, plan).await
    }
    async fn inspect_upload(&self, id: UploadId) -> Result<Option<UploadState>, RepositoryFailure> {
        Self::inspect_upload(self, id).await
    }
    async fn resume_upload(&self, part: UploadPart) -> Result<UploadOutcome, RepositoryFailure> {
        Self::resume_upload(self, part).await
    }
    async fn abort_upload(&self, id: UploadId) -> Result<DeleteOutcome, RepositoryFailure> {
        Self::abort_upload(self, id).await
    }
    async fn head(&self, id: ObjectId) -> Result<ObjectMetadata, RepositoryFailure> {
        Self::head(self, id).await
    }
    async fn read_range(&self, range: ObjectRange) -> Result<ChecksummedBytes, RepositoryFailure> {
        Self::read_range(self, range).await
    }
    async fn put_if_absent(
        &self,
        object: ImmutableObject,
    ) -> Result<PutOutcome, RepositoryFailure> {
        Self::put_if_absent(self, object).await
    }
    async fn delete(&self, id: ObjectId) -> Result<DeleteOutcome, RepositoryFailure> {
        Self::delete(self, id).await
    }
    async fn registry_head_at(
        &self,
        slot: HeadSlot,
    ) -> Result<Option<RegistryHead>, RepositoryFailure> {
        Self::registry_head_at(self, slot).await
    }
    async fn delete_head_if_version(
        &self,
        slot: HeadSlot,
        expected: ObjectVersion,
    ) -> Result<DeleteOutcome, RepositoryFailure> {
        Self::delete_head_if_version(self, slot, expected).await
    }
    async fn compare_and_swap_head_at(
        &self,
        slot: HeadSlot,
        change: RegistryHeadChange,
    ) -> Result<CasOutcome, RepositoryFailure> {
        Self::compare_and_swap_head_at(self, slot, change).await
    }
}
