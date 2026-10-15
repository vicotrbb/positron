use super::{GoogleCloudStorageRepository, protocol};
use crate::*;
impl GoogleCloudStorageRepository {
    pub async fn storage_policy(&self) -> Result<RepositoryPolicy, RepositoryFailure> {
        let _guard = self.enter()?;
        self.read_identity().await?;
        Ok(protocol::policy(&self.bucket().await?))
    }
}
