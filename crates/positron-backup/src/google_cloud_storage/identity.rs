use super::{GoogleCloudStorageRepository, protocol};
use crate::{RepositoryFailure, RepositoryIdentity};
use http::{HeaderMap, Method};
impl GoogleCloudStorageRepository {
    pub(super) async fn bucket(&self) -> Result<serde_json::Value, RepositoryFailure> {
        let reply = self
            .checked(
                Method::GET,
                format!(
                    "https://storage.googleapis.com/storage/v1/b/{}",
                    self.target.bucket()
                ),
                HeaderMap::new(),
                Vec::new(),
                131072,
            )
            .await?;
        let bucket = protocol::bucket(&reply.body, &self.target)?;
        if bucket
            .pointer("/hierarchicalNamespace/enabled")
            .is_some_and(|v| v.as_bool() != Some(false))
        {
            return Err(RepositoryFailure::InvalidInput);
        }
        Ok(bucket)
    }
    pub(super) async fn read_identity(&self) -> Result<RepositoryIdentity, RepositoryFailure> {
        self.bucket().await?;
        let (bytes, _) = self.read_key(&self.key("identity"), None, 108).await?;
        let actual = RepositoryIdentity::decode(&bytes)?;
        if actual != self.identity {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        Ok(actual)
    }
    pub async fn attach(&self) -> Result<RepositoryIdentity, RepositoryFailure> {
        let _guard = self.enter()?;
        self.read_identity().await
    }
    pub async fn initialize(&self) -> Result<(), RepositoryFailure> {
        self.upload_authenticator()?;
        let _guard = self.enter()?;
        match self.read_identity().await {
            Ok(_) => return Ok(()),
            Err(RepositoryFailure::NotFound) => {},
            Err(e) => return Err(e),
        }
        for soft in [false, true] {
            let page = self
                .inventory(self.target.prefix(), None, 1, !soft, soft)
                .await?;
            if !page.items.is_empty() {
                return Err(RepositoryFailure::ForeignPrefix);
            }
            if page.next.is_some() {
                return Err(RepositoryFailure::OutcomeUnknown);
            }
        }
        match self
            .write_key(&self.key("identity"), self.identity.encode(), 0)
            .await
        {
            Ok(_) => {},
            Err(RepositoryFailure::PreconditionFailed | RepositoryFailure::OutcomeUnknown) => {},
            Err(e) => return Err(e),
        }
        self.read_identity().await.map(|_| ()).map_err(|e| {
            if e == RepositoryFailure::NotFound {
                RepositoryFailure::OutcomeUnknown
            } else {
                e
            }
        })
    }
}
