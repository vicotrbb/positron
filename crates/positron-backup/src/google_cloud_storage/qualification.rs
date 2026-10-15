//! Read-only exact history preservation for separately prepared real fixtures.
use super::{GoogleCloudStorageRepository, protocol};
use crate::RepositoryFailure;
use sha2::{Digest, Sha256};
impl GoogleCloudStorageRepository {
    /// Inspect only native target identity; useful for denied/quota/renewal fixtures.
    pub async fn qualification_bucket_identity(&self) -> Result<(), RepositoryFailure> {
        let _guard = self.enter()?;
        self.bucket().await.map(|_| ())
    }
    /// Create one deliberately malformed owned probe, refuse it through the
    /// public Repository boundary, then delete only the generation just created.
    pub async fn qualification_content_corruption(
        &self,
        probe: [u8; 32],
    ) -> Result<(), RepositoryFailure> {
        let id = crate::ObjectId::from_checksum(probe);
        let body = b"non-secret native corruption fixture";
        let metadata = {
            let _guard = self.enter()?;
            self.read_identity().await?;
            self.write_key(&self.key(&id.name()), body.to_vec(), 0)
                .await?
        };
        if self.head(id).await != Err(RepositoryFailure::ChecksumMismatch)
            || self.delete(id).await != Err(RepositoryFailure::ChecksumMismatch)
        {
            return Err(RepositoryFailure::CorruptState);
        }
        let _guard = self.enter()?;
        let key = self.key(&id.name());
        let (bytes, current) = self
            .read_key(&key, Some(metadata.generation), body.len())
            .await?;
        if bytes != body || current.generation != metadata.generation {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        self.checked(
            http::Method::DELETE,
            format!(
                "{}?generation={}&ifGenerationMatch={}&ifMetagenerationMatch={}",
                self.object_url(&key),
                metadata.generation,
                metadata.generation,
                current.metageneration
            ),
            http::HeaderMap::new(),
            Vec::new(),
            131072,
        )
        .await?;
        for soft in [false, true] {
            let page = self.inventory(&key, None, 1, !soft, soft).await?;
            if !page.items.is_empty() || page.next.is_some() {
                return Err(RepositoryFailure::OutcomeUnknown);
            }
        }
        Ok(())
    }

    /// The fixture has no current/versioned objects and retained soft history,
    /// even though its current bucket soft-delete duration is zero.
    pub async fn qualification_foreign_soft_history_digest(
        &self,
    ) -> Result<[u8; 32], RepositoryFailure> {
        let _guard = self.enter()?;
        let bucket = self.bucket().await?;
        if bucket
            .pointer("/softDeletePolicy/retentionDurationSeconds")
            .and_then(|v| v.as_str())
            != Some("0")
        {
            return Err(RepositoryFailure::InvalidInput);
        }
        let current = self
            .inventory(self.target.prefix(), None, 1, true, false)
            .await?;
        if !current.items.is_empty() || current.next.is_some() {
            return Err(RepositoryFailure::InvalidInput);
        }
        let retained = self
            .inventory(self.target.prefix(), None, 16, false, true)
            .await?;
        if retained.items.is_empty() || retained.next.is_some() {
            return Err(RepositoryFailure::InvalidInput);
        }
        let mut rows = Vec::new();
        for value in retained.items {
            let name = protocol::string(&value, "name")?;
            let generation = protocol::number(&value, "generation")?;
            let soft = protocol::string(&value, "softDeleteTime")?;
            let hard = protocol::string(&value, "hardDeleteTime")?;
            rows.push((
                name.to_owned(),
                generation,
                soft.to_owned(),
                hard.to_owned(),
            ));
        }
        rows.sort_unstable();
        let bytes = serde_json::to_vec(&rows).map_err(|_| RepositoryFailure::CorruptState)?;
        Ok(Sha256::digest(&bytes).into())
    }
}
