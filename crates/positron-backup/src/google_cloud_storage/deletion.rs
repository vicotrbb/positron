use super::{GoogleCloudStorageRepository, protocol};
use crate::*;
use http::{HeaderMap, Method};
use sha2::{Digest, Sha256};
pub(super) enum Proof {
    Object(ObjectId),
    Head,
    Upload(UploadId),
}
impl GoogleCloudStorageRepository {
    async fn generations(&self, key: &str) -> Result<Vec<u64>, RepositoryFailure> {
        let mut generations = Vec::new();
        let mut token = None;
        for _ in 0..4 {
            let page = self
                .inventory(key, token.as_deref(), 64, true, false)
                .await?;
            for value in page.items {
                if protocol::string(&value, "name")? == key {
                    let generation = protocol::number(&value, "generation")?;
                    if generation == 0 || generations.contains(&generation) {
                        return Err(RepositoryFailure::CorruptState);
                    }
                    generations.push(generation);
                }
            }
            token = page.next;
            if token.is_none() {
                return Ok(generations);
            }
        }
        Err(RepositoryFailure::LimitExceeded)
    }
    pub(super) async fn purge_key(
        &self,
        key: &str,
        proof: Proof,
        expected: Option<u64>,
    ) -> Result<DeleteOutcome, RepositoryFailure> {
        self.bucket().await?;
        // Snapshot owned history before the conditional live-head fence. A
        // successor published after that fence must never join this deletion set.
        let mut generations = self.generations(key).await?;
        let mut existed = false;
        if let Some(expected) = expected {
            let (bytes, metadata) = self
                .read_key(key, None, MAX_OBJECT_BYTES as usize + 65536)
                .await?;
            if metadata.generation != expected {
                return Err(RepositoryFailure::PreconditionFailed);
            }
            self.validate_owned(bytes, &proof)?;
            // Fence only this live version before inventorying historical bytes.
            // Generation identifiers are opaque, not an ordering primitive.
            self.checked(
                Method::DELETE,
                format!(
                    "{}?ifGenerationMatch={expected}&ifMetagenerationMatch={}",
                    self.object_url(key),
                    metadata.metageneration
                ),
                HeaderMap::new(),
                Vec::new(),
                131072,
            )
            .await?;
            existed = true;
        }
        if matches!(proof, Proof::Head) {
            match self.metadata(key, None).await {
                Err(RepositoryFailure::NotFound) => {},
                Ok(_) => return Err(RepositoryFailure::PreconditionFailed),
                Err(e) => return Err(e),
            }
        }
        if let Some(expected) = expected
            && let Some(position) = generations.iter().position(|g| *g == expected)
        {
            generations.swap(0, position);
        }
        for generation in &generations {
            let (bytes, metadata) = match self
                .read_key(key, Some(*generation), MAX_OBJECT_BYTES as usize + 65536)
                .await
            {
                Ok(v) => v,
                Err(RepositoryFailure::NotFound) => continue,
                Err(e) => return Err(e),
            };
            self.validate_owned(bytes, &proof)?;
            let url = format!(
                "{}?generation={generation}&ifGenerationMatch={generation}&ifMetagenerationMatch={}",
                self.object_url(key),
                metadata.metageneration
            );
            match self
                .checked(Method::DELETE, url, HeaderMap::new(), Vec::new(), 131072)
                .await
            {
                Ok(_) => existed = true,
                Err(RepositoryFailure::NotFound) => {},
                Err(e) => return Err(e),
            }
            self.faults
                .at(super::GoogleCloudStorageFaultPoint::AfterVersionDeletion)?;
            match self.metadata(key, Some(*generation)).await {
                Err(RepositoryFailure::NotFound) => {},
                Ok(_) => return Err(RepositoryFailure::OutcomeUnknown),
                Err(e) => return Err(e),
            }
        }
        match self.metadata(key, None).await {
            Err(RepositoryFailure::NotFound) => {},
            Ok(_) => return Err(RepositoryFailure::PreconditionFailed),
            Err(e) => return Err(e),
        }
        if !self.generations(key).await?.is_empty() {
            return Err(RepositoryFailure::OutcomeUnknown);
        }
        let retained = self.inventory(key, None, 1, false, true).await?;
        if retained
            .items
            .iter()
            .any(|v| v.get("name").and_then(|n| n.as_str()) == Some(key))
            || retained.next.is_some()
        {
            return Err(RepositoryFailure::OutcomeUnknown);
        }
        self.faults
            .at(super::GoogleCloudStorageFaultPoint::AfterDeletion)?;
        Ok(if existed {
            DeleteOutcome::Deleted
        } else {
            DeleteOutcome::AlreadyAbsent
        })
    }
    fn validate_owned(&self, bytes: Vec<u8>, proof: &Proof) -> Result<(), RepositoryFailure> {
        match proof {
            Proof::Object(id) => {
                if <[u8; 32]>::from(Sha256::digest(&bytes)) != id.checksum() {
                    return Err(RepositoryFailure::ChecksumMismatch);
                }
            },
            Proof::Head => {
                RegistryHead::decode_frame(&bytes)?;
            },
            Proof::Upload(id) => {
                self.decode_record(bytes, *id)?;
            },
        }
        Ok(())
    }
    pub async fn delete(&self, id: ObjectId) -> Result<DeleteOutcome, RepositoryFailure> {
        self.upload_authenticator()?;
        let _guard = self.enter()?;
        self.read_identity().await?;
        match self
            .read_key(&self.key(&id.name()), None, MAX_OBJECT_BYTES as usize)
            .await
        {
            Ok((bytes, _)) => self.check_purge_fence(id, &bytes)?,
            Err(RepositoryFailure::NotFound) => {},
            Err(e) => return Err(e),
        }
        self.purge_key(&self.key(&id.name()), Proof::Object(id), None)
            .await
    }
    pub(super) async fn cleanup_upload(
        &self,
        id: UploadId,
    ) -> Result<DeleteOutcome, RepositoryFailure> {
        let key = self.key(&id.name());
        let mut records = Vec::new();
        for generation in self.generations(&key).await? {
            let (bytes, _) = self
                .read_key(&key, Some(generation), MAX_OBJECT_BYTES as usize + 65536)
                .await?;
            let mut record = self.decode_record(bytes, id)?;
            record.bytes = Vec::new();
            records.push(record);
        }
        for record in &records {
            if record.requested && record.session.is_none() {
                if records
                    .iter()
                    .any(|r| r.selector == record.selector && r.session.is_some())
                {
                    continue;
                }
                return Err(RepositoryFailure::OutcomeUnknown);
            }
            self.cancel_session(record).await?;
            self.purge_key(
                &self.staging_key(record),
                Proof::Object(record.plan.object),
                None,
            )
            .await?;
        }
        self.purge_key(&key, Proof::Upload(id), None).await
    }
}

impl GoogleCloudStorageRepository {
    /// Occupy the old name before removing secret generations, so a delayed
    /// generation-zero creator can never publish after purge completion.
    pub async fn delete_tenant_key(
        &self,
        id: ObjectId,
        fence: &TenantKeyPurgeFence,
    ) -> Result<DeleteOutcome, RepositoryFailure> {
        self.upload_authenticator()?;
        let _guard = self.enter()?;
        self.read_identity().await?;
        TenantKeyPurgeFence::verify(fence.bytes(), &self.identity, id)?;
        let key = self.key(&id.name());
        let current = match self.read_key(&key, None, MAX_OBJECT_BYTES as usize).await {
            Ok(value) => Some(value),
            Err(RepositoryFailure::NotFound) => None,
            Err(e) => return Err(e),
        };
        let installed = current
            .as_ref()
            .is_some_and(|(bytes, _)| bytes == fence.bytes());
        if !installed {
            if let Some((bytes, _)) = &current {
                self.check_purge_fence(id, bytes)?;
                self.validate_owned(bytes.clone(), &Proof::Object(id))?;
            }
            let expected = current.as_ref().map_or(0, |(_, meta)| meta.generation);
            match self.write_key(&key, fence.bytes().to_vec(), expected).await {
                Ok(_)
                | Err(RepositoryFailure::OutcomeUnknown | RepositoryFailure::PreconditionFailed) =>
                    {},
                Err(e) => return Err(e),
            }
        }
        let (bytes, retained) = self
            .read_key(&key, None, TenantKeyPurgeFence::MAX_BYTES)
            .await?;
        if bytes != fence.bytes() {
            return Err(RepositoryFailure::OutcomeUnknown);
        }
        TenantKeyPurgeFence::verify(&bytes, &self.identity, id)?;
        for generation in self.generations(&key).await? {
            if generation == retained.generation {
                continue;
            }
            let (bytes, metadata) = match self
                .read_key(&key, Some(generation), MAX_OBJECT_BYTES as usize)
                .await
            {
                Ok(value) => value,
                Err(RepositoryFailure::NotFound) => continue,
                Err(e) => return Err(e),
            };
            if TenantKeyPurgeFence::is_frame(&bytes) {
                TenantKeyPurgeFence::verify(&bytes, &self.identity, id)?;
            } else {
                self.validate_owned(bytes, &Proof::Object(id))?;
            }
            let url = format!(
                "{}?generation={generation}&ifGenerationMatch={generation}&ifMetagenerationMatch={}",
                self.object_url(&key),
                metadata.metageneration
            );
            match self
                .checked(Method::DELETE, url, HeaderMap::new(), Vec::new(), 131072)
                .await
            {
                Ok(_) | Err(RepositoryFailure::NotFound) => {},
                Err(e) => return Err(e),
            }
            self.faults
                .at(super::GoogleCloudStorageFaultPoint::AfterVersionDeletion)?;
        }
        if self.generations(&key).await? != vec![retained.generation] {
            return Err(RepositoryFailure::OutcomeUnknown);
        }
        let retained_history = self.inventory(&key, None, 1, false, true).await?;
        if retained_history.next.is_some()
            || retained_history
                .items
                .iter()
                .any(|v| v.get("name").and_then(|n| n.as_str()) == Some(key.as_str()))
        {
            return Err(RepositoryFailure::OutcomeUnknown);
        }
        let (bytes, final_metadata) = self
            .read_key(&key, None, TenantKeyPurgeFence::MAX_BYTES)
            .await?;
        if bytes != fence.bytes() || final_metadata.generation != retained.generation {
            return Err(RepositoryFailure::OutcomeUnknown);
        }
        self.faults
            .at(super::GoogleCloudStorageFaultPoint::AfterDeletion)?;
        Ok(if installed {
            DeleteOutcome::AlreadyAbsent
        } else {
            DeleteOutcome::Deleted
        })
    }
}
