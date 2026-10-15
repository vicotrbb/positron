use super::{AwsS3Repository, failure};
use crate::{ObjectId, RepositoryFailure, UploadId};
mod proof;
pub(super) enum Proof {
    Object(ObjectId),
    Head,
    Upload(UploadId),
}
use tracing::instrument::WithSubscriber;

const MAX_VERSIONS: usize = 256;
struct Version {
    id: String,
    marker: bool,
}
pub(super) fn owned_version_id(
    key: Option<&str>,
    id: Option<&str>,
    expected: &str,
) -> Result<Option<String>, RepositoryFailure> {
    let key = key.ok_or(RepositoryFailure::CorruptState)?;
    if key != expected {
        return Ok(None);
    }
    let id = id
        .filter(|id| !id.is_empty() && id.len() <= 4096 && !id.chars().any(char::is_control))
        .ok_or(RepositoryFailure::CorruptState)?;
    Ok(Some(id.to_owned()))
}
impl AwsS3Repository {
    async fn versions(&self, key: &str) -> Result<Vec<Version>, RepositoryFailure> {
        let mut versions = Vec::new();
        let mut key_marker: Option<String> = None;
        let mut version_marker: Option<String> = None;
        for _ in 0..4 {
            let response = self
                .client
                .list_object_versions()
                .bucket(self.target.bucket())
                .prefix(key)
                .max_keys(64)
                .expected_bucket_owner(self.target.expected_owner())
                .set_key_marker(key_marker.clone())
                .set_version_id_marker(version_marker.clone())
                .send()
                .with_subscriber(tracing::subscriber::NoSubscriber::default())
                .await
                .map_err(|error| failure::sdk(error, false))?;
            for version in response.versions() {
                if let Some(id) = owned_version_id(version.key(), version.version_id(), key)? {
                    versions.push(Version { id, marker: false });
                }
            }
            for marker in response.delete_markers() {
                if let Some(id) = owned_version_id(marker.key(), marker.version_id(), key)? {
                    versions.push(Version { id, marker: true });
                }
            }
            if versions.len() > MAX_VERSIONS {
                return Err(RepositoryFailure::LimitExceeded);
            }
            match response.is_truncated() {
                Some(false) => return Ok(versions),
                Some(true) => {},
                None => return Err(RepositoryFailure::CorruptState),
            }
            let next_key = response
                .next_key_marker()
                .filter(|value| !value.is_empty() && value.len() <= 1024)
                .ok_or(RepositoryFailure::CorruptState)?
                .to_owned();
            let next_version = response
                .next_version_id_marker()
                .filter(|value| !value.is_empty() && value.len() <= 4096)
                .ok_or(RepositoryFailure::CorruptState)?
                .to_owned();
            if key_marker.as_deref() == Some(&next_key)
                && version_marker.as_deref() == Some(&next_version)
            {
                return Err(RepositoryFailure::CorruptState);
            }
            key_marker = Some(next_key);
            version_marker = Some(next_version);
        }
        Err(RepositoryFailure::LimitExceeded)
    }
}

impl AwsS3Repository {
    pub(super) async fn purge_key(
        &self,
        key: &str,
        etag: Option<&str>,
        proof: Proof,
    ) -> Result<bool, RepositoryFailure> {
        let versions = self.versions(key).await?;
        for version in &versions {
            if !version.marker {
                self.verify_version(key, &version.id, &proof).await?;
            }
        }
        self.faults.at(super::AwsS3FaultPoint::BeforeDeletion)?;
        let mut marker = None;
        if let Some(etag) = etag {
            let response = self
                .client
                .delete_object()
                .bucket(self.target.bucket())
                .key(key)
                .if_match(etag)
                .expected_bucket_owner(self.target.expected_owner())
                .send()
                .with_subscriber(tracing::subscriber::NoSubscriber::default())
                .await
                .map_err(|error| failure::sdk(error, true))?;
            marker = response
                .version_id()
                .filter(|id| {
                    !id.is_empty() && id.len() <= 4096 && !id.chars().any(char::is_control)
                })
                .map(str::to_owned);
            if response.version_id().is_some() && marker.is_none() {
                return Err(RepositoryFailure::OutcomeUnknown);
            }
        }
        for version in &versions {
            self.delete_version(key, &version.id).await?;
        }
        if let Some(marker) = marker {
            self.delete_version(key, &marker).await?;
        }
        if !self.versions(key).await?.is_empty() {
            return Err(RepositoryFailure::OutcomeUnknown);
        }
        match self
            .client
            .head_object()
            .bucket(self.target.bucket())
            .key(key)
            .expected_bucket_owner(self.target.expected_owner())
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|error| failure::sdk(error, false))
        {
            Err(RepositoryFailure::NotFound) => {
                self.faults.at(super::AwsS3FaultPoint::AfterDeletion)?;
                Ok(etag.is_some() || !versions.is_empty())
            },
            Ok(_) => Err(RepositoryFailure::PreconditionFailed),
            Err(error) => Err(error),
        }
    }
    async fn delete_version(&self, key: &str, id: &str) -> Result<(), RepositoryFailure> {
        self.client
            .delete_object()
            .bucket(self.target.bucket())
            .key(key)
            .version_id(id)
            .expected_bucket_owner(self.target.expected_owner())
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|error| failure::sdk(error, true))?;
        // Direct native version reads reconcile deletion independently of the
        // advisory Repository listing; external retention is never inferred.
        match self
            .client
            .head_object()
            .bucket(self.target.bucket())
            .key(key)
            .version_id(id)
            .expected_bucket_owner(self.target.expected_owner())
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|error| failure::sdk(error, false))
        {
            Err(RepositoryFailure::NotFound) => Ok(()),
            Ok(_) => Err(RepositoryFailure::OutcomeUnknown),
            Err(error) => Err(error),
        }
    }
}

impl AwsS3Repository {
    pub async fn delete(&self, id: ObjectId) -> Result<crate::DeleteOutcome, RepositoryFailure> {
        let _operation = self.enter()?;
        self.read_identity().await?;
        match self.read_object(id).await {
            Ok(_) | Err(RepositoryFailure::NotFound) => {},
            Err(error) => return Err(error),
        }
        let key = self.object_key(id);
        let etag = self.current_etag(&key).await?;
        let deleted = self
            .purge_key(&key, etag.as_deref(), Proof::Object(id))
            .await?;
        Ok(if deleted {
            crate::DeleteOutcome::Deleted
        } else {
            crate::DeleteOutcome::AlreadyAbsent
        })
    }
    pub async fn delete_head_if_version(
        &self,
        slot: crate::HeadSlot,
        expected: crate::ObjectVersion,
    ) -> Result<crate::DeleteOutcome, RepositoryFailure> {
        let _operation = self.enter()?;
        self.read_identity().await?;
        let current = self.read_head(slot).await?;
        if current
            .as_ref()
            .is_some_and(|(head, _)| head.version() != expected)
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        let key = self.head_key(slot);
        let deleted = self
            .purge_key(
                &key,
                current.as_ref().map(|(_, etag)| etag.as_str()),
                Proof::Head,
            )
            .await?;
        Ok(if deleted {
            crate::DeleteOutcome::Deleted
        } else {
            crate::DeleteOutcome::AlreadyAbsent
        })
    }
    pub(super) async fn current_etag(
        &self,
        key: &str,
    ) -> Result<Option<String>, RepositoryFailure> {
        match self
            .client
            .head_object()
            .bucket(self.target.bucket())
            .key(key)
            .expected_bucket_owner(self.target.expected_owner())
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|error| failure::sdk(error, false))
        {
            Ok(response) => response
                .e_tag()
                .filter(|etag| !etag.is_empty() && etag.len() <= 1024)
                .map(|etag| Some(etag.to_owned()))
                .ok_or(RepositoryFailure::CorruptState),
            Err(RepositoryFailure::NotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

impl AwsS3Repository {
    pub(super) async fn retained_uploads(
        &self,
        id: UploadId,
    ) -> Result<Vec<super::upload::OwnedUpload>, RepositoryFailure> {
        let key = self.upload_key(id);
        let versions = self.versions(&key).await?;
        let mut owned = Vec::new();
        for version in versions.iter().filter(|version| !version.marker) {
            let response = match self
                .client
                .get_object()
                .bucket(self.target.bucket())
                .key(&key)
                .version_id(&version.id)
                .expected_bucket_owner(self.target.expected_owner())
                .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled)
                .send()
                .with_subscriber(tracing::subscriber::NoSubscriber::default())
                .await
                .map_err(|error| failure::sdk(error, false))
            {
                Ok(response) => response,
                Err(RepositoryFailure::NotFound) => continue,
                Err(error) => return Err(error),
            };
            let max = crate::MAX_OBJECT_BYTES + 65536;
            if response
                .content_length()
                .is_some_and(|size| size < 0 || size as u64 > max)
            {
                return Err(RepositoryFailure::LimitExceeded);
            }
            let length = response.content_length();
            let bytes = crate::aws_s3::http::read_bytes(response.body, length, max).await?;
            let record =
                super::upload::Record::inspect_owned(&bytes, self.target.commitment(), id)?;
            if !owned.contains(&record) {
                owned.push(record);
            }
        }
        Ok(owned)
    }
}
