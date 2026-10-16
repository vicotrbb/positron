use super::*;
use crate::aws_s3::objects::validate_object;
use crate::{DeleteOutcome, TenantKeyPurgeFence};
impl AwsS3Repository {
    pub(super) async fn fence_current(
        &self,
        object: ObjectId,
    ) -> Result<(Vec<u8>, String, Option<String>), RepositoryFailure> {
        let response = self
            .client
            .get_object()
            .bucket(self.target.bucket())
            .key(self.object_key(object))
            .expected_bucket_owner(self.target.expected_owner())
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|e| failure::sdk(e, false))?;
        let etag = response
            .e_tag()
            .filter(|s| !s.is_empty() && s.len() <= 1024)
            .ok_or(RepositoryFailure::CorruptState)?
            .to_owned();
        let version = response.version_id().map(str::to_owned);
        if version
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.len() > 4096 || s.chars().any(char::is_control))
        {
            return Err(RepositoryFailure::CorruptState);
        }
        let length = response.content_length();
        let bytes =
            crate::aws_s3::http::read_bytes(response.body, length, crate::MAX_OBJECT_BYTES).await?;
        Ok((bytes, etag, version))
    }
    pub async fn delete_tenant_key(
        &self,
        object: ObjectId,
        fence: &TenantKeyPurgeFence,
    ) -> Result<DeleteOutcome, RepositoryFailure> {
        let _operation = self.enter()?;
        self.read_identity().await?;
        TenantKeyPurgeFence::verify(fence.bytes(), &self.identity, object)?;
        let current = match self.fence_current(object).await {
            Ok(current) => Some(current),
            Err(RepositoryFailure::NotFound) => None,
            Err(e) => return Err(e),
        };
        let installed = current
            .as_ref()
            .is_some_and(|(bytes, _, _)| bytes == fence.bytes());
        if !installed {
            if let Some((bytes, _, _)) = &current {
                validate_object(object, bytes)?;
            }
            let request = self
                .client
                .put_object()
                .bucket(self.target.bucket())
                .key(self.object_key(object))
                .expected_bucket_owner(self.target.expected_owner())
                .body(aws_sdk_s3::primitives::ByteStream::from(
                    fence.bytes().to_vec(),
                ));
            let request = match &current {
                Some((_, etag, _)) => request.if_match(etag),
                None => request.if_none_match("*"),
            };
            match request
                .send()
                .with_subscriber(tracing::subscriber::NoSubscriber::default())
                .await
                .map_err(|e| failure::sdk(e, true))
            {
                Ok(_)
                | Err(RepositoryFailure::OutcomeUnknown | RepositoryFailure::PreconditionFailed) =>
                    {},
                Err(e) => return Err(e),
            }
        }
        let (bytes, _, retained) = self.fence_current(object).await?;
        if bytes != fence.bytes() {
            return Err(RepositoryFailure::OutcomeUnknown);
        }
        TenantKeyPurgeFence::verify(&bytes, &self.identity, object)?;
        let key = self.object_key(object);
        let versions = self.versions(&key).await?;
        if (!versions.is_empty() && retained.is_none())
            || retained
                .as_ref()
                .is_some_and(|id| !versions.iter().any(|v| !v.marker && &v.id == id))
        {
            return Err(RepositoryFailure::OutcomeUnknown);
        }
        // Never remove the current fence. Version-specific deletions cannot
        // expose an empty current name to an earlier conditional creator.
        for version in &versions {
            if retained.as_deref() == Some(version.id.as_str()) {
                continue;
            }
            if !version.marker {
                self.verify_version(&key, &version.id, &Proof::Tenant(object, fence.clone()))
                    .await?;
            }
        }
        self.faults
            .at(super::super::AwsS3FaultPoint::BeforeDeletion)?;
        for version in &versions {
            if retained.as_deref() != Some(version.id.as_str()) {
                self.delete_version(&key, &version.id).await?;
            }
        }
        let remaining = self.versions(&key).await?;
        if remaining
            .iter()
            .any(|v| v.marker || retained.as_deref() != Some(v.id.as_str()))
        {
            return Err(RepositoryFailure::OutcomeUnknown);
        }
        let (bytes, _, final_version) = self.fence_current(object).await?;
        if bytes != fence.bytes() || final_version != retained {
            return Err(RepositoryFailure::OutcomeUnknown);
        }
        self.faults
            .at(super::super::AwsS3FaultPoint::AfterDeletion)?;
        Ok(if installed {
            DeleteOutcome::AlreadyAbsent
        } else {
            DeleteOutcome::Deleted
        })
    }
}

#[cfg(all(test, feature = "test-support"))]
#[path = "fence_tests.rs"]
mod tests;
