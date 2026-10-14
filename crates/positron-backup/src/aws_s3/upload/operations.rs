use super::Record;
use crate::aws_s3::{AwsS3Repository, deletion::Proof, failure};
use crate::{
    DeleteOutcome, ImmutableObject, PutOutcome, RepositoryFailure, UploadId, UploadOutcome,
    UploadPart, UploadPlan, UploadState,
};
use tracing::instrument::WithSubscriber;

impl AwsS3Repository {
    async fn cleanup_artifacts(
        &self,
        record: &super::OwnedUpload,
    ) -> Result<(), RepositoryFailure> {
        let key = self.staging_key(record);
        let mut ids = self.owned_multipart_ids(record).await?;
        if let Some(id) = &record.native_id
            && !ids.contains(id)
        {
            ids.push(id.clone());
        }
        if record.creation_unresolved && ids.is_empty() {
            return Err(RepositoryFailure::OutcomeUnknown);
        }
        for id in ids {
            match self
                .client
                .abort_multipart_upload()
                .bucket(self.target.bucket())
                .key(&key)
                .upload_id(&id)
                .expected_bucket_owner(self.target.expected_owner())
                .send()
                .with_subscriber(tracing::subscriber::NoSubscriber::default())
                .await
                .map_err(|error| failure::sdk(error, true))
            {
                Ok(_) | Err(RepositoryFailure::NotFound) => {},
                Err(error) => return Err(error),
            }
            match self
                .client
                .list_parts()
                .bucket(self.target.bucket())
                .key(&key)
                .upload_id(&id)
                .max_parts(1)
                .expected_bucket_owner(self.target.expected_owner())
                .send()
                .with_subscriber(tracing::subscriber::NoSubscriber::default())
                .await
                .map_err(|error| failure::sdk(error, false))
            {
                Err(RepositoryFailure::NotFound) => {},
                Ok(_) => return Err(RepositoryFailure::OutcomeUnknown),
                Err(error) => return Err(error),
            }
        }
        let current = self.current_etag(&key).await?;
        self.purge_key(&key, current.as_deref(), Proof::Object(record.plan.object))
            .await?;
        Ok(())
    }
    async fn cleanup_upload(
        &self,
        id: UploadId,
        current: Option<&Record>,
        etag: Option<&str>,
    ) -> Result<bool, RepositoryFailure> {
        // A deleted current record is terminal authority. Historical frames
        // authorize cleanup only, never resurrection or resumed publication.
        let mut owned = self.retained_uploads(id).await?;
        if let Some(current) = current {
            let current = current.owned();
            if !owned.contains(&current) {
                owned.push(current);
            }
        }
        for record in &owned {
            if record.creation_unresolved
                && owned.iter().any(|other| {
                    other.selector == record.selector
                        && other.attempt == record.attempt
                        && other.native_id.is_some()
                })
            {
                continue;
            }
            self.cleanup_artifacts(record).await?;
        }
        self.purge_key(&self.upload_key(id), etag, Proof::Upload(id))
            .await
    }
    async fn finish_upload(
        &self,
        record: &mut Record,
        etag: &mut String,
    ) -> Result<PutOutcome, RepositoryFailure> {
        let bytes = match self.read_object(record.plan.object).await {
            Ok(bytes) => {
                if bytes.len() as u64 != record.plan.size {
                    return Err(RepositoryFailure::ChecksumMismatch);
                }
                self.cleanup_upload(record.plan.id(), Some(record), Some(etag))
                    .await?;
                return Ok(PutOutcome::AlreadyPresent);
            },
            Err(RepositoryFailure::NotFound) => match self.assemble_native(record, etag).await {
                Ok(bytes) => bytes,
                // A missing session may be an uncertain completed publication.
                // Preserve its identity instead of issuing a second Create.
                Err(RepositoryFailure::NotFound) => return Err(RepositoryFailure::OutcomeUnknown),
                Err(error) => return Err(error),
            },
            Err(error) => return Err(error),
        };
        let object = ImmutableObject::new(bytes)?;
        if object.id() != record.plan.object {
            return Err(RepositoryFailure::ChecksumMismatch);
        }
        let outcome = self.put_checked(object).await?;
        self.cleanup_upload(record.plan.id(), Some(record), Some(etag))
            .await?;
        Ok(outcome)
    }
    pub async fn begin_upload(&self, plan: UploadPlan) -> Result<UploadState, RepositoryFailure> {
        let _operation = self.enter()?;
        self.read_identity().await?;
        match self.read_object(plan.object).await {
            Ok(bytes) => {
                if bytes.len() as u64 != plan.size {
                    return Err(RepositoryFailure::ChecksumMismatch);
                }
                let current = self.read_upload(plan.id()).await?;
                self.cleanup_upload(
                    plan.id(),
                    current.as_ref().map(|(record, _)| record),
                    current.as_ref().map(|(_, etag)| etag.as_str()),
                )
                .await?;
                return Ok(UploadState {
                    plan,
                    written: plan.size,
                    checksum: plan.object.checksum(),
                });
            },
            Err(RepositoryFailure::NotFound) => {},
            Err(error) => return Err(error),
        }
        let (mut record, mut etag) = match self.read_upload(plan.id()).await? {
            Some(record) => record,
            None => {
                self.cleanup_upload(plan.id(), None, None).await?;
                let record = Record::new(plan, Vec::new(), None)?;
                match self.write_upload(&record, None).await {
                    Ok(etag) => (record, etag),
                    Err(RepositoryFailure::PreconditionFailed) => self
                        .read_upload(plan.id())
                        .await?
                        .ok_or(RepositoryFailure::PreconditionFailed)?,
                    Err(error) => return Err(error),
                }
            },
        };
        if record.state().complete() {
            self.finish_upload(&mut record, &mut etag).await?;
        }
        Ok(record.state())
    }
    pub async fn inspect_upload(
        &self,
        id: UploadId,
    ) -> Result<Option<UploadState>, RepositoryFailure> {
        let _operation = self.enter()?;
        self.read_identity().await?;
        Ok(self
            .read_upload(id)
            .await?
            .map(|(record, _)| record.state()))
    }
    pub async fn resume_upload(
        &self,
        part: UploadPart,
    ) -> Result<UploadOutcome, RepositoryFailure> {
        let _operation = self.enter()?;
        self.read_identity().await?;
        let (mut record, mut etag) = match self.read_upload(part.state.id()).await? {
            Some(record) => record,
            None => {
                let bytes = self.read_object(part.state.object()).await?;
                if bytes.len() as u64 != part.state.total_size() {
                    return Err(RepositoryFailure::ChecksumMismatch);
                }
                return Ok(UploadOutcome::Complete(PutOutcome::AlreadyPresent));
            },
        };
        if let Some(next) = record.apply(&part)? {
            etag = self.write_upload(&next, Some(&etag)).await?;
            record = next;
        }
        if record.state().complete() {
            return self
                .finish_upload(&mut record, &mut etag)
                .await
                .map(UploadOutcome::Complete);
        }
        Ok(UploadOutcome::Pending(record.state()))
    }
    pub async fn abort_upload(&self, id: UploadId) -> Result<DeleteOutcome, RepositoryFailure> {
        let _operation = self.enter()?;
        self.read_identity().await?;
        let current = self.read_upload(id).await?;
        let deleted = self
            .cleanup_upload(
                id,
                current.as_ref().map(|(record, _)| record),
                current.as_ref().map(|(_, etag)| etag.as_str()),
            )
            .await?;
        Ok(if deleted {
            DeleteOutcome::Deleted
        } else {
            DeleteOutcome::AlreadyAbsent
        })
    }
}
