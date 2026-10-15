use super::{MAX_NATIVE_UPLOAD_ID, Record};
use crate::RepositoryFailure;
use crate::aws_s3::{AwsS3Repository, failure, objects::validate_object};
use tracing::instrument::WithSubscriber;

const NATIVE_PART_BYTES: usize = 5 * 1024 * 1024;
impl AwsS3Repository {
    pub(in crate::aws_s3) async fn staged_bytes(
        &self,
        record: &Record,
    ) -> Result<Vec<u8>, RepositoryFailure> {
        let response = self
            .client
            .get_object()
            .bucket(self.target.bucket())
            .key(self.staging_key(&record.owned()))
            .expected_bucket_owner(self.target.expected_owner())
            .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled)
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|error| failure::sdk(error, false))?;
        if response
            .content_length()
            .is_some_and(|length| length < 0 || length as u64 != record.plan.size)
        {
            return Err(RepositoryFailure::ChecksumMismatch);
        }
        let length = response.content_length();
        let bytes =
            crate::aws_s3::http::read_bytes(response.body, length, record.plan.size).await?;
        if bytes.len() as u64 != record.plan.size {
            return Err(RepositoryFailure::ChecksumMismatch);
        }
        validate_object(record.plan.object, &bytes)?;
        Ok(bytes)
    }
    pub(in crate::aws_s3) async fn owned_multipart_ids(
        &self,
        record: &super::OwnedUpload,
    ) -> Result<Vec<String>, RepositoryFailure> {
        let key = self.staging_key(record);
        let response = self
            .client
            .list_multipart_uploads()
            .bucket(self.target.bucket())
            .prefix(&key)
            .max_uploads(16)
            .expected_bucket_owner(self.target.expected_owner())
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|error| failure::sdk(error, false))?;
        match response.is_truncated() {
            Some(false) => {},
            Some(true) => return Err(RepositoryFailure::LimitExceeded),
            None => return Err(RepositoryFailure::CorruptState),
        }
        let mut ids = Vec::new();
        for upload in response
            .uploads()
            .iter()
            .filter(|upload| upload.key() == Some(key.as_str()))
        {
            let id = upload
                .upload_id()
                .filter(|id| {
                    !id.is_empty()
                        && id.len() <= MAX_NATIVE_UPLOAD_ID
                        && !id.chars().any(char::is_control)
                })
                .ok_or(RepositoryFailure::CorruptState)?;
            ids.push(id.to_owned());
        }
        Ok(ids)
    }
    pub(in crate::aws_s3) async fn assemble_native(
        &self,
        record: &mut Record,
        etag: &mut String,
    ) -> Result<Vec<u8>, RepositoryFailure> {
        if !record.state().complete() {
            return Err(RepositoryFailure::InvalidInput);
        }
        match self.staged_bytes(record).await {
            Ok(bytes) => return Ok(bytes),
            Err(RepositoryFailure::NotFound) => {},
            Err(error) => return Err(error),
        }
        if record.native_id().is_none() {
            let ids = self.owned_multipart_ids(&record.owned()).await?;
            let create = record.native_creation_allowed(ids.len())?;
            let id = if let Some(id) = ids.into_iter().next() {
                id
            } else if create {
                self.faults
                    .at(crate::aws_s3::AwsS3FaultPoint::BeforeNativeCreation)?;
                record.mark_native_creation_requested()?;
                *etag = self.write_upload(record, Some(etag)).await?;
                let response = self
                    .client
                    .create_multipart_upload()
                    .bucket(self.target.bucket())
                    .key(self.staging_key(&record.owned()))
                    .expected_bucket_owner(self.target.expected_owner())
                    .checksum_algorithm(aws_sdk_s3::types::ChecksumAlgorithm::Sha256)
                    .checksum_type(aws_sdk_s3::types::ChecksumType::Composite)
                    .send()
                    .with_subscriber(tracing::subscriber::NoSubscriber::default())
                    .await
                    .map_err(|error| failure::sdk(error, true))?;
                self.faults
                    .at(crate::aws_s3::AwsS3FaultPoint::AfterNativeCreation)?;
                response
                    .upload_id()
                    .filter(|id| {
                        !id.is_empty()
                            && id.len() <= MAX_NATIVE_UPLOAD_ID
                            && !id.chars().any(char::is_control)
                    })
                    .ok_or(RepositoryFailure::OutcomeUnknown)?
                    .to_owned()
            } else {
                return Err(RepositoryFailure::OutcomeUnknown);
            };
            record.attach_native_id(id)?;
            *etag = self.write_upload(record, Some(etag)).await?;
        }
        let id = record.native_id().ok_or(RepositoryFailure::CorruptState)?;
        let mut parts = Vec::with_capacity(14);
        for (index, bytes) in record.bytes.chunks(NATIVE_PART_BYTES).enumerate() {
            let number = i32::try_from(index + 1).map_err(|_| RepositoryFailure::LimitExceeded)?;
            let response = self
                .client
                .upload_part()
                .bucket(self.target.bucket())
                .key(self.staging_key(&record.owned()))
                .upload_id(id)
                .expected_bucket_owner(self.target.expected_owner())
                .part_number(number)
                .checksum_algorithm(aws_sdk_s3::types::ChecksumAlgorithm::Sha256)
                .body(aws_sdk_s3::primitives::ByteStream::from(bytes.to_vec()))
                .send()
                .with_subscriber(tracing::subscriber::NoSubscriber::default())
                .await
                .map_err(|error| failure::sdk(error, true))?;
            let etag = response
                .e_tag()
                .filter(|etag| !etag.is_empty() && etag.len() <= 1024)
                .ok_or(RepositoryFailure::CorruptState)?;
            let checksum = response
                .checksum_sha256()
                .filter(|checksum| checksum.len() <= 128)
                .ok_or(RepositoryFailure::CorruptState)?;
            parts.push(
                aws_sdk_s3::types::CompletedPart::builder()
                    .part_number(number)
                    .e_tag(etag)
                    .checksum_sha256(checksum)
                    .build(),
            );
        }
        self.faults
            .at(crate::aws_s3::AwsS3FaultPoint::BeforeNativeCompletion)?;
        let result = self
            .client
            .complete_multipart_upload()
            .bucket(self.target.bucket())
            .key(self.staging_key(&record.owned()))
            .upload_id(id)
            .expected_bucket_owner(self.target.expected_owner())
            .if_none_match("*")
            .checksum_type(aws_sdk_s3::types::ChecksumType::Composite)
            .multipart_upload(
                aws_sdk_s3::types::CompletedMultipartUpload::builder()
                    .set_parts(Some(parts))
                    .build(),
            )
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|error| failure::sdk(error, true));
        if result.is_ok() {
            self.faults
                .at(crate::aws_s3::AwsS3FaultPoint::AfterNativeCompletion)?;
        }
        match result {
            Ok(_)
            | Err(RepositoryFailure::PreconditionFailed | RepositoryFailure::OutcomeUnknown) => {
                match self.staged_bytes(record).await {
                    Ok(bytes) => Ok(bytes),
                    Err(_) => Err(RepositoryFailure::OutcomeUnknown),
                }
            },
            Err(error) => Err(error),
        }
    }
}
