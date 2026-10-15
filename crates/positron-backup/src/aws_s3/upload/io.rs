use super::{HEADER, MAX_NATIVE_UPLOAD_ID, Record};
use crate::aws_s3::{AwsS3Repository, failure};
use crate::{MAX_OBJECT_BYTES, RepositoryFailure, UploadId};
use tracing::instrument::WithSubscriber;

impl AwsS3Repository {
    pub(in crate::aws_s3) fn upload_key(&self, id: UploadId) -> String {
        format!("{}{}", self.target.prefix(), id.name())
    }
    pub(in crate::aws_s3) fn staging_key(&self, record: &super::OwnedUpload) -> String {
        let mut key = format!("{}m-", self.target.prefix());
        for byte in record.selector {
            key.push_str(&format!("{byte:02x}"));
        }
        key
    }
    pub(in crate::aws_s3) async fn read_upload(
        &self,
        id: UploadId,
    ) -> Result<Option<(Record, String)>, RepositoryFailure> {
        let response = match self
            .client
            .get_object()
            .bucket(self.target.bucket())
            .key(self.upload_key(id))
            .expected_bucket_owner(self.target.expected_owner())
            .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled)
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|error| failure::sdk(error, false))
        {
            Ok(response) => response,
            Err(RepositoryFailure::NotFound) => return Ok(None),
            Err(error) => return Err(error),
        };
        let max = MAX_OBJECT_BYTES + (HEADER + MAX_NATIVE_UPLOAD_ID + 32) as u64;
        if response
            .content_length()
            .is_some_and(|length| length < 0 || length as u64 > max)
        {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let etag = response
            .e_tag()
            .filter(|value| !value.is_empty() && value.len() <= 1024)
            .ok_or(RepositoryFailure::CorruptState)?
            .to_owned();
        let length = response.content_length();
        let bytes = crate::aws_s3::http::read_bytes(response.body, length, max).await?;
        let record = Record::decode_buffer(bytes, self.target.commitment(), id)?;
        Ok(Some((record, etag)))
    }
    pub(in crate::aws_s3) async fn write_upload(
        &self,
        record: &Record,
        etag: Option<&str>,
    ) -> Result<String, RepositoryFailure> {
        self.faults
            .at(crate::aws_s3::AwsS3FaultPoint::BeforeRecordPublication)?;
        let mut request = self
            .client
            .put_object()
            .bucket(self.target.bucket())
            .key(self.upload_key(record.plan.id()))
            .expected_bucket_owner(self.target.expected_owner())
            .checksum_algorithm(aws_sdk_s3::types::ChecksumAlgorithm::Sha256)
            .body(aws_sdk_s3::primitives::ByteStream::from(
                record.encode(self.target.commitment()),
            ));
        request = match etag {
            Some(etag) => request.if_match(etag),
            None => request.if_none_match("*"),
        };
        let result = match request
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|error| failure::sdk(error, true))
        {
            Ok(response) => response
                .e_tag()
                .filter(|value| !value.is_empty() && value.len() <= 1024)
                .map(str::to_owned)
                .ok_or(RepositoryFailure::OutcomeUnknown),
            Err(RepositoryFailure::OutcomeUnknown) => {
                match self.read_upload(record.plan.id()).await {
                    Ok(Some((observed, etag))) if observed == *record => Ok(etag),
                    _ => Err(RepositoryFailure::OutcomeUnknown),
                }
            },
            Err(error) => Err(error),
        };
        if result.is_ok() {
            self.faults
                .at(crate::aws_s3::AwsS3FaultPoint::AfterRecordPublication)?;
        }
        result
    }
}
