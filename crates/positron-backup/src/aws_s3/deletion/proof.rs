use super::Proof;
use crate::aws_s3::{AwsS3Repository, failure, objects::validate_object, upload::Record};
use crate::{MAX_OBJECT_BYTES, MAX_REGISTRY_HEAD_BYTES, RegistryHead, RepositoryFailure};
use tokio::io::AsyncReadExt;
use tracing::instrument::WithSubscriber;
impl AwsS3Repository {
    pub(in crate::aws_s3) async fn verify_version(
        &self,
        key: &str,
        version: &str,
        proof: &Proof,
    ) -> Result<(), RepositoryFailure> {
        let max = match proof {
            Proof::Object(_) => MAX_OBJECT_BYTES,
            Proof::Head => (MAX_REGISTRY_HEAD_BYTES + 40) as u64,
            Proof::Upload(_) => MAX_OBJECT_BYTES + 65536,
        };
        let response = match self
            .client
            .get_object()
            .bucket(self.target.bucket())
            .key(key)
            .version_id(version)
            .expected_bucket_owner(self.target.expected_owner())
            .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled)
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|error| failure::sdk(error, false))
        {
            Ok(response) => response,
            Err(RepositoryFailure::NotFound) => return Ok(()),
            Err(error) => return Err(error),
        };
        if response
            .content_length()
            .is_some_and(|size| size < 0 || size as u64 > max)
        {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let mut bytes = Vec::new();
        response
            .body
            .into_async_read()
            .take(max + 1)
            .read_to_end(&mut bytes)
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|_| RepositoryFailure::StorageUnavailable)?;
        if bytes.len() as u64 > max {
            return Err(RepositoryFailure::LimitExceeded);
        }
        match proof {
            Proof::Object(id) => validate_object(*id, &bytes),
            Proof::Head => RegistryHead::decode_frame(&bytes).map(|_| ()),
            Proof::Upload(id) => Record::decode(&bytes, self.target.commitment(), *id).map(|_| ()),
        }
    }
}
