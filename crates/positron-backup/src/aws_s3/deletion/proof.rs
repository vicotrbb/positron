use super::Proof;
use crate::aws_s3::{AwsS3Repository, failure, objects::validate_object, upload::Record};
use crate::{MAX_OBJECT_BYTES, MAX_REGISTRY_HEAD_BYTES, RegistryHead, RepositoryFailure};
use tracing::instrument::WithSubscriber;
impl AwsS3Repository {
    pub(in crate::aws_s3) async fn verify_version(
        &self,
        key: &str,
        version: &str,
        proof: &Proof,
    ) -> Result<(), RepositoryFailure> {
        let max = match proof {
            Proof::Object(_) | Proof::Tenant(_, _) => MAX_OBJECT_BYTES,
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
        let length = response.content_length();
        let bytes = crate::aws_s3::http::read_bytes(response.body, length, max).await?;
        match proof {
            Proof::Object(id) => validate_object(*id, &bytes),
            Proof::Tenant(id, fence) => {
                if bytes == fence.bytes() {
                    crate::TenantKeyPurgeFence::verify(&bytes, &self.identity, *id).map(|_| ())
                } else {
                    validate_object(*id, &bytes)
                }
            },
            Proof::Head => RegistryHead::decode_frame(&bytes).map(|_| ()),
            Proof::Upload(id) => {
                Record::inspect_owned(&bytes, self.target.commitment(), *id).map(|_| ())
            },
        }
    }
}
