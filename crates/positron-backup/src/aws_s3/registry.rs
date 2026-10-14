use super::{AwsS3Repository, failure};
use crate::{
    CasOutcome, HeadSlot, MAX_REGISTRY_HEAD_BYTES, RegistryHead, RegistryHeadChange,
    RepositoryFailure,
};
use tokio::io::AsyncReadExt;
use tracing::instrument::WithSubscriber;

impl AwsS3Repository {
    pub(super) fn head_key(&self, slot: HeadSlot) -> String {
        format!("{}{}", self.target.prefix(), slot.name())
    }
    pub(super) async fn read_head(
        &self,
        slot: HeadSlot,
    ) -> Result<Option<(RegistryHead, String)>, RepositoryFailure> {
        let response = match self
            .client
            .get_object()
            .bucket(self.target.bucket())
            .key(self.head_key(slot))
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
        if response
            .content_length()
            .is_some_and(|size| size < 0 || size as u64 > (MAX_REGISTRY_HEAD_BYTES + 40) as u64)
        {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let etag = response
            .e_tag()
            .filter(|value| !value.is_empty() && value.len() <= 1024)
            .ok_or(RepositoryFailure::CorruptState)?
            .to_owned();
        let mut bytes = Vec::new();
        response
            .body
            .into_async_read()
            .take((MAX_REGISTRY_HEAD_BYTES + 41) as u64)
            .read_to_end(&mut bytes)
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|_| RepositoryFailure::StorageUnavailable)?;
        Ok(Some((RegistryHead::decode_frame(&bytes)?, etag)))
    }
    pub async fn registry_head_at(
        &self,
        slot: HeadSlot,
    ) -> Result<Option<RegistryHead>, RepositoryFailure> {
        let _operation = self.enter()?;
        self.read_identity().await?;
        Ok(self.read_head(slot).await?.map(|(head, _)| head))
    }
    pub async fn compare_and_swap_head_at(
        &self,
        slot: HeadSlot,
        change: RegistryHeadChange,
    ) -> Result<CasOutcome, RepositoryFailure> {
        let _operation = self.enter()?;
        self.read_identity().await?;
        let current = self.read_head(slot).await?;
        let version = current.as_ref().map(|(head, _)| head.version());
        if version != change.expected {
            return Ok(CasOutcome::Conflict(version));
        }
        let mut request = self
            .client
            .put_object()
            .bucket(self.target.bucket())
            .key(self.head_key(slot))
            .expected_bucket_owner(self.target.expected_owner())
            .checksum_algorithm(aws_sdk_s3::types::ChecksumAlgorithm::Sha256)
            .body(aws_sdk_s3::primitives::ByteStream::from(
                change.successor.encode_frame(),
            ));
        request = match current {
            Some((_, etag)) => request.if_match(etag),
            None => request.if_none_match("*"),
        };
        self.faults
            .at(super::AwsS3FaultPoint::BeforeRegistryPublication)?;
        let outcome = match request
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|error| failure::sdk(error, true))
        {
            Ok(_) => Ok(CasOutcome::Published(change.successor.version())),
            Err(RepositoryFailure::PreconditionFailed) => Ok(CasOutcome::Conflict(
                self.read_head(slot).await?.map(|(head, _)| head.version()),
            )),
            Err(RepositoryFailure::OutcomeUnknown) => match self.read_head(slot).await {
                Ok(Some((head, _))) if head.version() == change.successor.version() => {
                    Ok(CasOutcome::Published(head.version()))
                },
                _ => Err(RepositoryFailure::OutcomeUnknown),
            },
            Err(error) => Err(error),
        };
        if matches!(outcome, Ok(CasOutcome::Published(_))) {
            self.faults
                .at(super::AwsS3FaultPoint::AfterRegistryPublication)?;
        }
        outcome
    }
}
