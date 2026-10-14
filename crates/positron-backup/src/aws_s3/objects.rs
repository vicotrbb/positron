use super::{AwsS3Repository, failure};
use crate::{
    ChecksummedBytes, ImmutableObject, MAX_OBJECT_BYTES, ObjectId, ObjectMetadata, ObjectRange,
    PutOutcome, RepositoryFailure,
};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tracing::instrument::WithSubscriber;

pub(super) fn validate_object(id: ObjectId, bytes: &[u8]) -> Result<(), RepositoryFailure> {
    if bytes.len() as u64 > MAX_OBJECT_BYTES {
        return Err(RepositoryFailure::LimitExceeded);
    }
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    if actual != id.checksum() {
        return Err(RepositoryFailure::ChecksumMismatch);
    }
    Ok(())
}
impl AwsS3Repository {
    pub(super) fn object_key(&self, id: ObjectId) -> String {
        format!("{}{}", self.target.prefix(), id.name())
    }
    pub(super) async fn read_object(&self, id: ObjectId) -> Result<Vec<u8>, RepositoryFailure> {
        self.read_object_metadata(id).await.map(|(bytes, _)| bytes)
    }
    async fn read_object_metadata(
        &self,
        id: ObjectId,
    ) -> Result<(Vec<u8>, crate::ObjectProtection), RepositoryFailure> {
        let response = self
            .client
            .get_object()
            .bucket(self.target.bucket())
            .key(self.object_key(id))
            .expected_bucket_owner(self.target.expected_owner())
            .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled)
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|error| failure::sdk(error, false))?;
        if response
            .content_length()
            .is_some_and(|size| size < 0 || size as u64 > MAX_OBJECT_BYTES)
        {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let protection = object_protection(&response);
        let length = response.content_length();
        let bytes =
            crate::aws_s3::http::read_bytes(response.body, length, MAX_OBJECT_BYTES).await?;
        validate_object(id, &bytes)?;
        Ok((bytes, protection))
    }
    /// Reads and verifies the full content checksum, including native multipart
    /// objects whose S3 SHA-256 checksum is composite rather than a full digest.
    pub async fn head(&self, id: ObjectId) -> Result<ObjectMetadata, RepositoryFailure> {
        let _operation = self.enter()?;
        self.read_identity().await?;
        let (bytes, protection) = self.read_object_metadata(id).await?;
        Ok(ObjectMetadata {
            size: bytes.len() as u64,
            checksum: id.checksum(),
            protection,
        })
    }
    pub async fn read_range(
        &self,
        range: ObjectRange,
    ) -> Result<ChecksummedBytes, RepositoryFailure> {
        let _operation = self.enter()?;
        self.read_identity().await?;
        let observed = self
            .client
            .head_object()
            .bucket(self.target.bucket())
            .key(self.object_key(range.object))
            .expected_bucket_owner(self.target.expected_owner())
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|error| failure::sdk(error, false))?;
        let size = observed
            .content_length()
            .and_then(|size| u64::try_from(size).ok())
            .filter(|size| *size <= MAX_OBJECT_BYTES)
            .ok_or(RepositoryFailure::CorruptState)?;
        let end = range
            .offset
            .checked_add(range.length)
            .filter(|end| *end <= size)
            .ok_or(RepositoryFailure::InvalidInput)?;
        if range.length == 0 {
            return Ok(ChecksummedBytes {
                bytes: Vec::new(),
                checksum: Sha256::digest([]).into(),
            });
        }
        let etag = observed
            .e_tag()
            .filter(|value| !value.is_empty() && value.len() <= 1024)
            .ok_or(RepositoryFailure::CorruptState)?;
        let response = self
            .client
            .get_object()
            .bucket(self.target.bucket())
            .key(self.object_key(range.object))
            .expected_bucket_owner(self.target.expected_owner())
            .if_match(etag)
            .range(format!("bytes={}-{}", range.offset, end - 1))
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|error| failure::sdk(error, false))?;
        validate_range_response(
            range,
            size,
            response.content_range(),
            response
                .content_length()
                .and_then(|size| u64::try_from(size).ok())
                .ok_or(RepositoryFailure::CorruptState)?,
        )?;
        let mut selected = Vec::new();
        response
            .body
            .into_async_read()
            .take(range.length + 1)
            .read_to_end(&mut selected)
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|_| RepositoryFailure::StorageUnavailable)?;
        if selected.len() as u64 != range.length {
            return Err(RepositoryFailure::CorruptState);
        }
        Ok(ChecksummedBytes {
            checksum: Sha256::digest(&selected).into(),
            bytes: selected,
        })
    }
    pub async fn put_if_absent(
        &self,
        object: ImmutableObject,
    ) -> Result<PutOutcome, RepositoryFailure> {
        let _operation = self.enter()?;
        self.read_identity().await?;
        self.put_checked(object).await
    }
    pub(super) async fn put_checked(
        &self,
        object: ImmutableObject,
    ) -> Result<PutOutcome, RepositoryFailure> {
        let id = object.id();
        self.faults
            .at(super::AwsS3FaultPoint::BeforeObjectPublication)?;
        let result = self
            .client
            .put_object()
            .bucket(self.target.bucket())
            .key(self.object_key(id))
            .expected_bucket_owner(self.target.expected_owner())
            .if_none_match("*")
            .checksum_algorithm(aws_sdk_s3::types::ChecksumAlgorithm::Sha256)
            .body(aws_sdk_s3::primitives::ByteStream::from(
                object.bytes().to_vec(),
            ))
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|error| failure::sdk(error, true));
        drop(object);
        let outcome = match result {
            Ok(_) => Ok(PutOutcome::Created),
            Err(RepositoryFailure::PreconditionFailed) => {
                self.read_object(id).await?;
                Ok(PutOutcome::AlreadyPresent)
            },
            Err(RepositoryFailure::OutcomeUnknown) => match self.read_object(id).await {
                Ok(_) => Ok(PutOutcome::AlreadyPresent),
                Err(
                    RepositoryFailure::NotFound
                    | RepositoryFailure::StorageUnavailable
                    | RepositoryFailure::Throttled { .. },
                ) => Err(RepositoryFailure::OutcomeUnknown),
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        };
        if outcome.is_ok() {
            self.faults
                .at(super::AwsS3FaultPoint::AfterObjectPublication)?;
        }
        outcome
    }
}

pub(super) fn validate_range_response(
    range: ObjectRange,
    size: u64,
    extent: Option<&str>,
    length: u64,
) -> Result<(), RepositoryFailure> {
    let end = range
        .offset
        .checked_add(range.length)
        .filter(|end| *end <= size)
        .and_then(|end| end.checked_sub(1))
        .ok_or(RepositoryFailure::InvalidInput)?;
    if size > MAX_OBJECT_BYTES
        || range.length == 0
        || length != range.length
        || extent != Some(format!("bytes {}-{end}/{size}", range.offset).as_str())
    {
        return Err(RepositoryFailure::CorruptState);
    }
    Ok(())
}

fn object_protection(
    response: &aws_sdk_s3::operation::get_object::GetObjectOutput,
) -> crate::ObjectProtection {
    use crate::PolicyObservation::{Observed, Unavailable, Unobservable};
    use aws_sdk_s3::types::{ObjectLockEventHold, ObjectLockLegalHoldStatus, ObjectLockMode};
    let invalid = RepositoryFailure::CorruptState;
    let retention = match (
        response.object_lock_mode(),
        response.object_lock_retain_until_date(),
    ) {
        (None, None) => Unobservable,
        (Some(mode), Some(date)) => {
            let mode = match mode {
                ObjectLockMode::Governance => Some(crate::RetentionMode::Governance),
                ObjectLockMode::Compliance => Some(crate::RetentionMode::Compliance),
                _ => None,
            };
            match (mode, u64::try_from(date.secs())) {
                (Some(mode), Ok(seconds)) if seconds > 0 && date.subsec_nanos() == 0 => {
                    Observed(crate::ObjectRetention {
                        mode,
                        retain_until_unix_seconds: seconds,
                    })
                },
                _ => Unavailable(invalid),
            }
        },
        _ => Unavailable(invalid),
    };
    let legal_hold = match response.object_lock_legal_hold_status() {
        None => Unobservable,
        Some(ObjectLockLegalHoldStatus::On) => Observed(true),
        Some(ObjectLockLegalHoldStatus::Off) => Observed(false),
        _ => Unavailable(invalid),
    };
    let duration = match (
        response.object_lock_event_hold_duration_days(),
        response.object_lock_event_hold_duration_years(),
    ) {
        (Some(days), None) if days > 0 => Some(crate::RetentionPeriod::Days(days as u32)),
        (None, Some(years)) if years > 0 => Some(crate::RetentionPeriod::Years(years as u32)),
        _ => None,
    };
    let event_hold = match response.object_lock_event_hold() {
        None if response.object_lock_event_hold_duration_days().is_none()
            && response.object_lock_event_hold_duration_years().is_none() =>
        {
            Unobservable
        },
        Some(ObjectLockEventHold::Off)
            if response.object_lock_event_hold_duration_days().is_none()
                && response.object_lock_event_hold_duration_years().is_none() =>
        {
            Observed(None)
        },
        Some(ObjectLockEventHold::On) => duration
            .map(|period| Observed(Some(period)))
            .unwrap_or(Unavailable(invalid)),
        _ => Unavailable(invalid),
    };
    crate::ObjectProtection {
        retention,
        legal_hold,
        event_hold,
    }
}

#[cfg(test)]
mod protection_tests {
    use super::*;
    use aws_sdk_s3::{
        operation::get_object::GetObjectOutput,
        types::{ObjectLockEventHold, ObjectLockLegalHoldStatus, ObjectLockMode},
    };
    #[test]
    fn missing_protection_headers_are_unknown_and_observed_headers_are_exact() {
        let absent = object_protection(&GetObjectOutput::builder().build());
        assert_eq!(absent.legal_hold, crate::PolicyObservation::Unobservable);
        assert_eq!(absent.retention, crate::PolicyObservation::Unobservable);
        let observed = object_protection(
            &GetObjectOutput::builder()
                .object_lock_mode(ObjectLockMode::Compliance)
                .object_lock_retain_until_date(aws_smithy_types::DateTime::from_secs(1_900_000_000))
                .object_lock_legal_hold_status(ObjectLockLegalHoldStatus::On)
                .object_lock_event_hold(ObjectLockEventHold::Off)
                .build(),
        );
        assert_eq!(
            observed.legal_hold,
            crate::PolicyObservation::Observed(true)
        );
        assert_eq!(
            observed.retention,
            crate::PolicyObservation::Observed(crate::ObjectRetention {
                mode: crate::RetentionMode::Compliance,
                retain_until_unix_seconds: 1_900_000_000,
            })
        );
        assert_eq!(
            observed.event_hold,
            crate::PolicyObservation::Observed(None)
        );
    }
    #[test]
    fn partial_or_unknown_protection_headers_fail_closed() {
        let partial = object_protection(
            &GetObjectOutput::builder()
                .object_lock_mode(ObjectLockMode::Governance)
                .build(),
        );
        assert_eq!(
            partial.retention,
            crate::PolicyObservation::Unavailable(RepositoryFailure::CorruptState)
        );
        let unknown = object_protection(
            &GetObjectOutput::builder()
                .object_lock_legal_hold_status(ObjectLockLegalHoldStatus::from("FUTURE"))
                .object_lock_event_hold(ObjectLockEventHold::On)
                .object_lock_event_hold_duration_days(0)
                .build(),
        );
        assert_eq!(
            unknown.legal_hold,
            crate::PolicyObservation::Unavailable(RepositoryFailure::CorruptState)
        );
        assert_eq!(
            unknown.event_hold,
            crate::PolicyObservation::Unavailable(RepositoryFailure::CorruptState)
        );
    }
}
