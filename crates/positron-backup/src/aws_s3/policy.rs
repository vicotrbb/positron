use super::{AwsS3Repository, failure};
use crate::{
    LifecyclePolicy, ObjectLockPolicy, PolicyObservation, RepositoryFailure, RepositoryPolicy,
    RetentionMode, RetentionPeriod, RetentionPolicy, VersioningPolicy,
};
use aws_sdk_s3::error::ProvideErrorMetadata;
use tracing::instrument::WithSubscriber;

pub(super) fn versioning(
    status: Option<&aws_sdk_s3::types::BucketVersioningStatus>,
) -> Result<VersioningPolicy, RepositoryFailure> {
    match status {
        None => Ok(VersioningPolicy::Disabled),
        Some(aws_sdk_s3::types::BucketVersioningStatus::Enabled) => Ok(VersioningPolicy::Enabled),
        Some(aws_sdk_s3::types::BucketVersioningStatus::Suspended) => {
            Ok(VersioningPolicy::Suspended)
        },
        _ => Err(RepositoryFailure::CorruptState),
    }
}
fn object_lock(
    configuration: Option<&aws_sdk_s3::types::ObjectLockConfiguration>,
) -> Result<ObjectLockPolicy, RepositoryFailure> {
    let configuration = configuration.ok_or(RepositoryFailure::CorruptState)?;
    if configuration.object_lock_enabled() != Some(&aws_sdk_s3::types::ObjectLockEnabled::Enabled) {
        return Err(RepositoryFailure::CorruptState);
    }
    let retention = configuration
        .rule()
        .and_then(|rule| rule.default_retention())
        .map(|retention| {
            let mode = match retention.mode() {
                Some(aws_sdk_s3::types::ObjectLockRetentionMode::Governance) => {
                    RetentionMode::Governance
                },
                Some(aws_sdk_s3::types::ObjectLockRetentionMode::Compliance) => {
                    RetentionMode::Compliance
                },
                _ => return Err(RepositoryFailure::CorruptState),
            };
            let period = match (retention.days(), retention.years()) {
                (Some(days), None) if days > 0 => RetentionPeriod::Days(
                    u32::try_from(days).map_err(|_| RepositoryFailure::CorruptState)?,
                ),
                (None, Some(years)) if years > 0 => RetentionPeriod::Years(
                    u32::try_from(years).map_err(|_| RepositoryFailure::CorruptState)?,
                ),
                _ => return Err(RepositoryFailure::CorruptState),
            };
            Ok(RetentionPolicy { mode, period })
        })
        .transpose()?;
    Ok(ObjectLockPolicy::Enabled {
        default_retention: retention,
    })
}
pub(super) fn lifecycle(
    rules: &[aws_sdk_s3::types::LifecycleRule],
    target: &str,
) -> Result<LifecyclePolicy, RepositoryFailure> {
    if rules.len() > 1000 {
        return Err(RepositoryFailure::LimitExceeded);
    }
    let mut policy = LifecyclePolicy {
        current_expiration: false,
        noncurrent_expiration: false,
        transition: false,
        abandoned_upload_expiration: false,
    };
    for rule in rules {
        match rule.status() {
            aws_sdk_s3::types::ExpirationStatus::Disabled => continue,
            aws_sdk_s3::types::ExpirationStatus::Enabled => {},
            _ => return Err(RepositoryFailure::CorruptState),
        }
        let filter = rule.filter();
        // The current API still returns Prefix-only rules created by the older lifecycle API.
        #[allow(
            deprecated,
            reason = "native S3 legacy Prefix-only lifecycle rules remain valid"
        )]
        let legacy_prefix = rule.prefix();
        let prefix = legacy_prefix
            .or_else(|| filter.and_then(|filter| filter.prefix()))
            .or_else(|| {
                filter
                    .and_then(|filter| filter.and())
                    .and_then(|filter| filter.prefix())
            })
            .unwrap_or("");
        if prefix.len() > 1024 || prefix.contains('\0') {
            return Err(RepositoryFailure::CorruptState);
        }
        if !target.starts_with(prefix) && !prefix.starts_with(target) {
            continue;
        }
        policy.current_expiration |= rule.expiration().is_some();
        policy.noncurrent_expiration |= rule.noncurrent_version_expiration().is_some();
        policy.transition |=
            !rule.transitions().is_empty() || !rule.noncurrent_version_transitions().is_empty();
        policy.abandoned_upload_expiration |= rule.abort_incomplete_multipart_upload().is_some();
    }
    Ok(policy)
}
fn observation<T>(result: Result<T, RepositoryFailure>) -> PolicyObservation<T> {
    match result {
        Ok(value) => PolicyObservation::Observed(value),
        Err(failure) => PolicyObservation::Unavailable(failure),
    }
}
impl AwsS3Repository {
    pub async fn storage_policy(&self) -> Result<RepositoryPolicy, RepositoryFailure> {
        let _operation = self.enter()?;
        self.read_identity().await?;
        let versioning = match self
            .client
            .get_bucket_versioning()
            .bucket(self.target.bucket())
            .expected_bucket_owner(self.target.expected_owner())
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
        {
            Ok(response) => versioning(response.status()),
            Err(error) => Err(failure::sdk(error, false)),
        };
        let object_lock = match self
            .client
            .get_object_lock_configuration()
            .bucket(self.target.bucket())
            .expected_bucket_owner(self.target.expected_owner())
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
        {
            Ok(response) => object_lock(response.object_lock_configuration()),
            Err(error)
                if error.as_service_error().is_some_and(|error| {
                    error.code() == Some("ObjectLockConfigurationNotFoundError")
                }) =>
            {
                Ok(ObjectLockPolicy::Disabled)
            },
            Err(error) => Err(failure::sdk(error, false)),
        };
        let lifecycle = match self
            .client
            .get_bucket_lifecycle_configuration()
            .bucket(self.target.bucket())
            .expected_bucket_owner(self.target.expected_owner())
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
        {
            Ok(response) => lifecycle(response.rules(), self.target.prefix()),
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|error| error.code() == Some("NoSuchLifecycleConfiguration")) =>
            {
                lifecycle(&[], self.target.prefix())
            },
            Err(error) => Err(failure::sdk(error, false)),
        };
        Ok(RepositoryPolicy {
            versioning: observation(versioning),
            object_lock: observation(object_lock),
            lifecycle: observation(lifecycle),
            doctor_probe: None,
        })
    }
}
