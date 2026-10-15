//! AWS S3 API 2006-03-01, using its native SDK and renewable workload identity.
mod failure;
mod fault;
#[cfg(feature = "test-support")]
mod simulation;
#[cfg(not(feature = "test-support"))]
use fault::AwsS3FaultPoint;
#[cfg(feature = "test-support")]
pub use fault::{AwsS3Fault, AwsS3FaultEffect, AwsS3FaultPoint};
mod deletion;
#[cfg(fuzzing)]
mod fuzzing;
mod http;
mod identity;
mod listing;
mod objects;
mod policy;
mod port;
mod registry;
mod upload;
use crate::{AwsS3Target, RepositoryFailure, RepositoryIdentity};
#[cfg(fuzzing)]
pub use fuzzing::fuzz_aws_s3_repository;
#[cfg(feature = "test-support")]
mod qualification;

#[cfg(test)]
use objects::{validate_object, validate_range_response};
use positron_kernel::{
    NativeAwsCredentialProcessAdmission, NativeAwsDns, NativeAwsResources, ResourceAmounts,
    ResourceDimension, ResourceReservation,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tracing::instrument::WithSubscriber;

pub struct AwsS3Repository {
    client: aws_sdk_s3::Client,
    target: AwsS3Target,
    identity: RepositoryIdentity,
    resources: Arc<NativeAwsResources>,
    active: AtomicBool,
    listing: std::sync::Mutex<listing::State>,
    faults: fault::Controller,
}

struct Operation<'a>(&'a AtomicBool);
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
fn validate_bucket_region(
    target: &AwsS3Target,
    region: Option<&str>,
) -> Result<(), RepositoryFailure> {
    if region == Some(target.region()) {
        Ok(())
    } else {
        Err(RepositoryFailure::IdentityMismatch)
    }
}
impl AwsS3Repository {
    #[cfg(feature = "test-support")]
    pub fn with_faults(mut self, schedule: Vec<AwsS3Fault>) -> Result<Self, RepositoryFailure> {
        self.faults = fault::Controller::new(schedule)?;
        Ok(self)
    }
    fn enter(&self) -> Result<Operation<'_>, RepositoryFailure> {
        if self.resources.busy()
            || self
                .active
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err(RepositoryFailure::Busy);
        }
        Ok(Operation(&self.active))
    }
    /// Includes bounded object/staging buffers, native TLS, DNS, and credential refresh.
    pub const fn required_resources() -> ResourceAmounts {
        ResourceAmounts::new([256 * 1024 * 1024, 1, 4, 0, 0, 1, 2, 4, 1, 8, 0])
    }
    /// Installs the standard chain; only an admitted operation resolves credentials.
    pub async fn from_standard_chain(
        target: AwsS3Target,
        identity: RepositoryIdentity,
        reservation: ResourceReservation<'_>,
    ) -> Result<Self, RepositoryFailure> {
        if identity.provider_kind() != "awsS3"
            || identity.prefix_commitment() != target.commitment()
        {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        if !reservation.is_active()
            || ResourceDimension::ALL.iter().any(|dimension| {
                reservation.granted().get(*dimension) < Self::required_resources().get(*dimension)
            })
        {
            return Err(RepositoryFailure::LimitExceeded);
        }
        Self::from_admitted_resources(
            target,
            identity,
            NativeAwsResources::new(reservation.transfer()),
        )
        .await
    }
    /// Uses the same peak grant retained by the exact bound Maintenance execution.
    pub async fn from_admitted_resources(
        target: AwsS3Target,
        identity: RepositoryIdentity,
        resources: Arc<NativeAwsResources>,
    ) -> Result<Self, RepositoryFailure> {
        if identity.provider_kind() != "awsS3"
            || identity.prefix_commitment() != target.commitment()
        {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        if ResourceDimension::ALL.iter().any(|dimension| {
            resources.granted().get(*dimension) < Self::required_resources().get(*dimension)
        }) {
            return Err(RepositoryFailure::LimitExceeded);
        }
        if !resources.authorizes_repository_transport() {
            return Err(RepositoryFailure::PermissionDenied);
        }

        let dns = NativeAwsDns::new(resources.clone());
        let http = aws_smithy_http_client::Builder::new()
            .pool_max_idle_per_host(1)
            .pool_idle_timeout(Duration::from_secs(5))
            .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
                aws_smithy_http_client::tls::rustls_provider::CryptoMode::Ring,
            ))
            .build_with_resolver(dns.clone());
        let http = http::BoundedClient::new(http, resources.clone(), &target);
        let timeout = aws_smithy_types::timeout::TimeoutConfig::builder()
            .connect_timeout(Duration::from_secs(2))
            .read_timeout(Duration::from_secs(5))
            .operation_attempt_timeout(Duration::from_secs(15))
            .operation_timeout(Duration::from_secs(15))
            .build();
        let retry = aws_smithy_types::retry::RetryConfig::standard().with_max_attempts(1);
        let behavior = aws_config::BehaviorVersion::v2026_01_12();
        let region = aws_sdk_s3::config::Region::new(target.region().to_owned());
        let provider_config = aws_config::provider_config::ProviderConfig::without_region()
            .with_region(Some(region.clone()))
            .with_behavior_version(Some(behavior))
            .with_dns_resolver(dns)
            .with_http_client(http.clone())
            .with_credential_process_admission(Arc::new(NativeAwsCredentialProcessAdmission::new(
                resources.clone(),
            )))
            .with_retry_config(retry.clone())
            .with_timeout_config(timeout.clone());
        let credentials =
            aws_config::default_provider::credentials::DefaultCredentialsChain::builder()
                .region(region.clone())
                .configure(provider_config)
                .build()
                .with_subscriber(tracing::subscriber::NoSubscriber::default())
                .await;
        let config = aws_sdk_s3::config::Builder::new()
            .behavior_version(behavior)
            .region(region)
            .endpoint_url(target.endpoint())
            .force_path_style(true)
            .disable_multi_region_access_points(true)
            .identity_cache(aws_sdk_s3::config::IdentityCache::no_cache())
            .credentials_provider(credentials)
            .http_client(http)
            .retry_config(retry)
            .timeout_config(timeout)
            .build();
        Ok(Self {
            client: aws_sdk_s3::Client::from_conf(config),
            target,
            identity,
            resources,
            active: AtomicBool::new(false),
            listing: std::sync::Mutex::new(listing::State::new()?),
            faults: Default::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_bucket_region_must_match_exact_target() {
        let target = AwsS3Target::new(
            "positron-backup",
            "us-east-1",
            "https://s3.us-east-1.amazonaws.com",
            "123456789012",
            "owned/",
        )
        .expect("target");
        assert_eq!(validate_bucket_region(&target, Some("us-east-1")), Ok(()));
        assert_eq!(
            validate_bucket_region(&target, Some("us-west-2")),
            Err(RepositoryFailure::IdentityMismatch)
        );
        assert_eq!(
            validate_bucket_region(&target, None),
            Err(RepositoryFailure::IdentityMismatch)
        );
    }
}

#[cfg(test)]
mod object_tests {
    use super::*;
    use crate::ImmutableObject;
    #[test]
    fn native_object_content_must_match_committed_checksum() {
        let object = ImmutableObject::new(b"encrypted backup object".to_vec()).expect("object");
        assert_eq!(validate_object(object.id(), object.bytes()), Ok(()));
        assert_eq!(
            validate_object(object.id(), b"modified backup object"),
            Err(RepositoryFailure::ChecksumMismatch)
        );
    }
}

#[cfg(test)]
mod range_tests {
    use super::*;
    use crate::{ObjectId, ObjectRange};
    #[test]
    fn native_range_requires_exact_bounded_response_extent() {
        let range = ObjectRange::new(ObjectId::from_checksum([1; 32]), 5, 3).expect("range");
        assert_eq!(
            validate_range_response(range, 12, Some("bytes 5-7/12"), 3),
            Ok(())
        );
        assert_eq!(
            validate_range_response(range, 12, Some("bytes 0-2/12"), 3),
            Err(RepositoryFailure::CorruptState)
        );
        assert_eq!(
            validate_range_response(range, 12, None, 3),
            Err(RepositoryFailure::CorruptState)
        );
        assert_eq!(
            validate_range_response(range, 12, Some("bytes 5-7/12"), 4),
            Err(RepositoryFailure::CorruptState)
        );
    }
}

#[cfg(test)]
mod upload_tests {
    use super::*;
    use crate::{ImmutableObject, UploadPlan};
    #[test]
    fn native_upload_record_binds_plan_target_and_partial_checksum() {
        let target = AwsS3Target::new(
            "positron-backup",
            "us-east-1",
            "https://s3.us-east-1.amazonaws.com",
            "123456789012",
            "owned/",
        )
        .expect("target");
        let object = ImmutableObject::new(b"encrypted upload".to_vec()).expect("object");
        let plan = UploadPlan::new(object.id(), object.bytes().len() as u64).expect("plan");
        let record = upload::Record::new(plan, b"encrypted".to_vec(), None).expect("record");
        let frame = record.encode(target.commitment());
        let reopened =
            upload::Record::decode(&frame, target.commitment(), plan.id()).expect("decode");
        assert_eq!(reopened.state(), record.state());
        assert!(matches!(
            upload::Record::decode(&frame, [3; 32], plan.id()),
            Err(RepositoryFailure::IdentityMismatch)
        ));
        let mut changed = frame;
        *changed.last_mut().expect("payload") ^= 1;
        assert!(matches!(
            upload::Record::decode(&changed, target.commitment(), plan.id()),
            Err(RepositoryFailure::ChecksumMismatch)
        ));
    }
}

#[cfg(test)]
mod version_tests {
    use super::*;
    #[test]
    fn version_inventory_never_authorizes_foreign_keys_or_unbounded_ids() {
        assert_eq!(
            deletion::owned_version_id(Some("owned/key-other"), Some("version"), "owned/key"),
            Ok(None)
        );
        assert_eq!(
            deletion::owned_version_id(Some("owned/key"), Some("version"), "owned/key"),
            Ok(Some("version".to_owned()))
        );
        assert_eq!(
            deletion::owned_version_id(Some("owned/key"), None, "owned/key"),
            Err(RepositoryFailure::CorruptState)
        );
        assert_eq!(
            deletion::owned_version_id(Some("owned/key"), Some("unsafe\nversion"), "owned/key"),
            Err(RepositoryFailure::CorruptState)
        );
    }
}

#[cfg(test)]
mod upload_replay_tests {
    use super::*;
    use crate::{ImmutableObject, UploadPart, UploadPlan};
    #[test]
    fn replayed_upload_parts_preserve_committed_prefix_and_reject_drift() {
        let object = ImmutableObject::new(b"encrypted upload".to_vec()).expect("object");
        let plan = UploadPlan::new(object.id(), object.bytes().len() as u64).expect("plan");
        let prefix = upload::Record::new(plan, b"encrypted".to_vec(), None).expect("prefix");
        let part = UploadPart::new(prefix.state(), b" upload".to_vec()).expect("part");
        let completed = prefix.apply(&part).expect("apply").expect("new content");
        assert!(completed.state().complete());
        assert!(completed.apply(&part).expect("replay").is_none());
        let different = UploadPart::new(prefix.state(), b" change".to_vec()).expect("part");
        assert!(matches!(
            completed.apply(&different),
            Err(RepositoryFailure::PreconditionFailed)
        ));
    }
}

#[cfg(test)]
mod listing_tests {
    use super::*;
    use crate::{ListKind, ListRequest};
    #[test]
    fn native_continuation_is_bound_to_owner_kind_and_single_use() {
        let mut first = listing::State::new().expect("state");
        let mut other = listing::State::new().expect("state");
        let cursor = first
            .store([1; 16], ListKind::Objects, "native-continuation".to_owned())
            .expect("store");
        let request =
            ListRequest::new(ListKind::Objects, Some(cursor.clone()), 1).expect("request");
        assert_eq!(
            other.take([1; 16], &request),
            Err(RepositoryFailure::InvalidInput)
        );
        assert_eq!(
            first.take(
                [1; 16],
                &ListRequest::new(ListKind::Uploads, Some(cursor.clone()), 1).expect("request")
            ),
            Err(RepositoryFailure::InvalidInput)
        );
        assert_eq!(
            first.take([1; 16], &request),
            Ok(Some("native-continuation".to_owned()))
        );
        assert_eq!(
            first.take([1; 16], &request),
            Ok(Some("native-continuation".to_owned()))
        );
        first
            .consume([1; 16], &request)
            .expect("successful response");
        assert_eq!(
            first.take([1; 16], &request),
            Err(RepositoryFailure::InvalidInput)
        );
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    #[test]
    fn native_versioning_observation_rejects_unknown_provider_state() {
        use aws_sdk_s3::types::BucketVersioningStatus;
        assert_eq!(
            policy::versioning(None),
            Ok(crate::VersioningPolicy::Disabled)
        );
        assert_eq!(
            policy::versioning(Some(&BucketVersioningStatus::Enabled)),
            Ok(crate::VersioningPolicy::Enabled)
        );
        assert_eq!(
            policy::versioning(Some(&BucketVersioningStatus::Suspended)),
            Ok(crate::VersioningPolicy::Suspended)
        );
        assert_eq!(
            policy::versioning(Some(&BucketVersioningStatus::from("future-state"))),
            Err(RepositoryFailure::CorruptState)
        );
    }
}

#[cfg(test)]
mod lifecycle_policy_tests {
    use super::*;
    #[test]
    fn native_lifecycle_observation_is_scoped_to_the_selected_prefix() {
        use aws_sdk_s3::types::{
            ExpirationStatus, LifecycleExpiration, LifecycleRule, LifecycleRuleFilter,
        };
        let rule = LifecycleRule::builder()
            .status(ExpirationStatus::Enabled)
            .filter(
                LifecycleRuleFilter::builder()
                    .prefix("another-instance/")
                    .build(),
            )
            .expiration(LifecycleExpiration::builder().days(1).build())
            .build()
            .expect("rule");
        assert!(
            !policy::lifecycle(std::slice::from_ref(&rule), "owned/")
                .expect("policy")
                .current_expiration
        );
        assert!(
            policy::lifecycle(std::slice::from_ref(&rule), "another-instance/")
                .expect("policy")
                .current_expiration
        );
    }
}
