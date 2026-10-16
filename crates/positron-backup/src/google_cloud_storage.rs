//! Native Google Cloud Storage JSON API v1, with pinned native ADC.
mod deletion;
mod fault;
#[cfg(fuzzing)]
mod fuzzing;
mod http;
mod identity;
mod listing;
mod objects;
mod policy;
mod port;
mod protocol;
#[cfg(feature = "test-support")]
mod qualification;
mod registry;
mod upload;
use crate::{GoogleCloudStorageTarget, RepositoryFailure, RepositoryIdentity};
#[cfg(not(feature = "test-support"))]
use fault::GoogleCloudStorageFaultPoint;
#[cfg(feature = "test-support")]
pub use fault::GoogleCloudStorageFaultPoint;
#[cfg(feature = "test-support")]
pub use fault::{GoogleCloudStorageFault, GoogleCloudStorageFaultEffect};
#[cfg(fuzzing)]
pub use fuzzing::fuzz_google_cloud_storage_repository;
use google_cloud_auth::credentials::Credentials;
use positron_kernel::{
    NativeAwsResources, NativeGoogleRuntime, ResourceAmounts, ResourceDimension,
    ResourceReservation,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
pub struct GoogleCloudStorageRepository {
    target: GoogleCloudStorageTarget,
    identity: RepositoryIdentity,
    credentials: Credentials,
    #[cfg(feature = "test-support")]
    simulation_address: Option<std::net::SocketAddr>,
    runtime: Arc<NativeGoogleRuntime>,
    resources: Arc<NativeAwsResources>,
    active: AtomicBool,
    upload_authenticator: Option<positron_kernel::RepositoryUploadAuthenticator>,
    faults: fault::Controller,
    listing: std::sync::Mutex<crate::listing::native_cursor::State>,
}
struct Operation<'a>(&'a AtomicBool);
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
impl GoogleCloudStorageRepository {
    fn upload_authenticator(
        &self,
    ) -> Result<&positron_kernel::RepositoryUploadAuthenticator, RepositoryFailure> {
        self.upload_authenticator
            .as_ref()
            .ok_or(RepositoryFailure::PermissionDenied)
    }

    #[cfg(feature = "test-support")]
    pub fn with_faults(
        mut self,
        schedule: Vec<GoogleCloudStorageFault>,
    ) -> Result<Self, RepositoryFailure> {
        self.faults = fault::Controller::new(schedule)?;
        Ok(self)
    }
    /// Includes payloads, bounded metadata, ADC, DNS and native connection tasks.
    pub const fn required_resources() -> ResourceAmounts {
        ResourceAmounts::new([256 * 1024 * 1024, 16, 16, 0, 0, 1, 10, 16, 1, 16, 0])
    }
    pub async fn from_application_default(
        target: GoogleCloudStorageTarget,
        identity: RepositoryIdentity,
        reservation: ResourceReservation<'_>,
        upload_authenticator: positron_kernel::RepositoryUploadAuthenticator,
    ) -> Result<Self, RepositoryFailure> {
        if !reservation.is_active() {
            return Err(RepositoryFailure::LimitExceeded);
        }
        Self::from_admitted_resources(
            target,
            identity,
            NativeAwsResources::new(reservation.transfer()),
            upload_authenticator,
        )
        .await
    }
    pub async fn from_admitted_resources(
        target: GoogleCloudStorageTarget,
        identity: RepositoryIdentity,
        resources: Arc<NativeAwsResources>,
        upload_authenticator: positron_kernel::RepositoryUploadAuthenticator,
    ) -> Result<Self, RepositoryFailure> {
        Self::construct(target, identity, resources, Some(upload_authenticator)).await
    }
    /// Opens native reads before SYSTEM recovery, without upload authority.
    pub async fn read_only_from_admitted_resources(
        target: GoogleCloudStorageTarget,
        identity: RepositoryIdentity,
        resources: Arc<NativeAwsResources>,
    ) -> Result<Self, RepositoryFailure> {
        Self::construct(target, identity, resources, None).await
    }
    async fn construct(
        target: GoogleCloudStorageTarget,
        identity: RepositoryIdentity,
        resources: Arc<NativeAwsResources>,
        upload_authenticator: Option<positron_kernel::RepositoryUploadAuthenticator>,
    ) -> Result<Self, RepositoryFailure> {
        if upload_authenticator
            .as_ref()
            .is_some_and(|authority| authority.instance_id() != identity.instance_id())
            || identity.provider_kind() != "googleCloudStorage"
            || identity.prefix_commitment() != target.commitment()
        {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        if ResourceDimension::ALL
            .iter()
            .any(|d| resources.granted().get(*d) < Self::required_resources().get(*d))
        {
            return Err(RepositoryFailure::LimitExceeded);
        }
        if !resources.authorizes_repository_transport() {
            return Err(RepositoryFailure::PermissionDenied);
        }
        tokio::runtime::Handle::try_current().map_err(|_| RepositoryFailure::InvalidInput)?;
        let runtime = NativeGoogleRuntime::from_resources(resources.clone())
            .map_err(|_| RepositoryFailure::StorageUnavailable)?;
        let credentials =
            tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
                google_cloud_auth::credentials::Builder::default()
                    .with_native_runtime(runtime.clone())
                    .with_scopes(["https://www.googleapis.com/auth/devstorage.read_write"])
                    .build()
            })
            .map_err(|_| RepositoryFailure::InvalidInput)?;
        Ok(Self {
            target,
            identity,
            credentials,
            #[cfg(feature = "test-support")]
            simulation_address: None,
            runtime,
            resources,
            upload_authenticator,
            faults: Default::default(),
            active: AtomicBool::new(false),
            listing: std::sync::Mutex::new(crate::listing::native_cursor::State::new()?),
        })
    }
    /// A loopback-only protocol simulator. Never discovers ADC or sends credentials.
    #[cfg(feature = "test-support")]
    pub fn from_local_simulator(
        target: GoogleCloudStorageTarget,
        identity: RepositoryIdentity,
        resources: Arc<NativeAwsResources>,
        upload_authenticator: positron_kernel::RepositoryUploadAuthenticator,
        address: std::net::SocketAddr,
    ) -> Result<Self, RepositoryFailure> {
        Self::simulator(
            target,
            identity,
            resources,
            Some(upload_authenticator),
            address,
        )
    }
    #[cfg(feature = "test-support")]
    pub fn read_only_from_local_simulator(
        target: GoogleCloudStorageTarget,
        identity: RepositoryIdentity,
        resources: Arc<NativeAwsResources>,
        address: std::net::SocketAddr,
    ) -> Result<Self, RepositoryFailure> {
        Self::simulator(target, identity, resources, None, address)
    }
    #[cfg(feature = "test-support")]
    fn simulator(
        target: GoogleCloudStorageTarget,
        identity: RepositoryIdentity,
        resources: Arc<NativeAwsResources>,
        upload_authenticator: Option<positron_kernel::RepositoryUploadAuthenticator>,
        address: std::net::SocketAddr,
    ) -> Result<Self, RepositoryFailure> {
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(RepositoryFailure::InvalidInput);
        }
        if upload_authenticator
            .as_ref()
            .is_some_and(|authority| authority.instance_id() != identity.instance_id())
            || identity.provider_kind() != "googleCloudStorage"
            || identity.prefix_commitment() != target.commitment()
        {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        if ResourceDimension::ALL
            .iter()
            .any(|d| resources.granted().get(*d) < Self::required_resources().get(*d))
        {
            return Err(RepositoryFailure::LimitExceeded);
        }
        if !resources.authorizes_repository_transport() {
            return Err(RepositoryFailure::PermissionDenied);
        }
        let runtime = NativeGoogleRuntime::from_resources(resources.clone())
            .map_err(|_| RepositoryFailure::StorageUnavailable)?;
        Ok(Self {
            target,
            identity,
            resources,
            runtime,
            upload_authenticator,
            credentials: google_cloud_auth::credentials::anonymous::Builder::new().build(),
            simulation_address: Some(address),
            active: AtomicBool::new(false),
            faults: Default::default(),
            listing: std::sync::Mutex::new(crate::listing::native_cursor::State::new()?),
        })
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
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_response_preserves_bounded_throttling_feedback_without_error_body() {
        let mut headers = ::http::HeaderMap::new();
        headers.insert(
            ::http::header::RETRY_AFTER,
            ::http::HeaderValue::from_static("30"),
        );
        let mut response = google_cloud_auth::native::Response {
            status: ::http::StatusCode::TOO_MANY_REQUESTS,
            headers,
            body: zeroize::Zeroizing::new(b"private native error body".to_vec()),
        };
        assert_eq!(
            self::http::response_failure(&response, true),
            RepositoryFailure::Throttled {
                retry_after_millis: 30000
            }
        );
        response.headers.insert(
            ::http::header::RETRY_AFTER,
            ::http::HeaderValue::from_static("999999999"),
        );
        assert_eq!(
            self::http::response_failure(&response, true),
            RepositoryFailure::Throttled {
                retry_after_millis: 60000
            }
        );
        response.headers.insert(
            ::http::header::RETRY_AFTER,
            ::http::HeaderValue::from_static("invalid"),
        );
        assert_eq!(
            self::http::response_failure(&response, true),
            RepositoryFailure::Throttled {
                retry_after_millis: 1000
            }
        );
        response.status = ::http::StatusCode::SERVICE_UNAVAILABLE;
        assert_eq!(
            self::http::response_failure(&response, true),
            RepositoryFailure::OutcomeUnknown
        );
        assert_eq!(
            self::http::response_failure(&response, false),
            RepositoryFailure::StorageUnavailable
        );
    }
    #[test]
    fn native_status_is_closed_and_never_exposes_error_body() {
        assert_eq!(
            protocol::status(403, false, Some("10")),
            RepositoryFailure::PermissionDenied
        );
        assert_eq!(
            protocol::status(429, true, Some("999999999999")),
            RepositoryFailure::Throttled {
                retry_after_millis: 60000
            }
        );
        assert_eq!(
            protocol::status(503, true, None),
            RepositoryFailure::OutcomeUnknown
        );
        assert_eq!(
            protocol::status(503, false, None),
            RepositoryFailure::StorageUnavailable
        );
        assert_eq!(
            protocol::status(412, true, None),
            RepositoryFailure::PreconditionFailed
        );
    }
    #[test]
    fn bucket_identity_and_native_crc_are_verified() {
        let target = GoogleCloudStorageTarget::new(
            "positron-backup",
            "123456789012",
            "US-CENTRAL1",
            "owned/",
        )
        .expect("target");
        let bucket = br#"{"name":"positron-backup","projectNumber":"123456789012","location":"US-CENTRAL1"}"#;
        assert!(protocol::bucket(bucket, &target).is_ok());
        let wrong = br#"{"name":"positron-backup","projectNumber":"7","location":"US-CENTRAL1"}"#;
        assert_eq!(
            protocol::bucket(wrong, &target).err(),
            Some(RepositoryFailure::IdentityMismatch)
        );
        let native =
            br#"{"name":"owned/o-test","generation":"123","metageneration":"1","size":"9","crc32c":"4waSgw=="}"#;
        let metadata = protocol::metadata(native, "owned/o-test").expect("metadata");
        assert_eq!(metadata.metageneration, 1);
        assert_eq!(metadata.verify(b"123456789"), Ok(()));
        assert_eq!(
            metadata.verify(b"123456788"),
            Err(RepositoryFailure::ChecksumMismatch)
        );
        assert!(protocol::metadata(native, "owned/foreign").is_err());
    }
    #[test]
    fn native_range_and_generation_reject_ambiguous_extent() {
        assert_eq!(protocol::range(Some("bytes 5-7/12"), 5, 3, 12, 3), Ok(()));
        assert_eq!(
            protocol::range(Some("bytes 0-2/12"), 5, 3, 12, 3),
            Err(RepositoryFailure::CorruptState)
        );
        assert_eq!(
            protocol::range(None, 5, 3, 12, 3),
            Err(RepositoryFailure::CorruptState)
        );
        assert_eq!(
            protocol::range(Some("bytes 5-7/12"), 5, 3, 12, 2),
            Err(RepositoryFailure::CorruptState)
        );
    }
    #[test]
    fn resumable_state_binds_target_payload_and_creation_without_exposing_session() {
        let plan = crate::UploadPlan::new(
            crate::ImmutableObject::new(b"encrypted backup".to_vec())
                .expect("object")
                .id(),
            16,
        )
        .expect("plan");
        let record = upload::Record::new(plan, [9; 16]);
        let frame = record.encode([1; 32]);
        let decoded = upload::Record::decode(frame.clone(), [1; 32], plan.id()).expect("decode");
        assert_eq!(decoded.state(), record.state());
        assert!(upload::Record::decode(frame.clone(), [2; 32], plan.id()).is_err());
        let mut corrupted = frame;
        *corrupted.last_mut().expect("checksum") ^= 1;
        assert!(upload::Record::decode(corrupted, [1; 32], plan.id()).is_err());
    }
    #[test]
    fn resumable_acknowledgement_and_session_authority_are_exact() {
        assert_eq!(protocol::uploaded(None, 16), Ok(0));
        assert_eq!(protocol::uploaded(Some("bytes=0-7"), 16), Ok(8));
        assert!(protocol::uploaded(Some("bytes=1-7"), 16).is_err());
        assert!(protocol::uploaded(Some("bytes=0-16"), 16).is_err());
        assert!(protocol::session("https://storage.googleapis.com/upload/storage/v1/b/positron-backup/o?uploadType=resumable&upload_id=opaque", "positron-backup").is_ok());
        assert!(protocol::session("http://storage.googleapis.com/upload/storage/v1/b/positron-backup/o?upload_id=opaque", "positron-backup").is_err());
        assert!(
            protocol::session(
                "https://storage.googleapis.com/upload/storage/v1/b/foreign/o?upload_id=opaque",
                "positron-backup"
            )
            .is_err()
        );
    }
    #[test]
    fn native_retention_seconds_and_soft_delete_are_preserved() {
        let value=protocol::json(br#"{"versioning":{"enabled":true},"retentionPolicy":{"retentionPeriod":"3600","isLocked":true},"softDeletePolicy":{"retentionDurationSeconds":"604800"},"lifecycle":{"rule":[{"action":{"type":"Delete"},"condition":{"isLive":false}}]}}"#).expect("json");
        let policy = protocol::policy(&value);
        assert_eq!(
            policy.soft_delete,
            Some(crate::PolicyObservation::Observed(604800))
        );
        assert_eq!(
            policy.object_lock,
            crate::PolicyObservation::Observed(crate::ObjectLockPolicy::Enabled {
                default_retention: Some(crate::RetentionPolicy {
                    mode: crate::RetentionMode::Compliance,
                    period: crate::RetentionPeriod::Seconds(3600)
                })
            })
        );
        assert_eq!(
            policy.lifecycle,
            crate::PolicyObservation::Observed(crate::LifecyclePolicy {
                current_expiration: false,
                noncurrent_expiration: true,
                transition: false,
                abandoned_upload_expiration: false
            })
        );
        let enabled = protocol::json(br#"{"objectRetention":{"mode":"Enabled"}}"#).expect("bucket");
        assert_eq!(
            protocol::policy(&enabled).object_lock,
            crate::PolicyObservation::Observed(crate::ObjectLockPolicy::Enabled {
                default_retention: None
            })
        );
        let value=protocol::metadata(br#"{"name":"owned/o-test","generation":"1","metageneration":"1","size":"9","crc32c":"4waSgw==","retention":{"mode":"Unlocked","retainUntilTime":"2030-01-01T00:00:00Z"},"retentionExpirationTime":"2031-01-01T00:00:00Z"}"#,"owned/o-test").expect("retention metadata");
        assert_eq!(
            value.protection.retention,
            crate::PolicyObservation::Observed(crate::ObjectRetention {
                mode: crate::RetentionMode::ProviderEnforced,
                retain_until_unix_seconds: 1924992000
            })
        );
    }
    #[test]
    fn fractional_native_retention_deadline_is_not_understated() {
        let value = protocol::metadata(br#"{"name":"owned/o-test","generation":"1","metageneration":"1","size":"9","crc32c":"4waSgw==","retentionExpirationTime":"2031-01-01T00:00:00.001Z"}"#, "owned/o-test").expect("metadata");
        assert_eq!(
            value.protection.retention,
            crate::PolicyObservation::Observed(crate::ObjectRetention {
                mode: crate::RetentionMode::ProviderEnforced,
                retain_until_unix_seconds: 1924992001
            })
        );
    }
    #[test]
    fn native_upload_authority_rejects_rewritten_session_frames() {
        let custody = positron_kernel::RepositoryUploadAuthenticator::new(
            positron_kernel::CatalogSecret::from_owned(Box::new([31; 32]), Box::new([32; 32])),
            positron_kernel::InstanceId::new([2; 16]).expect("instance"),
        );
        let authentication = custody.authenticate([1; 32]).expect("authenticate");
        assert!(custody.verify([1; 32], authentication).is_ok());
        assert!(custody.verify([2; 32], authentication).is_err());
        let secret = b"https://storage.googleapis.com/upload/native-secret";
        let sealed = custody.seal_session(secret).expect("seal");
        assert!(!sealed.windows(secret.len()).any(|window| window == secret));
        assert_eq!(
            custody.open_session(&sealed).expect("open").as_slice(),
            secret
        );
        let other = positron_kernel::RepositoryUploadAuthenticator::new(
            positron_kernel::CatalogSecret::from_owned(Box::new([31; 32]), Box::new([32; 32])),
            positron_kernel::InstanceId::new([3; 16]).expect("other instance"),
        );
        assert!(other.open_session(&sealed).is_err());
        assert!(custody.seal_session(&vec![1; 3073]).is_err());
        let mut altered = sealed;
        *altered.last_mut().expect("tag") ^= 1;
        assert!(custody.open_session(&altered).is_err());
    }
}
