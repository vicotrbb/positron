//! Native Azure Blob REST 2023-11-03 Repository adapter.
mod deletion;
mod http;
mod listing;
mod objects;
mod port;
mod protocol;
mod registry;
mod upload;
use crate::*;
use positron_kernel::{
    NativeAwsResources, NativeAzureRepositoryRuntime, ResourceAmounts, ResourceDimension,
    ResourceReservation,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
pub struct AzureBlobRepository {
    target: AzureBlobTarget,
    identity: RepositoryIdentity,
    runtime: NativeAzureRepositoryRuntime,
    resources: Arc<NativeAwsResources>,
    upload_authenticator: positron_kernel::RepositoryUploadAuthenticator,
    active: AtomicBool,
    listing: std::sync::Mutex<crate::listing::native_cursor::State>,
}
struct Operation<'a>(&'a AtomicBool);
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
impl AzureBlobRepository {
    pub const fn required_resources() -> ResourceAmounts {
        ResourceAmounts::new([256 * 1024 * 1024, 16, 16, 0, 0, 1, 10, 16, 1, 16, 0])
    }
    pub async fn from_managed_identity(
        target: AzureBlobTarget,
        identity: RepositoryIdentity,
        reservation: ResourceReservation<'_>,
        custody: positron_kernel::RepositoryUploadAuthenticator,
    ) -> Result<Self, RepositoryFailure> {
        if !reservation.is_active() {
            return Err(RepositoryFailure::LimitExceeded);
        }
        Self::from_admitted_resources(
            target,
            identity,
            NativeAwsResources::new(reservation.transfer()),
            custody,
        )
        .await
    }
    fn validate(
        target: &AzureBlobTarget,
        identity: &RepositoryIdentity,
        resources: &NativeAwsResources,
        custody: &positron_kernel::RepositoryUploadAuthenticator,
    ) -> Result<(), RepositoryFailure> {
        if custody.instance_id() != identity.instance_id()
            || identity.provider_kind() != "azureBlob"
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
        Ok(())
    }
    pub async fn from_admitted_resources(
        target: AzureBlobTarget,
        identity: RepositoryIdentity,
        resources: Arc<NativeAwsResources>,
        custody: positron_kernel::RepositoryUploadAuthenticator,
    ) -> Result<Self, RepositoryFailure> {
        Self::validate(&target, &identity, &resources, &custody)?;
        let runtime = NativeAzureRepositoryRuntime::from_resources(
            resources.clone(),
            target.account(),
            target.container(),
        )
        .map_err(|_| RepositoryFailure::PermissionDenied)?;
        Self::new(target, identity, resources, custody, runtime)
    }
    #[cfg(feature = "test-support")]
    pub fn from_local_simulator(
        target: AzureBlobTarget,
        identity: RepositoryIdentity,
        resources: Arc<NativeAwsResources>,
        custody: positron_kernel::RepositoryUploadAuthenticator,
        address: std::net::SocketAddr,
    ) -> Result<Self, RepositoryFailure> {
        Self::validate(&target, &identity, &resources, &custody)?;
        let runtime = NativeAzureRepositoryRuntime::from_local_simulator(
            resources.clone(),
            target.account(),
            target.container(),
            address,
        )
        .map_err(|_| RepositoryFailure::InvalidInput)?;
        Self::new(target, identity, resources, custody, runtime)
    }
    fn new(
        target: AzureBlobTarget,
        identity: RepositoryIdentity,
        resources: Arc<NativeAwsResources>,
        upload_authenticator: positron_kernel::RepositoryUploadAuthenticator,
        runtime: NativeAzureRepositoryRuntime,
    ) -> Result<Self, RepositoryFailure> {
        Ok(Self {
            target,
            identity,
            resources,
            upload_authenticator,
            runtime,
            active: AtomicBool::new(false),
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

#[cfg(fuzzing)]
pub fn fuzz_azure_blob_repository(data: &[u8]) {
    let _ = protocol::xml(data);
    upload::fuzz_frame(data);
    let _ = RepositoryIdentity::decode(data);
    if let Ok(value) = std::str::from_utf8(data) {
        let _ = AzureBlobTarget::decode_locator(value);
    }
}
