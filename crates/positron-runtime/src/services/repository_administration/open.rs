//! Native Repository opening retains the existing admitted transport and upload custody.
use super::*;
use positron_backup::{LocalRepository, Repository, RepositoryFailure, RepositoryIdentity};
use std::sync::Arc;
pub(in crate::services) async fn open(
    services: &ServiceHandle,
    parameters: RepositoryOperationParameters,
    native_resources: Option<Arc<positron_kernel::NativeAwsResources>>,
) -> Result<(RepositoryIdentity, Box<dyn Repository>), RepositoryFailure> {
    let (identity, repository): (RepositoryIdentity, Box<dyn Repository>) =
        match parameters.provider_kind() {
            positron_governance::RepositoryProviderKind::LocalFilesystem => {
                let path = Path::new(
                    parameters
                        .locator()
                        .map_err(|_| RepositoryFailure::CorruptState)?,
                );
                let identity = RepositoryIdentity::local(
                    parameters.repository_id(),
                    services.instance.instance.to_bytes(),
                    parameters.integrity_fingerprint(),
                    path,
                )?;
                if identity.prefix_commitment() != parameters.prefix_commitment() {
                    return Err(RepositoryFailure::IdentityMismatch);
                }
                let repository = match parameters.action() {
                    RepositoryAction::Initialize => {
                        match LocalRepository::attach(path, &identity).await {
                            Ok(repository) => repository,
                            Err(RepositoryFailure::NotFound) => {
                                LocalRepository::initialize(path, identity.clone()).await?
                            },
                            Err(failure) => return Err(failure),
                        }
                    },
                    RepositoryAction::Verify | RepositoryAction::Doctor => {
                        LocalRepository::attach(path, &identity).await?
                    },
                };
                (identity, Box::new(repository))
            },
            positron_governance::RepositoryProviderKind::AwsS3 => {
                let target = positron_backup::AwsS3Target::decode_locator(
                    parameters
                        .locator()
                        .map_err(|_| RepositoryFailure::CorruptState)?,
                )?;
                let identity = RepositoryIdentity::aws_s3(
                    parameters.repository_id(),
                    services.instance.instance.to_bytes(),
                    parameters.integrity_fingerprint(),
                    &target,
                )?;
                if identity.prefix_commitment() != parameters.prefix_commitment() {
                    return Err(RepositoryFailure::IdentityMismatch);
                }
                let repository = positron_backup::AwsS3Repository::from_admitted_resources(
                    target,
                    identity.clone(),
                    native_resources.ok_or(RepositoryFailure::PermissionDenied)?,
                )
                .await?;
                match parameters.action() {
                    RepositoryAction::Initialize => {
                        repository.initialize().await?;
                    },
                    RepositoryAction::Verify | RepositoryAction::Doctor => {
                        repository.attach().await?;
                    },
                }
                (identity, Box::new(repository))
            },
            positron_governance::RepositoryProviderKind::GoogleCloudStorage => {
                let target = positron_backup::GoogleCloudStorageTarget::decode_locator(
                    parameters
                        .locator()
                        .map_err(|_| RepositoryFailure::CorruptState)?,
                )?;
                let identity = RepositoryIdentity::google_cloud_storage(
                    parameters.repository_id(),
                    services.instance.instance.to_bytes(),
                    parameters.integrity_fingerprint(),
                    &target,
                )?;
                if identity.prefix_commitment() != parameters.prefix_commitment() {
                    return Err(RepositoryFailure::IdentityMismatch);
                }
                let repository =
                    positron_backup::GoogleCloudStorageRepository::from_admitted_resources(
                        target,
                        identity.clone(),
                        native_resources.ok_or(RepositoryFailure::PermissionDenied)?,
                        positron_kernel::RepositoryUploadAuthenticator::new(
                            services
                                .instance
                                .key
                                .catalog_secret(services.instance.instance)
                                .map_err(|_| RepositoryFailure::StorageUnavailable)?,
                            services.instance.instance,
                        ),
                    )
                    .await?;
                match parameters.action() {
                    RepositoryAction::Initialize => {
                        repository.initialize().await?;
                    },
                    RepositoryAction::Verify | RepositoryAction::Doctor => {
                        repository.attach().await?;
                    },
                }
                (identity, Box::new(repository))
            },
            positron_governance::RepositoryProviderKind::AzureBlob => {
                let target = positron_backup::AzureBlobTarget::decode_locator(
                    parameters
                        .locator()
                        .map_err(|_| RepositoryFailure::CorruptState)?,
                )?;
                let identity = RepositoryIdentity::azure_blob(
                    parameters.repository_id(),
                    services.instance.instance.to_bytes(),
                    parameters.integrity_fingerprint(),
                    &target,
                )?;
                if identity.prefix_commitment() != parameters.prefix_commitment() {
                    return Err(RepositoryFailure::IdentityMismatch);
                }
                let repository = positron_backup::AzureBlobRepository::from_admitted_resources(
                    target,
                    identity.clone(),
                    native_resources.ok_or(RepositoryFailure::PermissionDenied)?,
                    positron_kernel::RepositoryUploadAuthenticator::new(
                        services
                            .instance
                            .key
                            .catalog_secret(services.instance.instance)
                            .map_err(|_| RepositoryFailure::StorageUnavailable)?,
                        services.instance.instance,
                    ),
                )
                .await?;
                match parameters.action() {
                    RepositoryAction::Initialize => {
                        repository.initialize().await?;
                    },
                    RepositoryAction::Verify | RepositoryAction::Doctor => {
                        repository.attach().await?;
                    },
                }
                (identity, Box::new(repository))
            },
        };
    if repository.identify().await? != identity {
        return Err(RepositoryFailure::IdentityMismatch);
    }
    Ok((identity, repository))
}
