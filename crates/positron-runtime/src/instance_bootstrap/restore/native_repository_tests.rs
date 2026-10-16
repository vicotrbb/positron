//! Actual native JSON API adapter composed with Runtime restore admission.
use super::*;
use positron_backup::*;
use positron_kernel::{
    BootstrapKeyCustody, BootstrapObjectPurpose, InstanceId, RepositoryUploadAuthenticator,
};
use std::{fs, os::unix::fs::PermissionsExt};
#[path = "../../../../positron-backup/tests/shared/native_authority.rs"]
mod native_authority;
#[path = "../../../../positron-backup/tests/shared/google_simulator.rs"]
mod simulator;

#[test]
fn native_repository_restore_demand_covers_simultaneous_reader_and_transport()
-> Result<(), Box<dyn std::error::Error>> {
    let root = fs::canonicalize(std::env::temp_dir())?.join(format!(
        "positron-restore-native-reader-{}",
        std::process::id()
    ));
    fs::create_dir(&root)?;
    for name in ["data", "secrets"] {
        fs::create_dir(root.join(name))?;
        fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700))?;
    }
    let server = simulator::Server::start()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    {
        let instance = InstanceId::new([2; 16])?;
        let custody = BootstrapKeyCustody::initialize(&root.join("secrets"))?;
        let protected = custody.protect(instance, BootstrapObjectPurpose::Initialized, &[7; 32])?;
        let signer = custody.backup_control_signer(instance, &protected)?;
        let target = GoogleCloudStorageTarget::new("simulation-bucket", "123", "US", "owned/")?;
        let identity = RepositoryIdentity::google_cloud_storage(
            [1; 16],
            instance.to_bytes(),
            signer.identity().fingerprint(),
            &target,
        )?;
        let demand = initial_demand(
            crate::services::repository_administration::repository_resources(
                positron_governance::RepositoryProviderKind::GoogleCloudStorage,
            ),
        )?;
        let authority = native_authority::authority(&root.join("data"), demand)?;
        let grant = authority
            .governor()
            .reserve(WorkClaim::backup_repository_read(demand)?)?;
        let resources = NativeAwsResources::new(grant.transfer());
        let writer = GoogleCloudStorageRepository::from_local_simulator(
            target.clone(),
            identity.clone(),
            resources.clone(),
            RepositoryUploadAuthenticator::new(custody.catalog_secret(instance)?, instance),
            server.address,
        )?;
        runtime.block_on(writer.initialize())?;
        let manifest = BackupManifest::new(
            [5; 16],
            identity.clone(),
            BackupCatalogIdentity::new(17, [6; 32], 2, 9, [3; 32])?
                .with_capture_binding([0x81; 16], [0x82; 32])?,
            BackupRetention::new(1000, 2000)?,
            [8; 32],
            vec![BackupObject::new([3; 32], 64, 0, [4; 32], 64)?],
        )?;
        let object = ImmutableObject::new(manifest.signed_bytes(&signer)?)?;
        runtime.block_on(writer.put_if_absent(object.clone()))?;
        let reader_repository = GoogleCloudStorageRepository::read_only_from_local_simulator(
            target,
            identity.clone(),
            resources.clone(),
            server.address,
        )?;
        let reader = runtime
            .block_on(BackupSnapshotReader::open(
                &reader_repository,
                &identity,
                signer.identity(),
                object.id(),
                &resources,
                0,
            ))
            .map_err(|error| format!("native restore reader composition: {error:?}"))?;
        assert_eq!(reader.manifest(), &manifest);
        assert!(
            server
                .replies
                .lock()
                .map_err(|_| "fixture replies")?
                .is_empty()
        );
        assert!(server.race.lock().map_err(|_| "fixture race")?.is_none());
    }
    drop(runtime);
    drop(server);
    fs::remove_dir_all(root)?;
    Ok(())
}
