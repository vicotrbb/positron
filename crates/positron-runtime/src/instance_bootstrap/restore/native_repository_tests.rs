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

#[test]
fn restore_grant_refusals_retain_the_kernel_dimension_and_numeric_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let root = fs::canonicalize(std::env::temp_dir())?.join(format!(
        "positron-restore-grant-diagnostic-{}",
        std::process::id()
    ));
    fs::create_dir(&root)?;
    {
        let authority = native_authority::authority(&root, ResourceAmounts::new([1; 11]))?;
        let request = ResourceAmounts::new([1 << 50, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0]);
        let refusal = authority
            .governor()
            .reserve(WorkClaim::backup_repository_read(request)?)
            .expect_err("one pebibyte must exceed this real observed host inventory");
        assert_eq!(
            refusal.limiting_dimension(),
            Some(positron_kernel::ResourceDimension::MemoryBytes)
        );
        assert_eq!(refusal.requested(), 1 << 50);
        assert!(refusal.allowed() < refusal.requested());
        for (stage, label) in [
            (
                BootstrapResourceStage::RestoreInitialGrant,
                "restore_initial_grant",
            ),
            (
                BootstrapResourceStage::RestoreCarryGrant,
                "restore_carry_grant",
            ),
            (
                BootstrapResourceStage::RestorePhaseGrant,
                "restore_phase_grant",
            ),
        ] {
            let failure = super::super::grant_failure(stage, refusal);
            assert_eq!(failure.code(), BootstrapFailureCode::ResourceUnavailable);
            // This existing getter is the baseline RED seam: the old mapping discards all evidence.
            let context = failure
                .resource_context()
                .ok_or("restore grant context discarded")?;
            let mut value = serde_json::json!({});
            context.append_json(&mut value);
            assert_eq!(
                value,
                serde_json::json!({
                    "resource_stage": label, "resource_reason": "resource_admission_refused",
                    "resource_dimension": "memory_bytes",
                    "admission_code": format!("{:?}", refusal.code()),
                    "admission_scope": format!("{:?}", refusal.limiting_scope()),
                    "admission_class": "OrdinaryMaintenanceBackup",
                    "admission_pressure": format!("{:?}", refusal.pressure_state()),
                    "admission_allowed": refusal.allowed(), "admission_in_use": refusal.in_use(),
                    "admission_requested": refusal.requested()
                })
            );
        }
    }
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn restore_handoff_reuses_exclusive_capacity_without_overlap()
-> Result<(), Box<dyn std::error::Error>> {
    handoff_fixture(false, true, None)
}

#[test]
fn restore_handoff_shared_owner_preserves_old_charge_on_refusal_and_fallback()
-> Result<(), Box<dyn std::error::Error>> {
    handoff_fixture(true, true, None)?;
    handoff_fixture(true, false, None)
}

#[test]
fn restore_handoff_failure_keeps_retained_state_charged_until_caller_releases_it()
-> Result<(), Box<dyn std::error::Error>> {
    handoff_fixture(false, true, Some(BootstrapResourceStage::RestoreCarryGrant))?;
    handoff_fixture(
        false,
        false,
        Some(BootstrapResourceStage::RestorePhaseGrant),
    )
}

fn handoff_fixture(
    shared_owner: bool,
    constrained: bool,
    failure_stage: Option<BootstrapResourceStage>,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "positron-restore-handoff-local-{}-{shared_owner}-{constrained}-{}",
        std::process::id(),
        u8::from(failure_stage.is_some())
    ));
    fs::create_dir(&root)?;
    fs::create_dir(root.join("data"))?;
    fs::create_dir(root.join("repository"))?;
    for path in [&root, &root.join("data"), &root.join("repository")] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    {
        let native = crate::services::repository_administration::repository_resources(
            positron_governance::RepositoryProviderKind::LocalFilesystem,
        );
        let initial = initial_demand(native)?;
        let authority = native_authority::authority(
            &root.join("data"),
            ResourceAmounts::new(positron_kernel::ResourceDimension::ALL.map(|d| {
                initial
                    .get(d)
                    .checked_mul(2)
                    .expect("bounded fixture demand")
            })),
        )?;
        let mut resources = NativeAwsResources::new(
            authority
                .governor()
                .reserve(WorkClaim::backup_repository_read(initial)?)?
                .transfer(),
        );
        let identity =
            RepositoryIdentity::local([1; 16], [2; 16], [3; 32], &root.join("repository"))?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let repository = runtime.block_on(LocalRepository::initialize(
            &root.join("repository"),
            identity.clone(),
        ))?;
        let manifest = BackupManifest::new(
            [5; 16],
            identity,
            BackupCatalogIdentity::new(17, [6; 32], 2, 9, [3; 32])?
                .with_capture_binding([0x81; 16], [0x82; 32])?,
            BackupRetention::new(1000, 2000)?,
            [8; 32],
            vec![BackupObject::new([3; 32], 64, 0, [4; 32], 64)?],
        )?;
        // This fixture carries its actual manifest plus the same fixed handoff overhead.
        let carry_memory = manifest
            .retained_memory_bytes()?
            .checked_add(16 * 1024)
            .ok_or("carry")?;
        let phase_memory = carry_memory
            .checked_add(BackupPublisher::control_read_memory_bytes())
            .and_then(|v| {
                v.checked_add(native.get(positron_kernel::ResourceDimension::MemoryBytes))
            })
            .ok_or("phase")?;
        let baseline = ResourceAmounts::new([phase_memory, 1, 1, 0, 8, 0, 1, 1, 1, 16, 0]);
        let mut phase = ResourceAmounts::new(
            positron_kernel::ResourceDimension::ALL.map(|d| baseline.get(d).max(native.get(d))),
        );
        assert!(phase.is_at_most(initial));
        // Derive available class headroom from the real governor, including its shared pool.
        let memory = positron_kernel::ResourceDimension::MemoryBytes;
        let shared = positron_kernel::OrdinaryPool::Shared;
        let maintenance = positron_kernel::OrdinaryPool::OrdinaryMaintenanceBackup;
        let snapshot = authority.governor().inspect()?;
        let available = snapshot
            .pool_capacity(shared, memory)
            .checked_sub(snapshot.pool_usage(shared, memory))
            .and_then(|v| v.checked_add(snapshot.pool_capacity(maintenance, memory)))
            .and_then(|v| v.checked_sub(snapshot.pool_usage(maintenance, memory)))
            .ok_or("class headroom")?;
        let competing_memory = available
            .checked_sub(carry_memory / 2)
            .ok_or("competing read")?;
        if let Some(stage) = failure_stage {
            let memory_amount = match stage {
                BootstrapResourceStage::RestoreCarryGrant => initial.get(memory).checked_add(1),
                BootstrapResourceStage::RestorePhaseGrant => available
                    .checked_add(initial.get(memory))
                    .and_then(|v| v.checked_add(1)),
                _ => return Err("unsupported test failure stage".into()),
            }
            .ok_or("failure phase amount")?;
            phase = ResourceAmounts::new(positron_kernel::ResourceDimension::ALL.map(|d| {
                if d == memory {
                    memory_amount
                } else {
                    phase.get(d)
                }
            }));
        }

        let competing = if constrained {
            Some(
                authority
                    .governor()
                    .reserve(WorkClaim::backup_repository_read(ResourceAmounts::only(
                        positron_kernel::ResourceDimension::MemoryBytes,
                        competing_memory,
                    )?)?)?,
            )
        } else {
            None
        };
        let shared = shared_owner.then(|| resources.clone());
        let outcome = super::preflight::handoff_resources(
            &authority,
            &mut resources,
            Box::new(repository),
            carry_memory,
            phase,
        );
        if let Err(error) = &outcome {
            assert_eq!(error.code(), BootstrapFailureCode::ResourceUnavailable);
            let mut context = serde_json::json!({});
            error
                .resource_context()
                .ok_or("carry refusal context")?
                .append_json(&mut context);
            assert_eq!(
                context["resource_stage"],
                if failure_stage == Some(BootstrapResourceStage::RestorePhaseGrant) {
                    "restore_phase_grant"
                } else {
                    "restore_carry_grant"
                }
            );
            assert_eq!(context["admission_class"], "OrdinaryMaintenanceBackup");
            assert_eq!(context["resource_dimension"], "memory_bytes");
            assert_eq!(
                context["admission_requested"],
                if failure_stage == Some(BootstrapResourceStage::RestorePhaseGrant) {
                    phase.get(memory)
                } else {
                    carry_memory
                }
            );
        }
        if failure_stage.is_some() {
            assert!(outcome.is_err());
            let retained_charge = if constrained {
                initial.get(memory) + competing_memory
            } else {
                carry_memory
            };
            assert_eq!(
                authority.governor().inspect()?.usage(memory),
                retained_charge,
                "retained manifest must remain charged after failed handoff returns"
            );
        } else if shared_owner && constrained {
            assert!(
                outcome.is_err(),
                "shared transport cannot surrender its existing charge"
            );
            assert_eq!(shared.as_ref().ok_or("shared owner")?.granted(), initial);
            assert_eq!(
                authority.governor().inspect()?.outstanding_reservations(),
                2
            );
        } else {
            outcome?;
            assert_eq!(resources.granted(), phase);
            assert_eq!(
                authority.governor().inspect()?.outstanding_reservations(),
                2
            );
            if let Some(old) = &shared {
                assert_eq!(old.granted(), initial);
            }
        }
        // Retained source objects are released before their early-bound charge.
        drop(manifest);
        drop(resources);
        assert_eq!(
            authority.governor().inspect()?.outstanding_reservations(),
            u32::from(constrained) + u32::from(shared_owner)
        );
        drop(shared);
        assert_eq!(
            authority.governor().inspect()?.outstanding_reservations(),
            u32::from(constrained)
        );
        drop(competing);
        assert_eq!(
            authority.governor().inspect()?.outstanding_reservations(),
            0
        );
    }
    fs::remove_dir_all(root)?;
    Ok(())
}
