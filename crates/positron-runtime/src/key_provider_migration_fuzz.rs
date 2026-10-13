//! Actual encrypted custody and Catalog recovery, with bounded lifecycle actions.
use crate::tail_fuzz_support::{FuzzRoot, describe};
use crate::{InitializationPlan, InstanceBootstrap, LocalKeyRotationFailure};
use positron_kernel::{
    CatalogPublicationFault, RecoveryRecipients, RecoveryUnlock,
    with_catalog_publication_fault_after,
};

pub(super) fn run(data: &[u8]) {
    if let Err(error) = run_checked(data) {
        panic!("root migration lifecycle invariant: {error}");
    }
}
fn run_checked(data: &[u8]) -> Result<(), String> {
    let root = FuzzRoot::new()?;
    let paths = root.paths()?;
    let mut instance = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())
        .map_err(describe)?;
    let mut committed_epoch = instance
        .local_key_rotation_status()
        .map_err(describe)?
        .active_epoch();
    let mut recovery_verified = false;
    let recovery = root.artifact_path("recovery");
    std::fs::create_dir(&recovery).map_err(describe)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&recovery, std::fs::Permissions::from_mode(0o700))
            .map_err(describe)?;
    }
    let unlock = age::x25519::Identity::generate();
    let recipients =
        RecoveryRecipients::parse(&[unlock.to_public().to_string()]).map_err(describe)?;
    for (index, byte) in data.iter().copied().take(12).enumerate() {
        let action = byte % 8;
        if action == 6 {
            drop(instance);
            instance = InstanceBootstrap::reopen(&paths).map_err(describe)?;
            assert_eq!(
                instance
                    .local_key_rotation_status()
                    .map_err(describe)?
                    .active_epoch(),
                committed_epoch
            );
            continue;
        }
        if action == 7 {
            let bundle = recovery.join(format!("verified-{index}.age"));
            if instance
                .create_recovery_bundle(&bundle, &recipients)
                .is_ok()
                && instance
                    .verify_recovery_bundle(&bundle, RecoveryUnlock::Identity(&unlock))
                    .is_ok()
            {
                recovery_verified = true;
            }
            continue;
        }
        let operation = || -> Result<(), LocalKeyRotationFailure> {
            match action {
                0 => instance.begin_local_key_rotation().map(|_| ()),
                1 => instance.activate_local_key_rotation().map(|_| ()),
                2 => instance.cancel_key_provider_migration().map(|_| ()),
                3 => instance.resume_key_provider_migration().map(|_| ()),
                4 => instance.verify_local_key_rotation().map(|_| ()),
                5 => instance.retire_local_key_predecessor(),
                _ => unreachable!("closed lifecycle action"),
            }
        };
        let result = if byte & 0x80 != 0 {
            with_catalog_publication_fault_after(
                if byte & 0x40 == 0 {
                    CatalogPublicationFault::RenameMarker
                } else {
                    CatalogPublicationFault::SynchronizeCommit
                },
                0,
                operation,
            )
        } else {
            operation()
        };
        // A failed acknowledgement can still publish cutover. Cold reopen is
        // the independent public recovery check of that committed route.
        let current = match instance.local_key_rotation_status() {
            Ok(status) => status,
            Err(_) => {
                drop(instance);
                instance = InstanceBootstrap::reopen(&paths).map_err(describe)?;
                instance.local_key_rotation_status().map_err(describe)?
            },
        };
        if action == 1 {
            assert!(
                current.active_epoch() == committed_epoch
                    || current.active_epoch() == committed_epoch.saturating_add(1)
            );
            if current.active_epoch() != committed_epoch {
                recovery_verified = false;
            }
            committed_epoch = current.active_epoch();
        } else {
            assert_eq!(current.active_epoch(), committed_epoch);
        }
        if action == 5 && result.is_ok() {
            assert!(
                recovery_verified,
                "retirement requires independently verified recovery"
            );
            assert_eq!(current.predecessor_epoch(), None);
        }
        drop(instance);
        instance = InstanceBootstrap::reopen(&paths).map_err(describe)?;
        assert_eq!(
            instance
                .local_key_rotation_status()
                .map_err(describe)?
                .active_epoch(),
            committed_epoch
        );
    }
    Ok(())
}
