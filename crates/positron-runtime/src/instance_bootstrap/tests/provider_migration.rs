use super::initialization::Roots;
use crate::process_lifecycle as lifecycle;
use crate::{InitializationPlan, InstanceBootstrap};
use positron_kernel::key_provider::{
    CredentialFileReference, NativeRootConfiguration, ProviderCredentialModel, ProviderFamily,
    ProviderKeyUri,
};

#[test]
fn failed_native_preflight_preserves_source_and_has_no_prepared_route()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|e| format!("paths: {e:?}"))?;
    let instance = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let before = instance.local_key_rotation_status()?;
    let identity = ProviderKeyUri::new(
        ProviderFamily::Kmip21,
        "kmip://localhost:5696/objects/immutable-id",
        "sha256:0606060606060606060606060606060606060606060606060606060606060606",
    )?;
    let absent = CredentialFileReference::new(&roots.data.join("absent-native-credential"))?;
    let configuration = NativeRootConfiguration::Kmip {
        identity,
        credentials: ProviderCredentialModel::KmipMutualTls {
            certificate: absent.clone(),
            private_key: absent.clone(),
            trust_roots: absent,
        },
    };
    assert!(
        instance
            .begin_key_provider_migration(configuration)
            .is_err()
    );
    assert_eq!(instance.local_key_rotation_status()?, before);
    assert!(instance.key_provider_migration_status().is_ok());
    drop(instance);
    InstanceBootstrap::reopen(&paths)?;
    Ok(())
}

mod audit_retention;
mod data;
mod fixtures;
use fixtures::*;
use std::sync::Arc;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_revokes_native_admission_and_wakes_its_queued_caller()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::RootRewrapSession;
    use std::os::unix::fs::PermissionsExt;
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|e| format!("paths: {e:?}"))?;
    let instance = Arc::new(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let credentials = roots
        .data
        .parent()
        .ok_or("fixture parent")?
        .join("credentials");
    std::fs::create_dir(&credentials)?;
    std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o700))?;
    let (port, server) = transcript_transport(
        |port| migration_replies(&instance, port, "immutable-id", 2),
        &[&rustls::version::TLS13],
    )
    .await?;
    let target = ProviderKeyUri::new(
        ProviderFamily::Kmip21,
        &format!("kmip://localhost:{port}/objects/immutable-id"),
        PIN,
    )?;
    let config = || -> Result<_, Box<dyn std::error::Error>> {
        Ok(NativeRootConfiguration::Kmip {
            identity: target.clone(),
            credentials: model(&credentials)?,
        })
    };
    instance.begin_key_provider_migration(config()?)?;
    instance.activate_key_provider_migration(config()?)?;
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let first_instance = Arc::clone(&instance);
    let first = std::thread::spawn(move || {
        let _session = RootRewrapSession::admit_provider(&first_instance._authority)
            .expect("bounded admission");
        RootRewrapSession::with_key_admission_action(
            move || {
                entered_tx.send(()).expect("admission entered");
                release_rx.recv().expect("admission release");
            },
            || first_instance.key.catalog_secret(first_instance.instance),
        )
    });
    entered_rx.recv_timeout(std::time::Duration::from_secs(5))?;
    let (waiting_tx, waiting_rx) = std::sync::mpsc::sync_channel(1);
    let second_instance = Arc::clone(&instance);
    let second = std::thread::spawn(move || {
        let _session = RootRewrapSession::admit_provider(&second_instance._authority)
            .expect("bounded admission");
        RootRewrapSession::with_key_admission_action(
            move || {
                waiting_tx.send(()).expect("queued admission entered");
            },
            || second_instance.key.catalog_secret(second_instance.instance),
        )
    });
    waiting_rx.recv_timeout(std::time::Duration::from_secs(5))?;
    instance.key.close_for_shutdown()?;
    assert!(
        second
            .join()
            .map_err(|_| "queued admission panicked")?
            .is_err()
    );
    release_tx.send(())?;
    assert!(
        first
            .join()
            .map_err(|_| "in-flight admission panicked")?
            .is_err()
    );
    assert!(instance.key.catalog_secret(instance.instance).is_err());
    assert_eq!(
        instance
            ._authority
            .governor()
            .inspect()?
            .outstanding_for(positron_kernel::WorkClass::SecurityLifecycle),
        0
    );
    assert_eq!(server.await?.len(), 15);
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_cutover_publication_failure_recovers_only_the_committed_route()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::{
        CatalogPublicationFault, with_catalog_publication_fault_after,
        with_catalog_publication_fault_sequence_after,
    };
    use std::os::unix::fs::PermissionsExt;
    for (fault, committed) in [
        (CatalogPublicationFault::SynchronizeCommit, false),
        (
            CatalogPublicationFault::SynchronizeGenerationDirectory,
            true,
        ),
    ] {
        let roots = Roots::new()?;
        let paths = roots.paths().map_err(|e| format!("paths: {e:?}"))?;
        let instance =
            InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
        let credentials = roots
            .data
            .parent()
            .ok_or("fixture parent")?
            .join("credentials");
        std::fs::create_dir(&credentials)?;
        std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o700))?;
        let verifications = if committed { 5 } else { 4 };
        let (port, server) = transcript_transport(
            |port| migration_replies(&instance, port, "immutable-id", verifications),
            &[&rustls::version::TLS13],
        )
        .await?;
        let target = ProviderKeyUri::new(
            ProviderFamily::Kmip21,
            &format!("kmip://localhost:{port}/objects/immutable-id"),
            PIN,
        )?;
        let config = || -> Result<_, Box<dyn std::error::Error>> {
            Ok(NativeRootConfiguration::Kmip {
                identity: target.clone(),
                credentials: model(&credentials)?,
            })
        };
        let prepared = instance.begin_key_provider_migration(config()?)?;
        let failed = if committed {
            with_catalog_publication_fault_sequence_after(&[(fault, 1), (fault, 0)], || {
                instance.activate_key_provider_migration(config().expect("fixed configuration"))
            })
        } else {
            with_catalog_publication_fault_after(fault, 0, || {
                instance.activate_key_provider_migration(config().expect("fixed configuration"))
            })
        };
        assert!(failed.is_err());
        let observed = instance.key_provider_migration_status()?;
        assert_eq!(
            observed.rotation().active_epoch(),
            if committed { 2 } else { 1 }
        );
        assert_eq!(
            observed.rotation().phase(),
            if committed {
                crate::LocalKeyRotationPhase::Verifying
            } else {
                crate::LocalKeyRotationPhase::Prepared
            }
        );
        drop(instance);
        let reopened = if committed {
            InstanceBootstrap::reopen_with_provider(&paths, config()?)
                .map_err(|e| format!("committed cutover cold reopen: {e:?}"))?
        } else {
            InstanceBootstrap::reopen(&paths)
                .map_err(|e| format!("uncommitted cutover source cold reopen: {e:?}"))?
        };
        assert_eq!(reopened.key_provider_migration_status()?, observed);
        if committed {
            assert_eq!(
                reopened.key_provider_migration_status()?.active_provider(),
                &target
            );
        } else {
            assert_eq!(reopened.key_provider_migration_status()?, prepared);
        }
        let active = reopened.activate_key_provider_migration(config()?)?;
        assert_eq!(active.active_provider(), &target);
        drop(reopened);
        let reopened = InstanceBootstrap::reopen_with_provider(&paths, config()?)
            .map_err(|e| format!("resumed cutover target cold reopen: {e:?}"))?;
        assert_eq!(reopened.key_provider_migration_status()?, active);
        assert!(
            roots
                .data
                .parent()
                .ok_or("fixture parent")?
                .join("secrets/local-root-key.v1")
                .exists()
        );
        assert_eq!(server.await?.len(), 5 + verifications * 5);
    }
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unverified_recovery_artifact_blocks_native_predecessor_retirement()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|e| format!("paths: {e:?}"))?;
    let instance = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let parent = roots.data.parent().ok_or("fixture parent")?;
    let recovery = parent.join("recovery");
    let credentials = parent.join("credentials");
    for directory in [&recovery, &credentials] {
        std::fs::create_dir(directory)?;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    }
    let unlock = age::x25519::Identity::generate();
    let bundle = recovery.join("source.age");
    instance.create_recovery_bundle(
        &bundle,
        &positron_kernel::RecoveryRecipients::parse(&[unlock.to_public().to_string()])?,
    )?;
    let (port, server) = transcript_transport(
        |port| migration_replies(&instance, port, "immutable-id", 3),
        &[&rustls::version::TLS13],
    )
    .await?;
    let target = ProviderKeyUri::new(
        ProviderFamily::Kmip21,
        &format!("kmip://localhost:{port}/objects/immutable-id"),
        PIN,
    )?;
    let config = || -> Result<_, Box<dyn std::error::Error>> {
        Ok(NativeRootConfiguration::Kmip {
            identity: target.clone(),
            credentials: model(&credentials)?,
        })
    };
    instance.begin_key_provider_migration(config()?)?;
    instance.activate_key_provider_migration(config()?)?;
    let before = instance.key_provider_migration_status()?;
    assert!(matches!(
        instance.retire_key_provider_predecessor(config()?),
        Err(crate::LocalKeyRotationFailure::Busy)
    ));
    assert_eq!(instance.key_provider_migration_status()?, before);
    assert!(parent.join("secrets/local-root-key.v1").exists());
    assert!(bundle.exists());
    assert_eq!(server.await?.len(), 20);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_migration_recovers_prepared_cutover_and_retired_routes()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|e| format!("paths: {e:?}"))?;
    let instance = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let credentials = roots
        .data
        .parent()
        .ok_or("fixture parent")?
        .join("credentials");
    std::fs::create_dir(&credentials)?;
    std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o700))?;
    let (port, server) = transcript_transport(
        |port| {
            let mut replies = migration_replies(&instance, port, "immutable-id", 10);
            replies.extend(migration_replies(&instance, port, "second-id", 5));
            replies
        },
        &[&rustls::version::TLS13],
    )
    .await?;
    let target = ProviderKeyUri::new(
        ProviderFamily::Kmip21,
        &format!("kmip://localhost:{port}/objects/immutable-id"),
        PIN,
    )?;
    let config = || -> Result<_, Box<dyn std::error::Error>> {
        Ok(NativeRootConfiguration::Kmip {
            identity: target.clone(),
            credentials: model(&credentials)?,
        })
    };
    let prepared = instance.begin_key_provider_migration(config()?)?;
    assert_eq!(prepared.target_provider(), Some(&target));
    assert_ne!(prepared.active_provider(), &target);
    let cancelled = instance.cancel_key_provider_migration()?;
    assert_eq!(
        cancelled.rotation().phase(),
        crate::LocalKeyRotationPhase::Cancelled
    );
    drop(instance);
    let reopened = InstanceBootstrap::reopen(&paths)?;
    assert_eq!(reopened.key_provider_migration_status()?, cancelled);
    assert!(reopened.begin_key_provider_migration(config()?).is_err());
    assert!(reopened.activate_key_provider_migration(config()?).is_err());
    assert_eq!(reopened.resume_key_provider_migration()?, prepared);
    assert_eq!(reopened.begin_key_provider_migration(config()?)?, prepared);
    let committed = reopened.activate_key_provider_migration(config()?)?;
    assert_eq!(committed.active_provider(), &target);
    assert_eq!(committed.rotation().predecessor_epoch(), Some(1));
    let cancelled = reopened.cancel_key_provider_migration()?;
    assert_eq!(cancelled.active_provider(), &target);
    assert!(reopened.retire_key_provider_predecessor(config()?).is_err());
    assert_eq!(reopened.resume_key_provider_migration()?, committed);
    drop(reopened);
    let native_reopened = InstanceBootstrap::reopen_with_provider(&paths, config()?)?;
    assert_eq!(native_reopened.key_provider_migration_status()?, committed);
    native_reopened.key.invalidate_for_rotation()?;
    assert!(
        native_reopened
            .key
            .protect(
                native_reopened.instance_id(),
                positron_kernel::BootstrapObjectPurpose::Initialized,
                b"unconfirmed writes"
            )
            .is_err()
    );
    assert_eq!(
        native_reopened
            .activate_key_provider_migration(config()?)
            .map_err(|e| format!("native admission reconfirmation: {e:?}"))?,
        committed
    );
    let resumed = native_reopened
        .key
        .protect(
            native_reopened.instance_id(),
            positron_kernel::BootstrapObjectPurpose::Initialized,
            b"independently revalidated writes",
        )
        .map_err(|e| format!("resumed native write: {e:?}"))?;
    assert_eq!(
        native_reopened
            .key
            .open_object(
                native_reopened.instance_id(),
                positron_kernel::BootstrapObjectPurpose::Initialized,
                &resumed
            )?
            .as_slice(),
        b"independently revalidated writes"
    );
    assert_eq!(
        native_reopened.verify_key_provider_migration(config()?)?,
        committed
    );
    assert!(
        roots
            .data
            .parent()
            .ok_or("fixture parent")?
            .join("secrets/local-root-key.v1")
            .exists()
    );
    native_reopened.retire_key_provider_predecessor(config()?)?;
    assert!(
        !roots
            .data
            .parent()
            .ok_or("fixture parent")?
            .join("secrets/local-root-key.v1")
            .exists()
    );
    let completed = native_reopened.key_provider_migration_status()?;
    assert_eq!(completed.rotation().predecessor_epoch(), None);
    assert_eq!(completed.source_provider(), prepared.source_provider());
    assert_eq!(completed.target_provider(), Some(&target));
    drop(native_reopened);
    let target_only = InstanceBootstrap::reopen_with_provider(&paths, config()?)
        .map_err(|e| format!("post-process reopen: {e:?}"))?;
    assert_eq!(target_only.key_provider_migration_status()?, completed);
    let second = ProviderKeyUri::new(
        ProviderFamily::Kmip21,
        &format!("kmip://localhost:{port}/objects/second-id"),
        PIN,
    )?;
    let second_config = || -> Result<_, Box<dyn std::error::Error>> {
        Ok(NativeRootConfiguration::Kmip {
            identity: second.clone(),
            credentials: model(&credentials)?,
        })
    };
    let second_prepared = target_only
        .begin_key_provider_migration(second_config()?)
        .map_err(|e| format!("post-process second prepare: {e:?}"))?;
    assert_eq!(second_prepared.source_provider(), &target);
    assert_eq!(second_prepared.target_provider(), Some(&second));
    target_only.activate_key_provider_migration(second_config()?)?;
    drop(target_only);
    let second_reopened = InstanceBootstrap::reopen_with_provider(&paths, second_config()?)?;
    second_reopened
        .retire_key_provider_predecessor(second_config()?)
        .map_err(|e| format!("post-process second retirement: {e:?}"))?;
    drop(second_reopened);
    let target_only = InstanceBootstrap::reopen_with_provider(&paths, second_config()?)?;
    assert_eq!(
        target_only
            .key_provider_migration_status()?
            .source_provider(),
        &target
    );
    assert_eq!(server.await?.len(), 85);
    assert_eq!(
        target_only
            .begin_local_key_rotation()
            .map_err(|e| format!("native-to-local prepare: {e}"))?
            .successor_epoch(),
        Some(4)
    );
    target_only.activate_local_key_rotation()?;
    drop(target_only);
    let local_again = InstanceBootstrap::reopen(&paths)?;
    assert_eq!(local_again.local_key_rotation_status()?.active_epoch(), 4);
    let recovery = roots
        .data
        .parent()
        .ok_or("fixture parent")?
        .join("recovery");
    std::fs::create_dir(&recovery)?;
    std::fs::set_permissions(&recovery, std::fs::Permissions::from_mode(0o700))?;
    let unlock = age::x25519::Identity::generate();
    let bundle = recovery.join("local-successor.age");
    local_again.create_recovery_bundle(
        &bundle,
        &positron_kernel::RecoveryRecipients::parse(&[unlock.to_public().to_string()])?,
    )?;
    local_again
        .verify_recovery_bundle(&bundle, positron_kernel::RecoveryUnlock::Identity(&unlock))?;
    local_again.retire_local_key_predecessor()?;
    assert_eq!(
        local_again
            .key_provider_migration_status()?
            .source_provider(),
        &second
    );
    drop(local_again);
    assert_eq!(
        InstanceBootstrap::reopen(&paths)?
            .local_key_rotation_status()?
            .active_epoch(),
        4
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_provider_configuration_starts_serving_after_local_root_removal()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|e| format!("paths: {e:?}"))?;
    let instance = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let credentials = roots
        .data
        .parent()
        .ok_or("fixture parent")?
        .join("credentials");
    std::fs::create_dir(&credentials)?;
    std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o700))?;
    let (port, server) = transcript_transport(
        |port| migration_replies(&instance, port, "immutable-id", 4),
        &[&rustls::version::TLS13],
    )
    .await?;
    let target = ProviderKeyUri::new(
        ProviderFamily::Kmip21,
        &format!("kmip://localhost:{port}/objects/immutable-id"),
        PIN,
    )?;
    let config = || -> Result<_, Box<dyn std::error::Error>> {
        Ok(NativeRootConfiguration::Kmip {
            identity: target.clone(),
            credentials: model(&credentials)?,
        })
    };
    instance.begin_key_provider_migration(config()?)?;
    instance.activate_key_provider_migration(config()?)?;
    instance.retire_key_provider_predecessor(config()?)?;
    drop(instance);
    assert!(
        !roots
            .data
            .parent()
            .ok_or("fixture parent")?
            .join("secrets/local-root-key.v1")
            .exists()
    );
    for wrong in [
        ProviderKeyUri::new(
            ProviderFamily::Kmip21,
            &format!("kmip://localhost:{port}/objects/other-id"),
            PIN,
        )?,
        ProviderKeyUri::new(
            ProviderFamily::Kmip21,
            target.locator(),
            "sha256:0707070707070707070707070707070707070707070707070707070707070707",
        )?,
    ] {
        assert!(
            InstanceBootstrap::reopen_with_provider(
                &paths,
                NativeRootConfiguration::Kmip {
                    identity: wrong,
                    credentials: model(&credentials)?
                }
            )
            .is_err()
        );
        assert!(
            !roots
                .data
                .parent()
                .ok_or("fixture parent")?
                .join("secrets/local-root-key.v1")
                .exists()
        );
    }
    let configuration_document = format!(
        "schema_version = 1\n[storage]\ndata_directory = '{}'\nsecrets_directory = '{}'\n[security]\nlocal_key_file = '{}'\n[security.provider_access]\nuri = '{}'\nversion = '{}'\nauthentication = 'kmip-mtls'\ncertificate_file = '{}'\nprivate_key_file = '{}'\ntrust_roots_file = '{}'\n",
        roots.data.display(),
        roots
            .data
            .parent()
            .ok_or("fixture parent")?
            .join("secrets")
            .display(),
        roots
            .data
            .parent()
            .ok_or("fixture parent")?
            .join("secrets/local-root-key.v1")
            .display(),
        target.locator(),
        target.version(),
        credentials.join("cert").display(),
        credentials.join("key").display(),
        credentials.join("ca").display()
    );
    let effective = Arc::new(positron_config::resolve(
        positron_config::ConfigurationInputs::try_new(
            Some(&configuration_document),
            positron_config::EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])?,
            positron_config::CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
        )?,
    )?);
    let listeners = lifecycle::ObservingListeners::default();
    let tasks = lifecycle::ObservingTasks::default();
    let process = crate::ApplicationRuntime::start(
        crate::ServeConfiguration::new(paths.clone(), crate::InitializationMode::ExistingOnly)
            .with_effective_configuration(effective),
        crate::HostInputs::new(&listeners, &tasks),
    )?;
    assert_eq!(process.health().readiness(), crate::Readiness::Ready);
    assert_eq!(
        process.shutdown(crate::ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful
    );
    drop(listeners);
    drop(tasks);
    assert_eq!(server.await?.len(), 25);
    assert!(
        !roots
            .data
            .parent()
            .ok_or("fixture parent")?
            .join("secrets/local-root-key.v1")
            .exists()
    );
    Ok(())
}

#[test]
fn native_preflight_resource_refusal_is_typed_and_leaves_no_migration_intent()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|e| format!("paths: {e:?}"))?;
    let instance = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let before = instance.key_provider_migration_status()?;
    let mut grants = Vec::new();
    let mut refused = false;
    for _ in 0..64 {
        match positron_kernel::RootRewrapSession::admit_provider(&instance._authority) {
            Ok(grant) => grants.push(grant),
            Err(positron_kernel::BootstrapKeyFailure::LimitExceeded) => {
                refused = true;
                break;
            },
            Err(error) => return Err(error.into()),
        }
    }
    assert!(refused, "bounded root grants reach the configured capacity");
    drop(grants.pop().ok_or("retained root grant")?);
    let identity = ProviderKeyUri::new(
        ProviderFamily::Kmip21,
        "kmip://localhost:5696/objects/immutable-id",
        PIN,
    )?;
    let absent = CredentialFileReference::new(&roots.data.join("absent-native-credential"))?;
    let configuration = NativeRootConfiguration::Kmip {
        identity,
        credentials: ProviderCredentialModel::KmipMutualTls {
            certificate: absent.clone(),
            private_key: absent.clone(),
            trust_roots: absent,
        },
    };
    assert_eq!(
        instance.begin_key_provider_migration(configuration),
        Err(crate::LocalKeyRotationFailure::LimitExceeded)
    );
    drop(grants);
    assert_eq!(instance.key_provider_migration_status()?, before);
    drop(instance);
    assert_eq!(
        InstanceBootstrap::reopen(&paths)?.key_provider_migration_status()?,
        before
    );
    Ok(())
}

#[test]
fn local_target_preparation_refuses_a_revalidated_source_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|e| format!("paths: {e:?}"))?;
    let instance = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let before = instance.local_key_rotation_status()?;
    let result = super::super::local_rotation::with_local_rotation_prepublication_hook(
        |instance| {
            let session = positron_kernel::RootRewrapSession::admit_provider(&instance._authority)
                .expect("source control admission");
            let identity = instance
                .key
                .active_root_identity()
                .expect("source identity");
            let epoch = instance.key.active_root_epoch().expect("source epoch");
            instance
                .key
                .invalidate_for_rotation()
                .expect("source revocation");
            session
                .confirm_active_provider(&instance.key, identity, epoch)
                .expect("independent source revalidation");
        },
        || instance.begin_local_key_rotation(),
    );
    assert_eq!(result, Err(crate::LocalKeyRotationFailure::Busy));
    assert_eq!(instance.local_key_rotation_status()?, before);
    drop(instance);
    assert_eq!(
        InstanceBootstrap::reopen(&paths)?.local_key_rotation_status()?,
        before
    );
    Ok(())
}
