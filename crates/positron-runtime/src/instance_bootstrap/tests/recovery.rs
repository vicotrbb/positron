use super::super::*;
use super::support::Roots;
use positron_kernel::{RecoveryRecipients, RecoveryUnlock};
#[test]
fn separate_bundle_verification_controls_backup_key_readiness_across_restart()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let roots = Roots::new()?;
    let export = roots.parent().join("recovery");
    std::fs::create_dir(&export)?;
    std::fs::set_permissions(&export, std::fs::Permissions::from_mode(0o700))?;
    let path = std::fs::canonicalize(export)?.join("recovery.age");
    let paths = roots.paths();
    let instance = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let identity = age::x25519::Identity::generate();
    let recipients = RecoveryRecipients::parse(&[identity.to_public().to_string()])?;
    assert_eq!(
        instance.backup_key_recovery_readiness()?,
        RecoveryReadiness::IndependentRecoveryRequired
    );
    instance.create_recovery_bundle(&path, &recipients)?;
    assert_eq!(
        instance.backup_key_recovery_readiness()?,
        RecoveryReadiness::IndependentRecoveryRequired
    );
    instance.verify_recovery_bundle(&path, RecoveryUnlock::Identity(&identity))?;
    assert_eq!(
        instance.backup_key_recovery_readiness()?,
        RecoveryReadiness::Verified
    );
    drop(instance);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let actor = instance.attribute(
        positron_governance::PresentedCredential::parse(claim.secret())?,
        positron_governance::RequestedIntent::SystemAdministration,
        positron_governance::CompatibilityHints::none(),
    )?;
    instance.verify_governance_audit_history(actor, None)?;
    let history = instance.inspect_governance_audit_history(actor)?;
    let actions = history
        .records()
        .iter()
        .filter_map(positron_governance::GovernanceAuditEntry::as_recovery_bundle)
        .map(|entry| entry.operation())
        .collect::<Vec<_>>();
    assert_eq!(
        actions,
        [
            positron_governance::RecoveryBundleAction::Created,
            positron_governance::RecoveryBundleAction::Verified
        ]
    );

    assert_eq!(
        instance.backup_key_recovery_readiness()?,
        RecoveryReadiness::Verified
    );
    std::fs::write(&path, b"corrupt")?;
    assert_eq!(
        instance.backup_key_recovery_readiness()?,
        RecoveryReadiness::IndependentRecoveryRequired
    );
    Ok(())
}
#[test]
fn recipient_rotation_verifies_replacement_before_retiring_predecessor()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let roots = Roots::new()?;
    let export = roots.parent().join("rotation");
    std::fs::create_dir(&export)?;
    std::fs::set_permissions(&export, std::fs::Permissions::from_mode(0o700))?;
    let export = std::fs::canonicalize(export)?;
    let old = export.join("old.age");
    let new = export.join("new.age");
    let instance =
        InstanceBootstrap::initialize(&roots.paths(), InitializationPlan::non_interactive())?;
    let first = age::x25519::Identity::generate();
    let second = age::x25519::Identity::generate();
    instance.create_recovery_bundle(
        &old,
        &RecoveryRecipients::parse(&[first.to_public().to_string()])?,
    )?;
    instance.verify_recovery_bundle(&old, RecoveryUnlock::Identity(&first))?;
    instance.create_recovery_bundle(
        &new,
        &RecoveryRecipients::parse(&[second.to_public().to_string()])?,
    )?;
    assert!(instance.retire_recovery_predecessor().is_err());
    assert!(old.exists());
    assert!(
        instance
            .verify_recovery_bundle(&new, RecoveryUnlock::Identity(&first))
            .is_err()
    );
    assert!(old.exists());
    instance.verify_recovery_bundle(&new, RecoveryUnlock::Identity(&second))?;
    let third = export.join("third.age");
    instance.create_recovery_bundle(
        &third,
        &RecoveryRecipients::parse(&[second.to_public().to_string()])?,
    )?;
    assert!(
        instance
            .verify_recovery_bundle(&third, RecoveryUnlock::Identity(&second))
            .is_err(),
        "a pending predecessor must not be forgotten"
    );
    let encrypted = std::fs::read(&new)?;
    std::fs::write(&new, b"corrupt")?;
    assert!(instance.retire_recovery_predecessor().is_err());
    assert!(old.exists());
    std::fs::write(&new, encrypted)?;
    let unlink = positron_kernel::RecoverySession::with_directory_sync_failure(|| {
        instance.retire_recovery_predecessor()
    });
    assert_eq!(unlink, Err(positron_kernel::RecoveryFailure::Storage));
    assert!(!old.exists());
    let retry = positron_kernel::RecoverySession::with_directory_sync_failure(|| {
        instance.retire_recovery_predecessor()
    });
    assert_eq!(retry, Err(positron_kernel::RecoveryFailure::Storage));
    // Reopening proves preparation survived and no completion was published on either failure.
    drop(instance);
    let claim = InstanceBootstrap::claim(&roots.paths())?;
    let instance = InstanceBootstrap::reopen(&roots.paths())?;
    let actor = instance.attribute(
        positron_governance::PresentedCredential::parse(claim.secret())?,
        positron_governance::RequestedIntent::SystemAdministration,
        positron_governance::CompatibilityHints::none(),
    )?;
    let history = instance.inspect_governance_audit_history(actor)?;
    let actions = history
        .records()
        .iter()
        .filter_map(positron_governance::GovernanceAuditEntry::as_recovery_bundle)
        .map(|entry| entry.operation())
        .collect::<Vec<_>>();
    assert!(actions.contains(&positron_governance::RecoveryBundleAction::RetirementPrepared));
    assert!(!actions.contains(&positron_governance::RecoveryBundleAction::Retired));
    instance.retire_recovery_predecessor()?;
    let history = instance.inspect_governance_audit_history(actor)?;
    assert_eq!(
        history
            .records()
            .iter()
            .filter_map(positron_governance::GovernanceAuditEntry::as_recovery_bundle)
            .filter(|entry| entry.operation() == positron_governance::RecoveryBundleAction::Retired)
            .count(),
        1
    );
    assert!(instance.retire_recovery_predecessor().is_err());
    assert!(!old.exists());
    assert!(new.exists());
    assert_eq!(
        instance.backup_key_recovery_readiness()?,
        RecoveryReadiness::Verified
    );
    Ok(())
}
#[test]
fn missing_local_root_is_recovered_only_after_pinned_bundle_and_instance_authentication()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let roots = Roots::new()?;
    let paths = roots.paths();
    let export = roots.parent().join("import");
    std::fs::create_dir(&export)?;
    std::fs::set_permissions(&export, std::fs::Permissions::from_mode(0o700))?;
    let path = std::fs::canonicalize(export)?.join("recovery.age");
    let instance = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let pin = instance.recovery_identity()?;
    let recipient = age::x25519::Identity::generate();
    instance.create_recovery_bundle(
        &path,
        &RecoveryRecipients::parse(&[recipient.to_public().to_string()])?,
    )?;
    instance.verify_recovery_bundle(&path, RecoveryUnlock::Identity(&recipient))?;
    let key = paths.secrets_root().join("local-root-key.v1");
    std::fs::remove_file(&key)?;
    assert_eq!(
        instance.backup_key_recovery_readiness()?,
        RecoveryReadiness::IndependentRecoveryRequired
    );
    drop(instance);
    assert!(InstanceBootstrap::reopen(&paths).is_err());
    let wrong = age::x25519::Identity::generate();
    assert!(
        InstanceBootstrap::import_recovery_bundle(
            &paths,
            &path,
            pin,
            RecoveryUnlock::Identity(&wrong)
        )
        .is_err()
    );
    assert!(!key.exists());
    let other = positron_kernel::RecoveryIdentity::new(
        positron_kernel::InstanceId::new([0xee; 16])?,
        pin.root(),
        pin.integrity(),
    )?;
    assert!(
        InstanceBootstrap::import_recovery_bundle(
            &paths,
            &path,
            other,
            RecoveryUnlock::Identity(&recipient)
        )
        .is_err()
    );
    assert!(!key.exists());
    let encrypted = std::fs::read(&path)?;
    std::fs::write(&path, b"corrupt")?;
    assert!(
        InstanceBootstrap::import_recovery_bundle(
            &paths,
            &path,
            pin,
            RecoveryUnlock::Identity(&recipient)
        )
        .is_err()
    );
    assert!(!key.exists());
    std::fs::write(&path, encrypted)?;
    let restored = InstanceBootstrap::import_recovery_bundle(
        &paths,
        &path,
        pin,
        RecoveryUnlock::Identity(&recipient),
    )?;
    assert_eq!(restored.instance_id(), pin.instance());
    assert_eq!(restored.recovery_identity()?, pin);
    assert_eq!(
        std::fs::metadata(&key)?.permissions().mode() & 0o7777,
        0o600
    );
    assert_eq!(
        restored.backup_key_recovery_readiness()?,
        RecoveryReadiness::Verified
    );
    Ok(())
}

#[test]
fn owner_recovery_startup_warnings_are_closed_and_actionable()
-> Result<(), Box<dyn std::error::Error>> {
    for (warning, label) in [
        (
            crate::OperationalDiagnostic::LocalKeyCustodyWarning,
            "local_key_custody_warning",
        ),
        (
            crate::OperationalDiagnostic::IndependentKeyRecoveryRequired,
            "independent_key_recovery_required",
        ),
    ] {
        let mut output = Vec::new();
        crate::render_operational_diagnostic(&mut output, false, warning)?;
        let value: serde_json::Value = serde_json::from_slice(&output)?;
        assert_eq!(value["severity"], "warn");
        assert_eq!(value["event"], label);
        assert!(
            value["warning"]
                .as_str()
                .is_some_and(|text| !text.is_empty())
        );
    }
    Ok(())
}

#[test]
fn owner_passphrase_workflow_is_admitted_through_real_catalog_publication()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let roots = Roots::new()?;
    let export = roots.parent().join("passphrase");
    std::fs::create_dir(&export)?;
    std::fs::set_permissions(&export, std::fs::Permissions::from_mode(0o700))?;
    let path = std::fs::canonicalize(export)?.join("recovery.age");
    let instance =
        InstanceBootstrap::initialize(&roots.paths(), InitializationPlan::non_interactive())?;
    instance.create_interactive_recovery_bundle(&path, || {
        positron_kernel::RecoveryPassphrase::from_interactive(
            "public recovery passphrase fixture".to_owned(),
        )
    })?;
    assert_eq!(
        instance.backup_key_recovery_readiness()?,
        RecoveryReadiness::IndependentRecoveryRequired
    );
    let mut read = || {
        positron_kernel::RecoveryPassphrase::from_interactive(
            "public recovery passphrase fixture".to_owned(),
        )
    };
    instance.verify_recovery_bundle(&path, RecoveryUnlock::InteractivePassphrase(&mut read))?;
    assert_eq!(
        instance.backup_key_recovery_readiness()?,
        RecoveryReadiness::Verified
    );
    Ok(())
}

#[test]
fn refused_recovery_admission_does_not_prompt_or_create_an_artifact()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let roots = Roots::new()?;
    let export = roots.parent().join("refused-input");
    std::fs::create_dir(&export)?;
    std::fs::set_permissions(&export, std::fs::Permissions::from_mode(0o700))?;
    let path = std::fs::canonicalize(export)?.join("recovery.age");
    let instance =
        InstanceBootstrap::initialize(&roots.paths(), InitializationPlan::non_interactive())?;
    let mut reservations = Vec::new();
    for _ in 0..32 {
        match positron_kernel::RecoverySession::admit(
            &instance._authority,
            positron_kernel::RecoveryProtection::Passphrase,
        ) {
            Ok(reservation) => reservations.push(reservation),
            Err(positron_kernel::RecoveryFailure::Admission) => break,
            Err(failure) => return Err(failure.into()),
        }
    }
    assert!(
        reservations.len() < 32,
        "the canonical Governor must bound concurrent recovery work"
    );
    let prompted = std::cell::Cell::new(false);
    let result = instance.create_interactive_recovery_bundle(&path, || {
        prompted.set(true);
        positron_kernel::RecoveryPassphrase::from_interactive(
            "public refusal fixture phrase".to_owned(),
        )
    });
    assert_eq!(result, Err(positron_kernel::RecoveryFailure::Admission));
    assert!(!prompted.get());
    assert!(!path.exists());
    drop(reservations);
    Ok(())
}

#[test]
fn corrupt_existing_root_import_preserves_catalog_and_destination()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    for mode in [0o600, 0o644] {
        let roots = Roots::new()?;
        let paths = roots.paths();
        let export = roots.parent().join("existing-root-import");
        std::fs::create_dir(&export)?;
        std::fs::set_permissions(&export, std::fs::Permissions::from_mode(0o700))?;
        let bundle = std::fs::canonicalize(&export)?.join("recovery.age");
        let instance =
            InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
        let pin = instance.recovery_identity()?;
        let recipient = age::x25519::Identity::generate();
        instance.create_recovery_bundle(
            &bundle,
            &RecoveryRecipients::parse(&[recipient.to_public().to_string()])?,
        )?;
        drop(instance);
        let instance = InstanceBootstrap::reopen(&paths)?;
        let generation = instance.catalog_generation();
        drop(instance);
        let root = paths.secrets_root().join("local-root-key.v1");
        // Keep the original fixture key under an owner-only local Root filename, without copying it.
        let original = export.join("local-root-key.v1");
        std::fs::rename(&root, &original)?;
        std::fs::write(&root, b"corrupt existing root")?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(mode))?;
        assert!(
            InstanceBootstrap::import_recovery_bundle(
                &paths,
                &bundle,
                pin,
                RecoveryUnlock::Identity(&recipient)
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&root)?, b"corrupt existing root");
        assert_eq!(
            std::fs::metadata(&root)?.permissions().mode() & 0o7777,
            mode
        );
        std::fs::remove_file(&root)?;
        std::fs::rename(&original, &root)?;
        let restored = InstanceBootstrap::reopen(&paths)?;
        assert_eq!(restored.recovery_identity()?, pin);
        assert_eq!(restored.catalog_generation(), generation);
    }
    Ok(())
}
