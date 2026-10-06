use super::*;

#[test]
fn canonical_allowlist_admits_typed_configuration_and_crash_families() {
    let bundle = SupportBundle::build(
        [
            BundleMember::effective_configuration(b"local_key_file = <redacted>"),
            BundleMember::sanitized_crash_records(b"finding_code=PROCESS_EXIT"),
        ],
        BundleLimits::new(2, 12_000).expect("bounded fixture limits"),
    )
    .expect("typed canonical families are exportable");
    let rendered = String::from_utf8_lossy(bundle.archive());
    assert!(rendered.contains("effective-configuration.txt"));
    assert!(rendered.contains("sanitized-crash-records.txt"));
}

#[test]
fn compatibility_and_product_evidence_describe_their_limited_build_inputs() {
    let manifest =
        super::super::command::compatibility_manifest_evidence().expect("compatibility evidence");
    let identity = super::super::command::product_identity_evidence().expect("product identity");
    let expected_digest = {
        let mut digest = Sha256::new();
        for (scope, bytes) in super::super::command::COMPATIBILITY_INPUTS {
            digest.update(scope.as_bytes());
            digest.update([0]);
            digest.update(
                u64::try_from(bytes.len())
                    .expect("input length")
                    .to_be_bytes(),
            );
            digest.update(bytes);
        }
        format!("{:x}", digest.finalize())
    };
    assert!(manifest.contains("compatibility_manifest_version=1"));
    for evidence in [&manifest, &identity] {
        assert!(evidence.contains(&format!("compatibility_inputs_sha256={expected_digest}")));
        assert!(evidence.contains(
            "compatibility_inputs_scope=Cargo.lock,Cargo.toml,crates/positron/Cargo.toml,api/positron/v1/positron.proto,api/positron/v1/http.json,configuration/schema.json"
        ));
        assert!(evidence.contains("source_build_state=not_captured"));
        assert!(evidence.contains("source_build_evidence_scope=unavailable"));
        assert!(evidence.contains("source_build_evidence_owner=release_pipeline"));
        assert!(!evidence.contains("source_build_identity="));
    }
}

#[test]
fn canonical_release_identity_marks_unshipped_facets_as_not_shipped() {
    let manifest =
        super::super::command::compatibility_manifest_evidence().expect("compatibility evidence");
    for claim in [
        "query_contract=not_shipped",
        "receiver_contract=not_shipped",
        "crd_contract=not_shipped",
        "operator_contract=not_shipped",
        "backup_contract=not_shipped",
        "migration_graph=not_shipped",
    ] {
        assert!(manifest.contains(claim), "missing {claim}");
    }
}

#[test]
fn canonical_member_inventory_has_exactly_fourteen_closed_product_families() {
    let paths = super::Class::ALL.map(|class| class.path());
    assert_eq!(paths.len(), 14);
    assert_eq!(paths[0], "effective-configuration.txt");
    assert_eq!(paths[1], "compatibility-manifest.txt");
    assert_eq!(paths[2], "product-identity.txt");
    assert_eq!(paths[13], "sanitized-crash-records.txt");
    for path in paths {
        assert!(!path.contains("unavailable"));
    }
}

#[test]
fn closed_allowlist_excludes_secret_and_telemetry_canaries_and_declares_a_deterministic_bound() {
    let bundle = SupportBundle::build(
        [
            BundleMember::doctor_report(b"finding=storage_available"),
            BundleMember::operational_telemetry(b"phase=serving"),
            BundleMember::unclassified(b"tenant-telemetry-canary"),
            BundleMember::unclassified(b"api-key-secret-canary"),
        ],
        BundleLimits::new(2, 20_000).expect("limits"),
    )
    .expect("bundle");
    assert_eq!(bundle.included_member_count(), 2);
    assert_eq!(bundle.redaction_report().excluded_unknown_members(), 2);
    assert!(
        !bundle
            .archive()
            .windows(23)
            .any(|v| v == b"tenant-telemetry-canary")
    );
    assert!(
        !bundle
            .archive()
            .windows(21)
            .any(|v| v == b"api-key-secret-canary")
    );
    assert!(
        bundle
            .redaction_report()
            .declared_omissions()
            .contains(&"unknown_member_class")
    );
}

#[test]
fn archive_bound_omits_later_allowlisted_members_and_declares_truncation() {
    let payload = [b'x'; 6_000];
    let bundle = SupportBundle::build(
        [
            BundleMember::doctor_report(&payload),
            BundleMember::operational_telemetry(&payload),
        ],
        BundleLimits::new(2, 15_000).expect("limits"),
    )
    .expect("bounded archive");
    assert_eq!(bundle.included_member_count(), 1);
    assert!(
        bundle
            .redaction_report()
            .declared_omissions()
            .contains(&"archive_byte_limit")
    );
    assert!(bundle.archive().len() <= 15_000);
}

#[test]
fn offline_key_unavailability_is_declared_in_the_redaction_report() {
    let bundle = SupportBundle::build_authenticated(
        [BundleMember::doctor_report(b"finding=key_unavailable")],
        BundleLimits::new(1, 12_000).expect("limits"),
        super::super::ManifestAuthentication::UnsignedKeyUnavailableOffline,
    )
    .expect("offline bundle remains exportable with an explicit reason");
    assert!(
        bundle
            .archive()
            .windows(b"signature=unsigned_key_unavailable_offline".len())
            .any(|entry| entry == b"signature=unsigned_key_unavailable_offline")
    );
}

#[test]
fn encrypted_signed_bundle_report_declares_classes_pseudonymization_and_real_export_state() {
    let bundle = SupportBundle::build_authenticated(
        [
            BundleMember::doctor_report(b"finding=verified"),
            BundleMember::health_state(b"health=ready"),
        ],
        BundleLimits::new(2, 20_000).expect("limits"),
        super::super::ManifestAuthentication::UnsignedKeyUnavailableOffline,
    )
    .expect("bundle");
    let archive = bundle.archive();
    for expected in [
        b"included_classes=doctor,health_state".as_slice(),
        b"identifier_pseudonymization=ephemeral_per_bundle".as_slice(),
        b"archive_byte_limit=20000".as_slice(),
        b"elapsed_time_limit_seconds=30".as_slice(),
        b"encryption=age_x25519".as_slice(),
        b"signature=unsigned_key_unavailable_offline".as_slice(),
    ] {
        assert!(
            archive
                .windows(expected.len())
                .any(|window| window == expected),
            "missing {}",
            String::from_utf8_lossy(expected)
        );
    }
    assert!(
        !archive
            .windows(b"encryption=not_applied".len())
            .any(|window| window == b"encryption=not_applied")
    );
}

#[test]
fn native_age_recipient_parser_rejects_malformed_and_empty_recipient_sets() {
    assert!(AgeRecipients::parse(std::iter::empty::<&str>()).is_err());
    assert!(AgeRecipients::parse(["not-an-age-recipient"]).is_err());
}

#[test]
fn native_age_x25519_encryption_round_trips_the_standard_archive() {
    let identity = age::x25519::Identity::generate();
    let recipients = AgeRecipients::parse([identity.to_public().to_string()]).expect("recipient");
    let encrypted = recipients.encrypt(b"support-bundle-tar").expect("encrypt");
    let decryptor = age::Decryptor::new(&encrypted[..]).expect("age envelope");
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .expect("recipient decrypts");
    let mut decrypted = Vec::new();
    reader
        .read_to_end(&mut decrypted)
        .expect("read decrypted archive");
    assert_eq!(decrypted, b"support-bundle-tar");
}

#[test]
fn encrypted_signed_bundle_decrypts_to_a_report_bound_by_its_manifest()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
    use positron_kernel::MountQualification;
    use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-support-encrypted-signed-{nonce}"));
    let data = root.join("data");
    let secrets = root.join("secrets");
    fs::create_dir(&root)?;
    fs::create_dir(&data)?;
    fs::create_dir(&secrets)?;
    #[cfg(unix)]
    fs::set_permissions(
        &secrets,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )?;
    let paths = BootstrapPaths::new(&data, &secrets, MountQualification::LocalHost)?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let actor = instance.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let signer = instance.support_bundle_manifest_signer(actor)?;
    let bundle = SupportBundle::build_authenticated(
        [BundleMember::doctor_report(b"finding=verified")],
        BundleLimits::new(1, 12_000).map_err(|_| "limits")?,
        super::super::ManifestAuthentication::Signed(&signer),
    )
    .map_err(|_| "bundle")?;
    let recipient = age::x25519::Identity::generate();
    let ciphertext = AgeRecipients::parse([recipient.to_public().to_string()])
        .map_err(|_| "recipient")?
        .encrypt(bundle.archive())
        .map_err(|_| "encrypt")?;
    let decryptor = age::Decryptor::new(&ciphertext[..])?;
    let mut reader = decryptor.decrypt(std::iter::once(&recipient as &dyn age::Identity))?;
    let mut archive = Vec::new();
    reader.read_to_end(&mut archive)?;
    SupportBundle::verify_signed_archive(&archive, signer.identity()).map_err(|_| "binding")?;
    assert!(
        archive
            .windows(b"encryption=age_x25519".len())
            .any(|window| window == b"encryption=age_x25519")
    );
    drop(instance);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn ciphertext_budget_rejects_age_header_and_payload_overflow() {
    let identity = age::x25519::Identity::generate();
    let recipients = AgeRecipients::parse([identity.to_public().to_string()]).expect("recipient");
    assert!(recipients.encrypt_bounded(b"archive", 16).is_err());
}

#[test]
fn authorized_runtime_signer_authenticates_the_final_archive_and_detects_member_tampering()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
    use positron_kernel::MountQualification;
    use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-support-signature-{nonce}"));
    let data = root.join("data");
    let secrets = root.join("secrets");
    fs::create_dir(&root)?;
    fs::create_dir(&data)?;
    fs::create_dir(&secrets)?;
    #[cfg(unix)]
    fs::set_permissions(
        &secrets,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )?;
    let paths = BootstrapPaths::new(&data, &secrets, MountQualification::LocalHost)?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let actor = instance.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let signer = instance.support_bundle_manifest_signer(actor)?;
    let bundle = SupportBundle::build_authenticated(
        [BundleMember::doctor_report(b"finding=degraded")],
        BundleLimits::new(1, 12_000).expect("limits"),
        super::super::ManifestAuthentication::Signed(&signer),
    )
    .map_err(|_| "bundle creation")?;
    SupportBundle::verify_signed_archive(bundle.archive(), signer.identity())
        .map_err(|_| "archive verification")?;

    let mut tampered = bundle.archive().to_vec();
    let location = tampered
        .windows(b"finding=degraded".len())
        .position(|window| window == b"finding=degraded")
        .ok_or("doctor member is present")?;
    tampered[location] = b'F';
    assert!(SupportBundle::verify_signed_archive(&tampered, signer.identity()).is_err());

    drop(instance);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn signature_attachment_cannot_bypass_the_final_archive_bound()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
    use positron_kernel::MountQualification;
    use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-support-bound-{nonce}"));
    let data = root.join("data");
    let secrets = root.join("secrets");
    fs::create_dir(&root)?;
    fs::create_dir(&data)?;
    fs::create_dir(&secrets)?;
    #[cfg(unix)]
    fs::set_permissions(
        &secrets,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )?;
    let paths = BootstrapPaths::new(&data, &secrets, MountQualification::LocalHost)?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let actor = instance.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let signer = instance.support_bundle_manifest_signer(actor)?;
    let payload = vec![b'x'; 6_000];
    assert!(
        SupportBundle::build_authenticated(
            [BundleMember::doctor_report(&payload)],
            BundleLimits::new(1, 10_240).expect("minimum tar bound"),
            super::super::ManifestAuthentication::Signed(&signer),
        )
        .is_err()
    );
    drop(instance);
    fs::remove_dir_all(root)?;
    Ok(())
}
