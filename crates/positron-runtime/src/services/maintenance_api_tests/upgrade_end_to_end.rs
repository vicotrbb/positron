//! Native source bytes, real repository and public lifecycle; target version is synthetic.
use super::*;
use crate::upgrade::{
    OfflineUpgradeSession, UpgradeArtifactInput, UpgradeFailure, UpgradeRequest,
    UpgradeStartupVerification,
};
use positron_governance::{
    AdministrativeIdempotencyKey, DurableOperationAdministration as Administration,
    DurableOperationStatus, UpgradePublicationOutcome, UpgradeStage,
};
use positron_kernel::release_manifest::ProductVersion;
use sha2::{Digest, Sha256};
use std::time::Instant;

#[path = "upgrade_end_to_end/admission_race.rs"]
mod admission_race;
#[path = "upgrade_end_to_end/source.rs"]
mod source;

#[test]
fn native_upgrade_acceptance_and_queued_lookup_preserve_one_intent()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let _drained = source::drain_source_case(true, false, false, true)?;
    Ok(())
}

#[test]
fn native_upgrade_preserves_query_through_real_snapshot_and_verified_restart()
-> Result<(), Box<dyn std::error::Error>> {
    full_lifecycle(false)
}
#[test]
fn native_http_upgrade_preserves_query_through_verified_restart()
-> Result<(), Box<dyn std::error::Error>> {
    full_lifecycle(true)
}
#[inline(never)]
fn full_lifecycle(http: bool) -> Result<(), Box<dyn std::error::Error>> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let drained = drain_source(http)?;
    publish_offline(&drained)?;
    verify_target(drained)
}
#[inline(never)]
pub(super) fn publish_offline(drained: &DrainedFixture) -> Result<(), Box<dyn std::error::Error>> {
    let mut session = snapshot_offline(drained)?;
    let DrainedFixture {
        configuration,
        target,
        ..
    } = drained;
    assert_eq!(
        session.publish(target)?.upgrade_stage(),
        Some(UpgradeStage::AwaitingRestart)
    );
    drop(session);
    if let Some(installation) = configuration.installed_release() {
        fs::write(
            installation.current_manifest_file().as_path(),
            target.signed_bytes(),
        )?;
        if let Some(path) = installation.current_inventory_file() {
            fs::write(
                path.as_path(),
                crate::upgrade::fixture_metadata::complete_metadata(target.manifest())?.1,
            )?;
        }
    }
    Ok(())
}
#[inline(never)]
pub(super) fn snapshot_offline(
    drained: &DrainedFixture,
) -> Result<OfflineUpgradeSession, Box<dyn std::error::Error>> {
    let DrainedFixture {
        fixture,
        configuration,
        id,
        ..
    } = drained;
    let id = *id;
    let drained_binding = cold_binding(fixture, configuration, id)?;
    let wait = Instant::now() + Duration::from_secs(12);
    let mut session = loop {
        match OfflineUpgradeSession::begin(&fixture.paths()?, configuration, id) {
            Ok(session) => break session,
            Err(UpgradeFailure::SnapshotUnavailable) if Instant::now() < wait => {
                assert_eq!(
                    cold_binding(fixture, configuration, id)?,
                    drained_binding,
                    "clock wait must preserve operation and Catalog"
                );
                std::thread::sleep(Duration::from_millis(50))
            },
            Err(error) => return Err(format!("offline begin {error:?}").into()),
        }
    };
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let operation = advance_once(&mut session, deadline)?;
        if operation.upgrade_stage() == Some(UpgradeStage::Publishing) {
            break;
        }
        assert!(
            !operation.status().is_terminal(),
            "unexpected terminal {operation:?}"
        );
        assert!(Instant::now() < deadline, "snapshot deadline {operation:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(session.rollback_snapshot()?.is_some());
    Ok(session)
}

#[inline(never)]
fn verify_target(drained: DrainedFixture) -> Result<(), Box<dyn std::error::Error>> {
    let DrainedFixture {
        fixture,
        configuration,
        query,
        target,
        version,
        id,
    } = drained;
    let listeners = crate::process_lifecycle::ObservingListeners::default();
    let tasks = crate::process_lifecycle::ObservingTasks::default();
    let mut verification = UpgradeStartupVerification::new(target, Some(query.clone()))?;
    verification.fixture_version = Some(version);
    let target_process = ApplicationRuntime::start(
        ServeConfiguration::new(fixture.paths()?, InitializationMode::ExistingOnly)
            .with_effective_configuration(configuration)
            .with_upgrade_verification(verification),
        HostInputs::new(&listeners, &tasks),
    )?;
    verify_readiness(&target_process, id, &query)?;
    assert_eq!(
        target_process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful
    );
    Ok(())
}

pub(super) fn fixture_release(
    epoch: u32,
    version: ProductVersion,
    digest: [u8; 32],
    size: u64,
) -> Result<positron_kernel::release_manifest::VerifiedReleaseManifest, Box<dyn std::error::Error>>
{
    use positron_kernel::release_manifest::{ProjectTrustRoot, SignedReleaseManifest};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let mut manifest = crate::upgrade::signed_fixture_release(version, digest, size)?
        .manifest()
        .clone();
    manifest.compatibility.persistent.readable_epochs = vec![epoch];
    manifest.compatibility.persistent.writable_epoch = epoch;
    manifest = crate::upgrade::fixture_metadata::complete_metadata(&manifest)?.0;
    let key = Ed25519KeyPair::from_seed_unchecked(&[0x91; 32]).map_err(|_| "fixture key")?;
    let mut message = b"positron.release-manifest.v1\0".to_vec();
    message.extend(manifest.canonical_bytes()?);
    let signature = key
        .sign(&message)
        .as_ref()
        .try_into()
        .map_err(|_| "fixture signature")?;
    Ok(
        SignedReleaseManifest::new(manifest, signature)?.verify(&ProjectTrustRoot::new(
            key.public_key()
                .as_ref()
                .try_into()
                .map_err(|_| "fixture root")?,
        ))?,
    )
}

#[inline(never)]
fn cold_binding(
    fixture: &Fixture,
    configuration: &positron_config::EffectiveConfiguration,
    id: positron_governance::OperationId,
) -> Result<
    (
        positron_kernel::CatalogGenerationId,
        Box<positron_governance::DurableOperation>,
    ),
    Box<dyn std::error::Error>,
> {
    let instance = crate::InstanceBootstrap::reopen_configured(&fixture.paths()?, configuration)?;
    let catalog = open_catalog(&instance)?;
    Ok((
        catalog.pin()?.identity(),
        Box::new(Administration::inspect(&catalog, id)?.ok_or("cold operation")?),
    ))
}

#[inline(never)]
fn successor_release(
    target: positron_kernel::release_manifest::VerifiedReleaseManifest,
) -> Result<positron_kernel::release_manifest::VerifiedReleaseManifest, Box<dyn std::error::Error>>
{
    use positron_kernel::release_manifest::{ReleaseSigningPublicKey, SignedReleaseManifest};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let pair = Ed25519KeyPair::from_seed_unchecked(&[0x92; 32]).map_err(|_| "successor")?;
    let manifest = target.manifest().clone();
    Ok(SignedReleaseManifest::new(
        manifest.clone(),
        pair.sign(&manifest.signing_message()?)
            .as_ref()
            .try_into()?,
    )?
    .verify_signature(&ReleaseSigningPublicKey::new(
        pair.public_key().as_ref().try_into()?,
    ))?)
}
pub(super) fn installed_configuration(
    fixture: &Fixture,
    export: &std::path::Path,
    source: &positron_kernel::release_manifest::VerifiedReleaseManifest,
    target: &positron_kernel::release_manifest::VerifiedReleaseManifest,
    executable: &std::path::Path,
    query: Option<&str>,
) -> Result<positron_config::EffectiveConfiguration, Box<dyn std::error::Error>> {
    use ring::signature::Ed25519KeyPair;
    let root = export.join("project.pub");
    let current = export.join("current.manifest");
    let candidate = export.join("candidate.manifest");
    let key = Ed25519KeyPair::from_seed_unchecked(&[0x91; 32]).map_err(|_| "installed key")?;
    let mut installed = positron_release::InstalledReleaseTrust::from_bytes(
        &crate::upgrade::installed_trust(&key)?,
    )?;
    let successor =
        Ed25519KeyPair::from_seed_unchecked(&[0x92; 32]).map_err(|_| "successor key")?;
    use ring::signature::KeyPair;
    let successor_public = successor.public_key().as_ref().try_into()?;
    if positron_kernel::release_manifest::SignedReleaseManifest::from_bytes(target.signed_bytes())?
        .verify_signature(
            &positron_kernel::release_manifest::ReleaseSigningPublicKey::new(successor_public),
        )
        .is_ok()
    {
        let mut snapshot = positron_release::TrustSnapshot::from_bytes(
            installed.signed_snapshot.get(64..).ok_or("snapshot")?,
        )?;
        let mut successor_identity = snapshot.identities.first().ok_or("identity")?.clone();
        successor_identity.public_key = successor_public;
        successor_identity.purpose = positron_release::KeyPurpose::Release;
        for identity in &mut snapshot.identities {
            if identity.purpose == positron_release::KeyPurpose::Release {
                identity.purpose = positron_release::KeyPurpose::InstalledSource;
            }
        }
        snapshot.identities.push(successor_identity);
        installed.release_signer = successor_public;
        installed.signed_snapshot = snapshot.sign(&key)?;
    }
    fs::write(&root, installed.canonical_bytes()?)?;
    fs::write(&current, source.signed_bytes())?;
    fs::write(&candidate, target.signed_bytes())?;
    let current_inventory = export.join("current.inventory.json");
    fs::write(
        &current_inventory,
        crate::upgrade::fixture_metadata::complete_metadata(source.manifest())?.1,
    )?;
    let target_paths =
        crate::upgrade::fixture_metadata::artifact_paths(target.manifest(), executable, export)?;
    let path = fixture.migration_configuration()?;
    let storage = path.parent().ok_or("config directory")?;
    let mut text = format!(
        "schema_version=1\n[storage]\ndata_directory={:?}\nsecrets_directory={:?}\n",
        storage.join("data"),
        storage.join("secrets")
    );
    let artifacts = target
        .manifest()
        .artifacts
        .iter()
        .zip(&target_paths)
        .map(|(_, path)| format!("{path:?}"))
        .collect::<Vec<_>>()
        .join(",");
    text.push_str(&format!("\n[release.installation]\nproject_trust_root_file={root:?}\ncurrent_manifest_file={current:?}\ncurrent_inventory_file={current_inventory:?}\ncandidate_manifest_file={candidate:?}\ncandidate_artifact_files=[{artifacts}]\n"));
    if let Some(query) = query {
        use std::os::unix::fs::PermissionsExt;
        let credential = export.join("query.credential");
        fs::write(&credential, query)?;
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o600))?;
        text.push_str(&format!("query_credential_file={credential:?}\n"));
    }
    fs::write(&path, text)?;
    Ok(positron_config::resolve(
        positron_config::ConfigurationInputs::try_from_sources(
            Some(&path),
            [] as [(&str, &str); 0],
            [] as [(&str, &str); 0],
        )
        .map_err(|e| format!("installed config {e:?}"))?,
    )?)
}

pub(super) struct DrainedFixture {
    pub(super) fixture: Fixture,
    pub(super) configuration: Arc<positron_config::EffectiveConfiguration>,
    pub(super) query: String,
    pub(super) target: positron_kernel::release_manifest::VerifiedReleaseManifest,
    pub(super) version: ProductVersion,
    pub(super) id: positron_governance::OperationId,
}
#[inline(never)]
pub(super) fn drain_source(http: bool) -> Result<DrainedFixture, Box<dyn std::error::Error>> {
    source::drain_source_case(http, false, false, false)
}

pub(super) fn drain_suspended_source() -> Result<DrainedFixture, Box<dyn std::error::Error>> {
    source::drain_source_case(false, true, false, false)
}

pub(super) fn crash_source_before_drain() -> Result<DrainedFixture, Box<dyn std::error::Error>> {
    source::drain_source_case(false, false, true, false)
}

pub(super) fn drain_installed_source() -> Result<DrainedFixture, Box<dyn std::error::Error>> {
    source::drain_source_case(false, false, false, false)
}

#[inline(never)]
pub(super) fn verify_readiness(
    target_process: &crate::RunningProcess,
    id: positron_governance::OperationId,
    query: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let services = target_process.services().ok_or("target services")?;
    assert_eq!(
        services.query_log_bodies(
            query,
            "logs | range query_time 0 100 | limit 16",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
        )?,
        ["upgrade-lifecycle-preserved"]
    );
    let catalog = open_catalog(&services.instance)?;
    let operation = Administration::inspect(&catalog, id)?.ok_or("upgrade operation")?;
    assert_eq!(
        operation.status(),
        DurableOperationStatus::Succeeded,
        "{operation:?}"
    );
    let publication =
        Administration::current_upgrade_publication(&catalog)?.ok_or("publication")?;
    assert_eq!(publication.operation_id(), id);
    assert!(matches!(
        publication.outcome(),
        UpgradePublicationOutcome::Verified { .. }
    ));
    let report_id = publication.verification_report().ok_or("report identity")?;
    assert_eq!(operation.upgrade_verification_report(), Some(report_id));
    let snapshot = catalog.pin()?;
    let object = snapshot
        .object_identities()
        .find(|id| id.to_bytes() == report_id)
        .ok_or("report object")?;
    let report = positron_kernel::upgrade_verification::UpgradeVerificationReport::from_bytes(
        snapshot.object(object)?.ok_or("report bytes")?,
    )?;
    let (_, governance) = snapshot.governance_object()?;
    report.verify(positron_kernel::BootstrapIntegrityIdentity::from_pinned(
        governance.integrity_public_key(),
        governance.integrity_key_fingerprint(),
    )?)?;
    assert_eq!(report.input().operation(), id.to_bytes());
    assert!(matches!(
        report.input().query(),
        positron_kernel::upgrade_verification::UpgradeQueryVerification::Executed { .. }
    ));
    drop(snapshot);
    drop(catalog);
    drop(services);
    Ok(())
}

#[inline(never)]
fn advance_once(
    session: &mut OfflineUpgradeSession,
    deadline: Instant,
) -> Result<Box<positron_governance::DurableOperation>, UpgradeFailure> {
    session.advance(deadline).map(Box::new)
}

fn refuse_revoked_retained_target(
    process: &crate::RunningProcess,
    configuration: &positron_config::EffectiveConfiguration,
    administrator: &str,
    request: &UpgradeRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    use ring::signature::Ed25519KeyPair;
    let path = configuration
        .installed_release()
        .ok_or("installed trust")?
        .project_trust_root_file()
        .as_path();
    let mut installed = positron_release::InstalledReleaseTrust::from_bytes(&fs::read(path)?)?;
    let mut snapshot = positron_release::TrustSnapshot::from_bytes(
        installed.signed_snapshot.get(64..).ok_or("snapshot")?,
    )?;
    let key = Ed25519KeyPair::from_seed_unchecked(&[0x91; 32]).map_err(|_| "key")?;
    // The retained request was qualified under the previous snapshot. Publish
    // explicit newer test snapshots and floors, without a trust rollback.
    snapshot.sequence += 1;
    snapshot.revoked_manifests.push(request.target.digest());
    installed.root.minimum_sequence = snapshot.sequence;
    installed.signed_snapshot = snapshot.sign(&key)?;
    fs::write(path, installed.canonical_bytes()?)?;
    assert!(
        matches!(
            process.accept_upgrade(administrator, request.clone()),
            Err(UpgradeFailure::AuthenticationFailed)
        ),
        "a retained target must recheck currently installed revocation"
    );
    assert_eq!(process.health().phase(), crate::ProcessPhase::Serving);
    snapshot.sequence += 1;
    snapshot.revoked_manifests.clear();
    installed.root.minimum_sequence = snapshot.sequence;
    installed.signed_snapshot = snapshot.sign(&key)?;
    fs::write(path, installed.canonical_bytes()?)?;
    Ok(())
}
