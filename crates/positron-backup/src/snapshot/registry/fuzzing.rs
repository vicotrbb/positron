//! Valid signed seeds reach the parsers behind the signature boundary.
use super::*;
#[path = "../../../tests/shared/azure_admission.rs"]
mod admission;
#[path = "../../../tests/shared/native_authority.rs"]
mod native_authority;
#[path = "snapshot_cursor_fuzz.rs"]
mod snapshot_cursor;
pub(crate) async fn fuzz_control_frames(data: &[u8]) -> bool {
    use positron_kernel::{BootstrapKeyCustody, BootstrapObjectPurpose, InstanceId};
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().expect("capture fuzz custody");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("custody permissions");
    let custody = BootstrapKeyCustody::initialize(directory.path()).expect("custody");
    let instance = InstanceId::new([2; 16]).expect("instance");
    let protected = custody
        .protect(instance, BootstrapObjectPurpose::Initialized, &[7; 32])
        .expect("integrity custody");
    let signer = custody
        .backup_control_signer(instance, &protected)
        .expect("signer");
    let identity = RepositoryIdentity::local(
        [1; 16],
        instance.to_bytes(),
        signer.identity().fingerprint(),
        directory.path(),
    )
    .expect("repository");
    let manifest = BackupManifest::new(
        [5; 16],
        identity.clone(),
        BackupCatalogIdentity::new(17, [6; 32], 2, 9, [3; 32])
            .expect("catalog")
            .with_capture_binding([0x81; 16], [0x82; 32])
            .expect("capture binding"),
        BackupRetention::new(1000, 2000).expect("retention"),
        [8; 32],
        vec![BackupObject::new([3; 32], 64, 0, [4; 32], 64).expect("object")],
    )
    .expect("manifest");
    let manifest_bytes = manifest.signed_bytes(&signer).expect("signed manifest");
    let _ = BackupVerificationReport::verify(data, &identity, signer.identity());
    let _ = BackupRestoreReport::verify(data, &identity, signer.identity());
    assert_eq!(
        BackupManifest::verify(&manifest_bytes, &identity, signer.identity())
            .expect("valid manifest"),
        manifest
    );
    let receipt = BackupReceipt {
        snapshot: [5; 16],
        manifest: ImmutableObject::new(manifest_bytes.clone())
            .expect("manifest object")
            .id(),
        created: 1000,
        retain_until: 2000,
    };
    let key = KeyReference {
        context: [8; 32],
        tenant: [9; 16],
        epoch: 1,
        fingerprint: [10; 32],
        object: ObjectId::from_checksum([11; 32]),
    };
    let mut generation = Generation {
        number: 1,
        previous: [0; 32],
        repository: identity.clone(),
        snapshots: Vec::new(),
        reservations: Vec::new(),
        keys: vec![key],
        overlays: Vec::new(),
        tombstones: Vec::new(),
        claims: Vec::new(),
    };
    match data.first().copied().unwrap_or(0) % 3 {
        0 => generation.snapshots.push(receipt),
        1 => generation.reservations.push(receipt),
        _ => generation.claims.push(DeletionClaim {
            owner: [12; 16],
            reason: if data.get(1).copied().unwrap_or(0) & 1 == 0 {
                BackupCleanupReason::Retention
            } else {
                BackupCleanupReason::Cancellation
            },
            receipt,
            remaining: vec![ObjectId::from_checksum([13; 32])],
            deleted: 1,
            absent: 2,
            shared: 3,
        }),
    }
    use positron_kernel::key_provider::{
        EnvelopeContext, KeyEnvelope, KeyScope, ProviderFamily, ProviderKeyUri, WrappingAlgorithm,
    };
    let envelope = |version: &str| {
        KeyEnvelope::from_provider_response(
            ProviderKeyUri::new(ProviderFamily::LocalFile, "root", version).expect("root URI"),
            EnvelopeContext::new([2; 16], KeyScope::System, [21; 32], 1, 1).expect("root context"),
            WrappingAlgorithm::Aes256Kwp,
            vec![22; 40],
        )
        .expect("root envelope")
    };
    let overlay = BackupEnvelopeOverlay::new(
        receipt.snapshot,
        receipt.manifest,
        key.context,
        [23; 16],
        envelope("one"),
        envelope("two"),
    )
    .expect("overlay");
    let overlay_bytes = overlay
        .signed_bytes(&identity, &signer)
        .expect("signed overlay");
    generation.overlays.push(OverlayReference {
        snapshot: receipt.snapshot,
        target: [24; 32],
        object: ImmutableObject::new(overlay_bytes.clone())
            .expect("overlay object")
            .id(),
    });
    let tombstone =
        BackupPurgeTombstone::new([25; 16], "purged-tenant", [26; 16], 1001).expect("tombstone");
    let tombstone_bytes = tombstone
        .signed_bytes(&identity, &signer)
        .expect("signed tombstone");
    let fence_object = ObjectId::from_checksum([29; 32]);
    let fence = TenantKeyPurgeFence::new(fence_object, &tombstone, &identity, &signer)
        .expect("signed fence");
    assert_eq!(
        TenantKeyPurgeFence::verify(fence.bytes(), &identity, fence_object).expect("valid fence"),
        fence
    );
    let _ = TenantKeyPurgeFence::verify(data, &identity, fence_object);
    let mut corrupted_fence = fence.bytes().to_vec();
    mutate(&mut corrupted_fence, data);
    if let Ok(decoded) = TenantKeyPurgeFence::verify(&corrupted_fence, &identity, fence_object) {
        assert_eq!(decoded, fence);
    }
    generation.tombstones.push(tombstone);
    let mut report = b"POSBRR02".to_vec();
    report.extend_from_slice(&[3; 16]);
    report.extend_from_slice(&[4; 32]);
    report.extend_from_slice(&identity.encode());
    for value in 5..9 {
        report.extend_from_slice(&[value; 32]);
    }
    report.extend_from_slice(&1u64.to_be_bytes());
    report.extend_from_slice(&2u64.to_be_bytes());
    report.extend_from_slice(&1u32.to_be_bytes());
    report.extend_from_slice(&0u64.to_be_bytes());
    report.extend_from_slice(&[9; 32]);
    report.extend_from_slice(&1u32.to_be_bytes());
    report.extend_from_slice(&1u32.to_be_bytes());
    report.extend_from_slice(&[25; 16]);
    report.extend_from_slice(&[1, 1, 1]);
    let report_bytes = super::super::codec::sign(report, &signer).expect("signed restore report");
    BackupRestoreReport::verify(&report_bytes, &identity, signer.identity())
        .expect("valid restore report");
    let registry_bytes = generation.signed_bytes(&signer).expect("signed registry");
    Generation::verify(&registry_bytes, &identity, signer.identity()).expect("valid registry");
    for (kind, bytes) in [
        (0, manifest_bytes),
        (1, registry_bytes),
        (2, overlay_bytes),
        (3, tombstone_bytes),
        (4, report_bytes),
    ] {
        let mut payload = super::super::codec::verify(&bytes, signer.identity())
            .expect("seed signature")
            .to_vec();
        for mutation in data.chunks(3).take(32) {
            if let [high, low, value] = mutation {
                let offset = usize::from(u16::from_be_bytes([*high, *low])) % payload.len();
                if let Some(byte) = payload.get_mut(offset) {
                    *byte ^= *value;
                }
            }
        }
        let mutated = super::super::codec::sign(payload, &signer).expect("bounded signed mutation");
        if kind == 0 {
            let _ = BackupManifest::verify(&mutated, &identity, signer.identity());
        } else if kind == 1 {
            let _ = Generation::verify(&mutated, &identity, signer.identity());
        } else if kind == 2 {
            let _ = BackupEnvelopeOverlay::verify(&mutated, &identity, signer.identity());
        } else if kind == 3 {
            let _ = BackupPurgeTombstone::verify(&mutated, &identity, signer.identity());
        } else {
            let _ = BackupRestoreReport::verify(&mutated, &identity, signer.identity());
        }
        let mut corrupt = mutated;
        if let Some(byte) = corrupt.last_mut() {
            *byte ^= 1;
        }
        assert!(super::super::codec::verify(&corrupt, signer.identity()).is_err());
    }
    let _ = BackupListCursor::decode(data);
    let _ = super::super::BackupCaptureContext::decode(data, &identity);
    let transfer = BackupTransfer::start(&manifest).expect("valid transfer");
    assert_eq!(
        BackupTransfer::decode(&transfer.encode(), &manifest).expect("seed checkpoint"),
        transfer
    );
    let envelope =
        BackupKeyEnvelope::new([9; 16], 1, [10; 32], vec![0x62; 32]).expect("key envelope");
    let context = BackupCaptureContext::new(
        identity.clone(),
        BackupRetention::new(1000, 2000).expect("retention"),
        vec![envelope],
    )
    .expect("context");
    let context_bytes = context.encode().expect("context bytes");
    assert_eq!(
        BackupCaptureContext::decode(&context_bytes, &identity)
            .expect("valid context")
            .encode()
            .expect("canonical context"),
        context_bytes
    );
    let registration = BackupRepositoryRegistration::new(
        identity.clone(),
        directory.path().to_str().expect("native path"),
    )
    .expect("registration");
    let registration_bytes = registration.encode().expect("registration bytes");
    assert_eq!(
        BackupRepositoryRegistration::decode(&registration_bytes)
            .expect("valid registration")
            .expect("matching magic")
            .encode()
            .expect("canonical registration"),
        registration_bytes
    );
    for mut bytes in [transfer.encode(), context_bytes, registration_bytes] {
        mutate(&mut bytes, data);
        for length in [bytes.len(), bytes.len().saturating_sub(1)] {
            let payload = bytes.get(..length).expect("bounded prefix");
            if let Ok(value) = BackupTransfer::decode(payload, &manifest) {
                assert_eq!(
                    BackupTransfer::decode(&value.encode(), &manifest).expect("canonical transfer"),
                    value
                );
            }
            if let Ok(value) = BackupCaptureContext::decode(payload, &identity) {
                assert_eq!(value.encode().expect("accepted context"), payload);
            }
            if let Ok(Some(value)) = BackupRepositoryRegistration::decode(payload) {
                assert_eq!(value.encode().expect("accepted registration"), payload);
            }
        }
    }
    let required =
        positron_kernel::ResourceAmounts::new([96 * 1024 * 1024, 1, 1, 0, 1, 0, 1, 1, 1, 8, 16384]);
    admission::admitted(required, |resources| async move {
        fuzz_cleanup(data, directory.path(), &signer, &resources).await;
        Ok(())
    })
    .await
    .is_ok()
}

fn mutate(bytes: &mut [u8], data: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    for mutation in data.chunks(3).take(32) {
        if let [high, low, value] = mutation {
            let offset = usize::from(u16::from_be_bytes([*high, *low])) % bytes.len();
            if let Some(byte) = bytes.get_mut(offset) {
                *byte ^= *value;
            }
        }
    }
}
async fn fuzz_registry_cursor(
    publisher: &BackupPublisher<'_>,
    signer: &BackupControlSigner,
    data: &[u8],
) {
    let owner = [0x71; 16];
    let request = [0x72; 32];
    let state = publisher
        .begin_registry_verification(owner, request)
        .await
        .expect("cursor seed");
    let bytes = publisher
        .registry_verification_checkpoint(&state)
        .expect("signed cursor");
    assert_eq!(bytes.len(), 333);
    let resumed = publisher
        .resume_registry_verification(&bytes, owner, request)
        .expect("valid cursor");
    assert_eq!(
        publisher
            .registry_verification_checkpoint(&resumed)
            .expect("canonical cursor"),
        bytes
    );
    assert!(
        publisher
            .resume_registry_verification(&bytes, [0x73; 16], request)
            .is_err()
    );
    assert!(
        publisher
            .resume_registry_verification(&bytes, owner, [0x74; 32])
            .is_err()
    );
    let _ = publisher.resume_registry_verification(data, owner, request);
    for length in [0, 8, 268, 269, 332] {
        assert!(
            publisher
                .resume_registry_verification(
                    bytes.get(..length).expect("cursor prefix"),
                    owner,
                    request
                )
                .is_err()
        );
    }
    let payload = super::super::codec::verify(&bytes, signer.identity()).expect("cursor signature");
    // Re-sign each field mutation so validation past the integrity boundary is reached.
    for offset in [8, 40, 56, 88, 152, 184, 216, 248, 256, 264, 268] {
        let mut changed = payload.to_vec();
        if offset == 152 && payload.get(268) == Some(&1) {
            changed.get_mut(152..184).expect("head").fill(0);
        } else {
            *changed.get_mut(offset).expect("cursor field") ^= 0xff;
        }
        let signed = super::super::codec::sign(changed, signer).expect("signed cursor field");
        assert!(
            publisher
                .resume_registry_verification(&signed, owner, request)
                .is_err()
        );
    }
    // A valid in-progress walk and the exact generation limit exercise count/sequence coherence.
    let mut walk = payload.to_vec();
    for range in [152..184, 184..216, 216..248] {
        walk.get_mut(range).expect("head fields").fill(0x75);
    }
    walk.get_mut(248..256)
        .expect("expected")
        .copy_from_slice(&1u64.to_be_bytes());
    walk.get_mut(256..264)
        .expect("number")
        .copy_from_slice(&65_537u64.to_be_bytes());
    walk.get_mut(264..268)
        .expect("count")
        .copy_from_slice(&65_536u32.to_be_bytes());
    *walk.get_mut(268).expect("stage") = 1;
    let signed = super::super::codec::sign(walk.clone(), signer).expect("signed valid walk");
    publisher
        .resume_registry_verification(&signed, owner, request)
        .expect("bounded coherent walk");
    for (range, value) in [
        (264..268, 65_537u32.to_be_bytes().to_vec()),
        (256..264, 65_536u64.to_be_bytes().to_vec()),
    ] {
        let mut invalid = walk.clone();
        invalid
            .get_mut(range)
            .expect("sequence field")
            .copy_from_slice(&value);
        let signed = super::super::codec::sign(invalid, signer).expect("signed invalid walk");
        assert!(
            publisher
                .resume_registry_verification(&signed, owner, request)
                .is_err()
        );
    }
    let mut arbitrary = payload.to_vec();
    mutate(&mut arbitrary, data);
    let signed = super::super::codec::sign(arbitrary, signer).expect("signed fuzz cursor");
    if let Ok(state) = publisher.resume_registry_verification(&signed, owner, request) {
        assert_eq!(
            publisher
                .registry_verification_checkpoint(&state)
                .expect("accepted cursor"),
            signed
        );
    }
    let mut corrupt = bytes;
    *corrupt.last_mut().expect("signature") ^= 1;
    assert!(
        publisher
            .resume_registry_verification(&corrupt, owner, request)
            .is_err()
    );
}

async fn complete_registry_cursor(publisher: &BackupPublisher<'_>) -> BackupRegistryVerification {
    let mut state = publisher
        .begin_registry_verification([0x79; 16], [0x7a; 32])
        .await
        .expect("cold cursor");
    for _ in 0..13 {
        if state.complete().expect("cursor state") {
            return state;
        }
        publisher
            .registry_verification_step(&mut state)
            .await
            .expect("bounded ancestry step");
    }
    assert!(
        state.complete().expect("cursor state"),
        "tiny lifecycle ancestry must finish within twelve frames plus head recheck"
    );
    state
}

async fn fuzz_cleanup(
    data: &[u8],
    root: &std::path::Path,
    signer: &BackupControlSigner,
    resources: &positron_kernel::NativeAwsResources,
) {
    use crate::{LocalFault, LocalFaultEffect, LocalFaultPoint, LocalRepository};
    use std::os::unix::fs::PermissionsExt;
    let path = root.join("repository");
    std::fs::create_dir(&path).expect("isolated snapshot repository");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .expect("repository permissions");
    let identity =
        RepositoryIdentity::local([20; 16], [2; 16], signer.identity().fingerprint(), &path)
            .expect("snapshot identity");
    let repository = LocalRepository::initialize(&path, identity.clone())
        .await
        .expect("snapshot repository");
    let object = ImmutableObject::new(vec![0x41; 16]).expect("small shared object");
    repository
        .put_if_absent(object.clone())
        .await
        .expect("shared ciphertext");
    let envelope = BackupKeyEnvelope::new([9; 16], 1, [10; 32], vec![0x62; 32]).expect("envelope");
    let envelopes = std::slice::from_ref(&envelope);
    let context = BackupPublisher::key_context(envelopes).expect("key context");
    let manifest = |snapshot| {
        BackupManifest::new(
            snapshot,
            identity.clone(),
            BackupCatalogIdentity::new(17, [6; 32], 2, 9, [3; 32])
                .expect("catalog")
                .with_capture_binding([0x81; 16], [0x82; 32])
                .expect("capture binding"),
            BackupRetention::new(1000, 2000).expect("retention"),
            context,
            vec![BackupObject::new([3; 32], 16, 0, object.id().checksum(), 16).expect("extent")],
        )
        .expect("small manifest")
    };
    let first = manifest([21; 16]);
    let second = manifest([22; 16]);
    let publisher = BackupPublisher::new(&repository, &identity, signer)
        .with_control_resources(resources, 0)
        .expect("live Maintenance control grant");
    fuzz_registry_cursor(&publisher, signer, data).await;
    publisher
        .reserve(&first, envelopes)
        .await
        .expect("first reservation");
    publisher
        .reserve(&second, envelopes)
        .await
        .expect("shared reservation");
    // Only the fully published candidate prepares keys; the first stays pending.
    assert_eq!(
        publisher.prepare_key_step(&second, envelopes, 2).await,
        Err(RepositoryFailure::InvalidInput)
    );
    let mutated_next = u32::from(data.get(1).copied().unwrap_or(0));
    let result = publisher
        .prepare_key_step(&second, envelopes, mutated_next)
        .await;
    if mutated_next > 1 {
        assert_eq!(result, Err(RepositoryFailure::InvalidInput));
    } else {
        assert_eq!(result.expect("valid key cursor"), 1);
    }
    let next_key = publisher
        .prepare_key_step(&second, envelopes, 0)
        .await
        .expect("one key preparation");
    assert_eq!(next_key, 1);
    assert_eq!(
        publisher
            .prepare_key_step(&second, envelopes, next_key)
            .await
            .expect("complete key preparation"),
        next_key
    );
    let published = publisher
        .publish(&second, envelopes)
        .await
        .expect("protected publication");
    fuzz_registry_cursor(&publisher, signer, data).await;
    snapshot_cursor::exercise(&publisher, signer, data).await;
    assert_eq!(
        publisher
            .prepare_cancellation(second.snapshot_id(), published.manifest().checksum())
            .await
            .err(),
        Some(RepositoryFailure::PreconditionFailed)
    );
    let retention = data.first().copied().unwrap_or(0) & 1 == 0;
    let manifest_id = ImmutableObject::new(first.signed_bytes(signer).expect("signed candidate"))
        .expect("manifest object")
        .id();
    let owner = if retention {
        [23; 16]
    } else {
        first.snapshot_id()
    };
    let mut plan = if retention {
        publisher
            .publish(&first, envelopes)
            .await
            .expect("expiry publication");
        publisher
            .prepare_expiry(owner, first.snapshot_id(), manifest_id.checksum())
            .await
            .expect("expiry plan")
    } else {
        publisher
            .prepare_cancellation(first.snapshot_id(), manifest_id.checksum())
            .await
            .expect("cancel plan")
    };
    assert!(publisher.claim_cancellation(&plan).await.is_err());
    for _ in 0..3 {
        let complete = if retention {
            publisher.scan_expiry_step(&mut plan).await
        } else {
            publisher.scan_cancellation_step(&mut plan).await
        }
        .expect("bounded reference scan");
        if complete {
            break;
        }
    }
    let clock = |seconds: i64| {
        positron_kernel::RetentionTimeAuthority::establish_with_source(
            positron_kernel::FixedLifecycleClockSource::new(
                positron_domain::time::UnixNanoseconds::new(seconds * 1_000_000_000),
            ),
            positron_kernel::LifecycleClockPolicy::default(),
        )
        .expect("trusted clock")
    };
    let progress = if retention {
        assert_eq!(
            publisher.claim_expiry(&plan, &clock(1999)).await,
            Err(RepositoryFailure::PreconditionFailed)
        );
        publisher
            .claim_expiry(&plan, &clock(2000))
            .await
            .expect("due expiry")
    } else {
        publisher
            .claim_cancellation(&plan)
            .await
            .expect("claimed cancellation")
    };
    assert!(!progress.complete());
    assert!(progress.retained_shared_objects() > 0);
    assert!(publisher.cleanup_checkpoint(progress).is_err());
    assert_eq!(
        publisher
            .acknowledge_expiry(owner, manifest_id.checksum())
            .await,
        Err(RepositoryFailure::PreconditionFailed)
    );
    assert_eq!(
        publisher
            .verify(second.snapshot_id())
            .await
            .expect("shared snapshot"),
        second
    );
    let repository = repository
        .with_faults(vec![LocalFault::new(
            LocalFaultPoint::AfterDeletion,
            LocalFaultEffect::OutcomeUnknown,
            0,
        )])
        .expect("lost delete acknowledgement");
    let publisher = BackupPublisher::new(&repository, &identity, signer)
        .with_control_resources(resources, 0)
        .expect("live Maintenance control grant");
    let proof = complete_registry_cursor(&publisher).await;
    let publisher = publisher
        .with_registry_verification(&proof)
        .expect("completed cold ancestry");
    assert_eq!(
        publisher
            .delete_expired_step(owner, manifest_id.checksum())
            .await,
        Err(RepositoryFailure::OutcomeUnknown)
    );
    let unchanged = publisher
        .expiry_progress(owner, manifest_id.checksum())
        .await
        .expect("retained claim");
    assert_eq!(unchanged.deleted_objects(), 0);
    assert_eq!(unchanged.pending_objects(), progress.pending_objects());
    drop(repository);
    let mut repository = LocalRepository::attach(&path, &identity)
        .await
        .expect("cold cleanup reopen");
    // Eleven fixed durable lifecycle transitions, plus at most one selected reopen.
    for action in data.iter().copied().take(1) {
        if action & 1 == 0 {
            drop(repository);
            repository = LocalRepository::attach(&path, &identity)
                .await
                .expect("restart during cleanup");
        }
        let publisher = BackupPublisher::new(&repository, &identity, signer)
            .with_control_resources(resources, 0)
            .expect("live Maintenance control grant");
        let proof = complete_registry_cursor(&publisher).await;
        let publisher = publisher
            .with_registry_verification(&proof)
            .expect("completed cold ancestry");
        assert_eq!(
            publisher
                .cleanup_for_owner(owner)
                .await
                .expect("durable claim"),
            Some(unchanged)
        );
        assert!(repository.head(object.id()).await.is_ok());
    }
    let publisher = BackupPublisher::new(&repository, &identity, signer)
        .with_control_resources(resources, 0)
        .expect("live Maintenance control grant");
    let proof = complete_registry_cursor(&publisher).await;
    let publisher = publisher
        .with_registry_verification(&proof)
        .expect("completed cold ancestry");
    let complete = publisher
        .delete_expired_step(owner, manifest_id.checksum())
        .await
        .expect("reconcile deleted object");
    assert!(complete.complete());
    assert_eq!(complete.deleted_objects(), 0);
    assert_eq!(complete.already_absent_objects(), 1);
    let checkpoint = publisher
        .cleanup_checkpoint(complete)
        .expect("completion checkpoint");
    publisher
        .acknowledge_expiry(owner, manifest_id.checksum())
        .await
        .expect("acknowledge complete cleanup");
    assert_eq!(
        publisher
            .verify_cleanup_checkpoint(&checkpoint)
            .await
            .expect("checkpoint after acknowledgement"),
        complete
    );
    let mut payload = super::super::codec::verify(&checkpoint, signer.identity())
        .expect("signed completion seed")
        .to_vec();
    mutate(&mut payload, data);
    let signed = super::super::codec::sign(payload, signer).expect("signed completion mutation");
    if let Ok(decoded) = publisher.verify_cleanup_checkpoint(&signed).await {
        assert_eq!(decoded, complete);
    }
    assert!(repository.head(object.id()).await.is_ok());
    assert_eq!(
        publisher
            .verify(second.snapshot_id())
            .await
            .expect("shared snapshot survives"),
        second
    );
    let tombstone = BackupPurgeTombstone::new([9; 16], "purged-tenant", [27; 16], 1002)
        .expect("purge identity");
    let mut progress = publisher
        .begin_tenant_purge(&tombstone, [28; 16], [29; 32])
        .await
        .expect("begin bounded purge");
    for _ in 0..128 {
        if progress.complete() {
            break;
        }
        let checkpoint = publisher
            .tenant_purge_checkpoint(&progress)
            .expect("purge checkpoint");
        assert!(checkpoint.len() <= BackupTenantPurge::MAX_CHECKPOINT_BYTES);
        let mut corrupt = checkpoint.clone();
        let offset = usize::from(data.first().copied().unwrap_or(0)) % corrupt.len();
        if let Some(byte) = corrupt.get_mut(offset) {
            *byte ^= 1;
        }
        assert!(
            publisher
                .resume_tenant_purge_checkpoint(&corrupt, [28; 16], [29; 32])
                .is_err()
        );
        progress = publisher
            .resume_tenant_purge_checkpoint(&checkpoint, [28; 16], [29; 32])
            .expect("resume purge");
        publisher
            .tenant_purge_step(&mut progress)
            .await
            .expect("bounded purge turn");
    }
    assert!(progress.complete());
    let anchor = progress
        .registry_generation()
        .expect("complete managed purge");
    assert_eq!(
        publisher
            .purge_tenant(&tombstone)
            .await
            .expect("retry purge"),
        anchor
    );
    assert_eq!(
        repository
            .head(envelope.object().expect("envelope object").id())
            .await,
        Err(RepositoryFailure::NotFound)
    );
    assert!(repository.head(object.id()).await.is_ok());
}

#[cfg(test)]
#[test]
fn valid_snapshot_cleanup_fuzz_seeds_preserve_public_invariants() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("fuzz seed runtime");
    for seed in [[0], [1]] {
        assert!(
            runtime.block_on(fuzz_control_frames(&seed)),
            "real Maintenance admission for valid cleanup seeds"
        );
    }
}
