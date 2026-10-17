//! Cold cursor and hostile inventory checks shared by the real capture fixture.
use positron_backup::{BackupManifest, BackupPublisher, BackupSnapshotVerification};
use positron_kernel::{BackupCaptureFile, BackupControlSigner};
pub async fn exercise(
    publisher: &BackupPublisher<'_>,
    signer: &BackupControlSigner,
    files: &[BackupCaptureFile],
    expected: &BackupManifest,
    mut verification: BackupSnapshotVerification,
) -> Result<BackupSnapshotVerification, Box<dyn std::error::Error>> {
    // Reconstruct from signed progress after every bounded file step.
    // No in-memory hash or ordinal may be required across calls.
    let maximum_steps = 4 * (files.len() + expected.objects().len() + 8);
    for _ in 0..maximum_steps {
        if verification.complete() {
            break;
        }
        publisher
            .snapshot_verification_step(&mut verification)
            .await?;
        let checkpoint = publisher.snapshot_verification_checkpoint(&verification)?;
        for length in [0, 8, checkpoint.len() - 1] {
            assert!(
                publisher
                    .resume_snapshot_verification(
                        checkpoint.get(..length).ok_or("checkpoint prefix")?,
                        [44; 16],
                        [45; 32]
                    )
                    .await
                    .is_err()
            );
        }
        let mut resumed = publisher
            .resume_snapshot_verification(&checkpoint, [44; 16], [45; 32])
            .await?;
        let mut reordered = files.to_vec();
        reordered.reverse();
        assert!(
            publisher
                .validate_snapshot_inventory(&mut resumed, &reordered)
                .is_err()
        );
        publisher.validate_snapshot_inventory(&mut resumed, files)?;
        verification = resumed;
    }
    assert!(
        verification.complete(),
        "cold file checkpoints must converge"
    );
    // Legacy cursors contain no native-file proof and restart that pass.
    let checkpoint = publisher.snapshot_verification_checkpoint(&verification)?;
    let sign = |payload: Vec<u8>| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        use sha2::{Digest, Sha256};
        let signature = signer.sign(&Sha256::digest(&payload))?;
        let mut signed = payload;
        signed.extend_from_slice(&signature.bytes());
        Ok(signed)
    };
    let payload_end = checkpoint.len().checked_sub(64).ok_or("signature")?;
    let mut legacy = checkpoint
        .get(..payload_end - 36)
        .ok_or("legacy payload")?
        .to_vec();
    legacy
        .get_mut(..8)
        .ok_or("legacy version")?
        .copy_from_slice(b"POSBSV01");
    let mut legacy = publisher
        .resume_snapshot_verification(&sign(legacy)?, [44; 16], [45; 32])
        .await?;
    publisher.validate_snapshot_inventory(&mut legacy, files)?;
    assert!(
        !legacy.complete(),
        "legacy cursor cannot invent native verification"
    );
    let mut changed = checkpoint.get(..payload_end).ok_or("payload")?.to_vec();
    *changed
        .get_mut(payload_end - 36)
        .ok_or("inventory digest")? ^= 1;
    let mut changed = publisher
        .resume_snapshot_verification(&sign(changed)?, [44; 16], [45; 32])
        .await?;
    assert!(
        publisher
            .validate_snapshot_inventory(&mut changed, files)
            .is_err()
    );
    let mut count = checkpoint.get(..payload_end).ok_or("payload")?.to_vec();
    count
        .get_mut(payload_end - 4..)
        .ok_or("file count")?
        .copy_from_slice(&(files.len() as u32 + 1).to_be_bytes());
    let mut count = publisher
        .resume_snapshot_verification(&sign(count)?, [44; 16], [45; 32])
        .await?;
    assert!(
        publisher
            .validate_snapshot_inventory(&mut count, files)
            .is_err()
    );
    Ok(verification)
}
