//! Mutated owner-signed progress reaches the snapshot cursor parser.
use super::*;
pub(super) async fn exercise(
    publisher: &BackupPublisher<'_>,
    signer: &BackupControlSigner,
    data: &[u8],
) {
    let owner = [0x75; 16];
    let request = [0x76; 32];
    let state = publisher
        .begin_snapshot_verification([22; 16], owner, request)
        .await
        .expect("published cursor seed");
    let bytes = publisher
        .snapshot_verification_checkpoint(&state)
        .expect("signed snapshot cursor");
    let resumed = publisher
        .resume_snapshot_verification(&bytes, owner, request)
        .await
        .expect("valid snapshot cursor");
    assert_eq!(
        publisher
            .snapshot_verification_checkpoint(&resumed)
            .expect("canonical cursor"),
        bytes
    );
    let _ = publisher
        .resume_snapshot_verification(data, owner, request)
        .await;
    let split = bytes.len().checked_sub(64).expect("signature");
    // Preserve the outer envelope and publication proof so mutations reach
    // the new inventory digest and completed-file count after authentication.
    let mut native = bytes.get(..split).expect("payload").to_vec();
    let start = native.len().checked_sub(36).expect("native cursor fields");
    super::mutate(native.get_mut(start..).expect("native cursor"), data);
    let native = crate::snapshot::codec::sign(native, signer).expect("signed native mutation");
    let _ = publisher
        .resume_snapshot_verification(&native, owner, request)
        .await;
    let mut payload = bytes.get(..split).expect("payload").to_vec();
    super::mutate(&mut payload, data);
    let signed = crate::snapshot::codec::sign(payload, signer).expect("mutated signed cursor");
    if let Ok(resumed) = publisher
        .resume_snapshot_verification(&signed, owner, request)
        .await
    {
        let canonical = publisher
            .snapshot_verification_checkpoint(&resumed)
            .expect("bounded accepted cursor");
        assert!(
            publisher
                .resume_snapshot_verification(&canonical, owner, request)
                .await
                .is_ok()
        );
    }
    for length in [0, 8, bytes.len().saturating_sub(1)] {
        assert!(
            publisher
                .resume_snapshot_verification(bytes.get(..length).expect("prefix"), owner, request)
                .await
                .is_err()
        );
    }
}
