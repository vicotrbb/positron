//! The existing Maintenance fuzzer also parses post-authentication references.
use super::*;

pub(in crate::maintenance) fn exercise(data: &[u8]) {
    if data.len() > 128 {
        return;
    }
    check(data);
    let mut prefixed = b"BKVREF01".to_vec();
    prefixed.extend_from_slice(data);
    check(&prefixed);
}

fn check(data: &[u8]) {
    let Ok((Some(reference), progress)) = verification::unpack(data) else {
        return;
    };
    let binding = RepositoryOperationBinding::new([0xb1; 16], [0xb2; 32])
        .expect("fixed fuzz operation binding");
    let checkpoint = binding
        .backup_verification_checkpoint(2, progress, reference)
        .expect("accepted bounded reference can be republished");
    let encoded = checkpoint
        .opaque_progress()
        .get(56..)
        .expect("repository binding prefix");
    let (restored, body) = verification::unpack(encoded).expect("canonical reference roundtrip");
    assert_eq!(restored, Some(reference));
    assert_eq!(body, progress);
}
