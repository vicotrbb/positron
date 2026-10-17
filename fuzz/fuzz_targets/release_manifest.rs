#![no_main]
use libfuzzer_sys::fuzz_target;
use positron_kernel::release_manifest::{ProjectTrustRoot, SignedReleaseManifest};

fuzz_target!(|data: &[u8]| {
    if let Ok(signed) = SignedReleaseManifest::from_bytes(data) {
        let canonical = signed
            .to_bytes()
            .expect("decoded canonical manifest must encode");
        assert_eq!(canonical, data);
        let _verification = signed.verify(&ProjectTrustRoot::new([
            208, 74, 178, 50, 116, 43, 180, 171, 58, 19, 104, 189, 70, 21, 228, 230, 208, 34, 74,
            183, 26, 1, 107, 175, 133, 32, 163, 50, 201, 119, 135, 55,
        ]));
    }
});
