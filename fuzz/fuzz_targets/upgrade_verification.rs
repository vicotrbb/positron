#![no_main]
use libfuzzer_sys::fuzz_target;
use positron_kernel::{
    BootstrapIntegrityIdentity, upgrade_verification::UpgradeVerificationReport,
};
fuzz_target!(|data: &[u8]| {
    if let Ok(report) = UpgradeVerificationReport::from_bytes(data) {
        assert_eq!(report.bytes(), data);
        // Fixed independent fixture authority exercises both valid seeds and tampering.
        let expected =
            BootstrapIntegrityIdentity::from_pinned(PUBLIC, FINGERPRINT).expect("fixture root");
        let _authenticated = report.verify(expected);
    }
});
const PUBLIC: [u8; 32] = [
    232, 218, 99, 164, 12, 166, 135, 200, 124, 252, 224, 92, 178, 74, 120, 108, 126, 117, 204, 73,
    199, 13, 181, 87, 63, 2, 111, 28, 106, 134, 206, 170,
];
const FINGERPRINT: [u8; 32] = [
    237, 82, 166, 39, 159, 191, 134, 14, 33, 235, 173, 144, 94, 29, 222, 183, 195, 125, 4, 5, 241,
    178, 239, 156, 189, 48, 188, 63, 220, 168, 137, 155,
];
