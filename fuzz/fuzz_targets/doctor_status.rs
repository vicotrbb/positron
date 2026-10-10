#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Some(report) = positron::fuzz_doctor_status(data) {
        assert!(report.len() <= 8192);
        assert!(!report.contains("secretcanaryFamily87"));
        assert!(!report.contains("secretcanary87NeverExportThis"));
    }
});
