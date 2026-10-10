#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    positron_kernel::fuzz_recovery_bundle_payload(data);
    positron_runtime::fuzz_recovery_catalog_state(data);
});
