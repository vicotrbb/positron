#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    positron::fuzz_bootstrap_control_response(bytes);
    positron_runtime::fuzz_bootstrap_control_request(bytes);
});
