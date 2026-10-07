#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    positron::fuzz_offline_integrity_continuation_hex(data);
});
