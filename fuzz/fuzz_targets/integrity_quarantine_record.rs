#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() <= 512 {
        positron_kernel::fuzz_integrity_quarantine_record(data);
    }
});
