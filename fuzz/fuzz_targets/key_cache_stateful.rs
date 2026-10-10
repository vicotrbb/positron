#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    positron_kernel::key_provider::fuzz_key_cache_stateful(data);
});
