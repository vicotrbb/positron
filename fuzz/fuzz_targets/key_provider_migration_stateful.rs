#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    positron_runtime::fuzz_key_provider_migration_stateful(data);
});
