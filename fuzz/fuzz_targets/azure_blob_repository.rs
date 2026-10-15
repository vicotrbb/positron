#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| { positron_backup::fuzz_azure_blob_repository(data); });
