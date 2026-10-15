#![no_main]
libfuzzer_sys::fuzz_target!(|data:&[u8]| {
    positron_backup::fuzz_google_cloud_storage_repository(data);
});
