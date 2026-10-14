#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    positron_backup::fuzz_aws_s3_repository(data);
});
