#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let decoded = positron_runtime::fuzz_operational_output_frame(bytes);
    assert_eq!(
        decoded,
        positron_runtime::fuzz_operational_output_frame(bytes)
    );
    if let Some(length) = decoded {
        assert!(length <= 510);
        assert!(bytes.len() >= length + 2);
        assert_eq!(
            bytes.get(..2),
            Some(
                u16::try_from(length)
                    .expect("bounded frame")
                    .to_be_bytes()
                    .as_slice()
            )
        );
    }
});
