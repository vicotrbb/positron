#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    positron::fuzz_live_bundle_request(data);

    // Every run also traverses the accepted retention form, so the canonical
    // encoder and the parse-after-encode assertion remain covered even when
    // the evolving corpus has not yet discovered a complete age recipient.
    let identity = age::x25519::Identity::generate();
    let request = format!(
        "version=1\nretain_identifier=data_directory\nrecipient={}\n",
        identity.to_public()
    );
    positron::fuzz_live_bundle_request(request.as_bytes());
});
