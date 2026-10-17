#![no_main]
use libfuzzer_sys::fuzz_target;
use positron_api::upgrade::{UpgradeRequest, UpgradeResponse};
fuzz_target!(|data: &[u8]| {
    if let Ok(request) = UpgradeRequest::decode(data) {
        let wire = request.encode().expect("checked request");
        assert_eq!(UpgradeRequest::decode(&wire), Ok(request));
    }
    if let Ok(response) = UpgradeResponse::decode(data) {
        let wire = response.encode().expect("checked response");
        assert_eq!(UpgradeResponse::decode(&wire), Ok(response));
    }
});
