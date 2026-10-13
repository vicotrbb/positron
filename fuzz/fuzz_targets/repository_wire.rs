#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() > 4097 { return; }
    if let Ok(request) = positron_api::repository::RepositoryRequest::decode(data) {
        assert_eq!(positron_api::repository::RepositoryRequest::decode(&request.encode().expect("accepted request encodes")).expect("canonical request"), request);
    }
    if let Ok(response) = positron_api::repository::RepositoryResponse::decode(data) {
        assert_eq!(positron_api::repository::RepositoryResponse::decode(&response.encode().expect("accepted response encodes")).expect("canonical response"), response);
    }
});
