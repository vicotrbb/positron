#![no_main]
use libfuzzer_sys::fuzz_target;
use positron_api::log_query::{LogQueryRequest, LogQueryResponse, decode_query_rejection};
fuzz_target!(|data: &[u8]| {
    if let Ok(request) = LogQueryRequest::decode(data) {
        let wire = request.encode().expect("checked request");
        assert_eq!(LogQueryRequest::decode(&wire), Ok(request));
    }
    if let Ok(response) = LogQueryResponse::decode(data) {
        let wire = response.encode().expect("checked response");
        assert_eq!(LogQueryResponse::decode(&wire), Ok(response));
    }
    for status in [400, 401, 429, 503] { let _ = decode_query_rejection(status, data); }
});
