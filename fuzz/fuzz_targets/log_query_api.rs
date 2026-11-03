#![no_main]
use libfuzzer_sys::fuzz_target;
use positron_api::log_query::{
    BatchTracker, LogQueryCancelRequest, LogQueryRequest, LogQueryResponse, LogQuerySessionRequest,
    OpaqueCursor, decode_cancellation_rejection, decode_query_rejection,
};
fuzz_target!(|data: &[u8]| {
    if let Ok(request) = LogQueryRequest::decode(data) {
        let wire = request.encode().expect("checked request");
        assert_eq!(LogQueryRequest::decode(&wire), Ok(request));
    }
    if let Ok(request) = LogQuerySessionRequest::decode(data) {
        let wire = request.encode().expect("checked session");
        assert_eq!(LogQuerySessionRequest::decode(&wire), Ok(request));
    }
    if let Ok(request) = LogQueryCancelRequest::decode(data) {
        let wire = request.encode().expect("checked cancellation");
        assert_eq!(LogQueryCancelRequest::decode(&wire), Ok(request));
    }
    if let Ok(response) = LogQueryResponse::decode(data) {
        let wire = response.encode().expect("checked response");
        assert_eq!(LogQueryResponse::decode(&wire), Ok(response));
    }
    if let Ok(response) = LogQueryResponse::decode_session(data) {
        let wire = response.encode_session().expect("checked session response");
        assert_eq!(
            LogQueryResponse::decode_session(&wire),
            Ok(response.clone())
        );
        let mut tracker = BatchTracker::query();
        if tracker.filter(&response).is_ok() {
            if let Ok(repeated) = tracker.filter(&response) {
                assert!(repeated.is_empty());
            }
        }
    }
    if let Ok(response) = LogQueryResponse::decode_tail(data) {
        let wire = response.encode_tail().expect("checked tail response");
        assert_eq!(LogQueryResponse::decode_tail(&wire), Ok(response.clone()));
        let mut tracker = BatchTracker::tail();
        if tracker.filter(&response).is_ok() {
            if let Ok(repeated) = tracker.filter(&response) {
                assert!(repeated.is_empty());
            }
        }
    }
    if let Ok(cursor) = OpaqueCursor::from_bytes(data) {
        assert_eq!(cursor.as_bytes(), data);
    }
    for status in [400, 401, 403, 409, 410, 413, 422, 429, 500, 503] {
        let _ = decode_query_rejection(status, data);
        let _ = decode_cancellation_rejection(status, data);
    }
});
