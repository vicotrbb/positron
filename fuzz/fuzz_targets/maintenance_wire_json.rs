#![no_main]

use libfuzzer_sys::fuzz_target;
use positron_api::maintenance::{
    MAX_CONTROL_REQUEST_BYTES, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, MAX_RUN_REQUEST_BYTES,
    MaintenanceControlResponse, MaintenanceExplainRequest, MaintenanceExplainResponse,
    MaintenancePauseRequest, MaintenanceResumeRequest, MaintenanceRunRequest,
    MaintenanceRunResponse, MaintenanceStatusRequest, MaintenanceStatusResponse,
};

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_RESPONSE_BYTES.saturating_add(1) {
        return;
    }
    if data.len() <= MAX_REQUEST_BYTES {
        let _ = MaintenanceStatusRequest::decode(data);
        let _ = MaintenanceExplainRequest::decode(data);
    }
    if data.len() <= MAX_RUN_REQUEST_BYTES {
        if let Ok(request) = MaintenanceRunRequest::decode(data) {
            let encoded = request.encode().expect("accepted run request encodes");
            assert_eq!(MaintenanceRunRequest::decode(&encoded), Ok(request));
        }
    }
    if data.len() <= MAX_CONTROL_REQUEST_BYTES {
        if let Ok(request) = MaintenancePauseRequest::decode(data) {
            let encoded = request.encode().expect("accepted pause request encodes");
            assert_eq!(MaintenancePauseRequest::decode(&encoded), Ok(request));
        }
        if let Ok(request) = MaintenanceResumeRequest::decode(data) {
            let encoded = request.encode().expect("accepted resume request encodes");
            assert_eq!(MaintenanceResumeRequest::decode(&encoded), Ok(request));
        }
    }
    if let Ok(response) = MaintenanceStatusResponse::decode(data) {
        let encoded = response.encode().expect("accepted status response encodes");
        assert_eq!(MaintenanceStatusResponse::decode(&encoded), Ok(response));
    }
    if let Ok(response) = MaintenanceExplainResponse::decode(data) {
        let encoded = response.encode().expect("accepted explanation encodes");
        assert_eq!(MaintenanceExplainResponse::decode(&encoded), Ok(response));
    }
    if let Ok(response) = MaintenanceRunResponse::decode(data) {
        let encoded = response.encode().expect("accepted run response encodes");
        assert_eq!(MaintenanceRunResponse::decode(&encoded), Ok(response));
    }
    if let Ok(response) = MaintenanceControlResponse::decode(data) {
        let encoded = response.encode().expect("accepted control response encodes");
        assert_eq!(MaintenanceControlResponse::decode(&encoded), Ok(response));
    }
});
