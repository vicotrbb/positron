#![no_main]

use libfuzzer_sys::fuzz_target;
use positron_api::maintenance::{
    MAX_CONTROL_REQUEST_BYTES, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, MAX_RUN_REQUEST_BYTES,
    MAX_VERIFY_REQUEST_BYTES, MAX_WINDOW_REQUEST_BYTES,
    MaintenanceControlResponse, MaintenanceExplainRequest, MaintenanceExplainResponse,
    MaintenancePauseRequest, MaintenanceResumeRequest, MaintenanceRunRequest, MaintenanceWindowRequest,
    MaintenanceRunResponse, MaintenanceStatusRequest, MaintenanceStatusResponse,
    OnlineVerificationReport, OnlineVerificationRequest,
};
use positron_kernel::IntegrityScrubContinuation;

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
    if data.len() <= MAX_WINDOW_REQUEST_BYTES {
        if let Ok(request) = MaintenanceWindowRequest::decode(data) {
            let encoded = request.encode().expect("accepted window request encodes");
            assert_eq!(MaintenanceWindowRequest::decode(&encoded), Ok(request));
        }
    }
    if data.len() <= MAX_VERIFY_REQUEST_BYTES {
        let _ = OnlineVerificationRequest::decode(data);
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
    if let Ok(report) = OnlineVerificationReport::decode(data) {
        let encoded = report.encode().expect("accepted verification report encodes");
        assert_eq!(OnlineVerificationReport::decode(&encoded), Ok(report));
    }

    let continuation = fuzz_continuation(data);
    let encoded_continuation = continuation.encode();
    assert_eq!(
        IntegrityScrubContinuation::decode(&encoded_continuation),
        Ok(continuation)
    );
    let continuation_hex = hex(&encoded_continuation);
    let request = OnlineVerificationRequest::new(
        "00000000-0000-0000-0000-000000000001".to_owned(),
        if data.first().copied().unwrap_or_default() & 1 == 0 {
            "logs".to_owned()
        } else {
            "traces".to_owned()
        },
        u32::from(data.get(1).copied().unwrap_or(1)).max(1),
        Some(u64::from(data.get(2).copied().unwrap_or(1)).max(1)),
        Some(continuation_hex.clone()),
    );
    let encoded_request = request
        .encode()
        .expect("accepted verification request encodes");
    assert_eq!(OnlineVerificationRequest::decode(&encoded_request), Ok(request));
    assert!(OnlineVerificationRequest::new(
        "00000000-0000-0000-0000-000000000001".to_owned(),
        "logs".to_owned(),
        1,
        None,
        Some(continuation_hex.clone()),
    )
    .encode()
    .is_err());

    let mut report = OnlineVerificationReport {
        report_version: 1,
        tenant: "00000000-0000-0000-0000-000000000001".to_owned(),
        signal: "logs".to_owned(),
        shard: 1,
        catalog_generation: 1,
        examined_segments: u32::from(data.get(3).copied().unwrap_or_default()),
        examined_bytes: u64::from(data.get(4).copied().unwrap_or_default()),
        omitted_segments: 0,
        outcome: "verified".to_owned(),
        verification_complete: true,
        report_checksum: String::new(),
        continuation: None,
        findings: Vec::new(),
    };
    report.report_checksum = report.checksum();
    let encoded_report = report
        .encode()
        .expect("accepted verification report encodes");
    assert_eq!(
        OnlineVerificationReport::decode(&encoded_report),
        Ok(report.clone())
    );
    assert!(OnlineVerificationReport {
        verification_complete: false,
        ..report
    }
    .encode()
    .is_err());
});

fn fuzz_continuation(data: &[u8]) -> IntegrityScrubContinuation {
    let mut bytes = [0_u8; 56];
    bytes[0] = 1;
    for (index, byte) in bytes.iter_mut().enumerate().skip(1) {
        *byte = data
            .get(index % data.len().max(1))
            .copied()
            .unwrap_or(u8::try_from(index).unwrap_or_default());
    }
    bytes[55] |= 1;
    IntegrityScrubContinuation::decode(&bytes).expect("constructed continuation is valid")
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}
