//! Bounded adapters over the canonical Prost Log Query wire types.
pub use crate::api_keys::ApiKeyTransport as LogQueryTransport;
pub use crate::api_keys::protobuf::{
    LogQueryAffectedRange, LogQueryArray, LogQueryBatch, LogQueryBudget, LogQueryCell,
    LogQueryColumn, LogQueryEvent, LogQueryHeader, LogQueryKeyValue, LogQueryLease, LogQueryMarker,
    LogQueryMissing, LogQueryNull, LogQueryObject, LogQueryOccurrences, LogQueryOrdering,
    LogQueryRequest, LogQueryResponse, LogQueryRow, LogQuerySnapshot, LogQueryStats,
    LogQueryTerminal, LogQueryTimestamp, LogQueryTruncated, LogQueryValue, log_query_cell,
    log_query_event, log_query_value,
};

mod response;

mod client {
    include!(concat!(env!("OUT_DIR"), "/log_query_service_client.rs"));
}
pub use client::{HTTP_PATH, LogQueryServiceClient, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogQueryServiceClientFailure {
    InvalidRequest,
    AuthenticationRejected,
    CapacityUnavailable,
    QueryUnavailable,
    Transport,
}
impl std::fmt::Display for LogQueryServiceClientFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Log Query request failed")
    }
}
impl std::error::Error for LogQueryServiceClientFailure {}
fn client_failure(status: u16, bytes: &[u8]) -> LogQueryServiceClientFailure {
    decode_query_rejection(status, bytes)
}

/// Canonical pre-execution rejection, with no caller-controlled detail.
pub fn query_rejection(status: u16, code: &str) -> Result<Vec<u8>, LogQueryWireFailure> {
    use crate::api_keys::protobuf::{
        CompletionState, FailureSource, PublicError, PublicErrorCode as Code, RetryClass as Retry,
        SafeDetail as Detail,
    };
    let (code, retry, source, detail) = match (status, code) {
        (400, "invalid_request") => (
            Code::MalformedRequest,
            Retry::AfterInputCorrection,
            FailureSource::HttpDecode,
            Detail::RequestMalformed,
        ),
        (413, "request_too_large") => (
            Code::RequestTooLarge,
            Retry::AfterInputCorrection,
            FailureSource::HttpDecode,
            Detail::RequestLimitExceeded,
        ),
        (401, "authentication_rejected") => (
            Code::AuthenticationRejected,
            Retry::AfterInputCorrection,
            FailureSource::QueryExecution,
            Detail::AuthenticationRejected,
        ),
        (429, "capacity_unavailable") => (
            Code::CapacityUnavailable,
            Retry::AfterBackoff,
            FailureSource::QueryExecution,
            Detail::CapacityUnavailable,
        ),
        (503, "query_unavailable") => (
            Code::QueryUnavailable,
            Retry::AfterBackoff,
            FailureSource::QueryExecution,
            Detail::QueryUnavailable,
        ),
        _ => return Err(LogQueryWireFailure),
    };
    serde_json::to_vec(&PublicError {
        code: code as i32,
        retry_class: retry as i32,
        completion_state: CompletionState::Rejected as i32,
        source: source as i32,
        safe_detail: detail as i32,
    })
    .map_err(|_| LogQueryWireFailure)
}

/// Unknown enums, mismatched status and missing completion metadata fail closed.
pub fn decode_query_rejection(status: u16, bytes: &[u8]) -> LogQueryServiceClientFailure {
    use crate::api_keys::protobuf::PublicError;
    if bytes.len() > 1024 {
        return LogQueryServiceClientFailure::Transport;
    }
    let Ok(actual) = serde_json::from_slice::<PublicError>(bytes) else {
        return LogQueryServiceClientFailure::Transport;
    };
    for (candidate, code, failure) in [
        (
            400,
            "invalid_request",
            LogQueryServiceClientFailure::InvalidRequest,
        ),
        (
            413,
            "request_too_large",
            LogQueryServiceClientFailure::InvalidRequest,
        ),
        (
            401,
            "authentication_rejected",
            LogQueryServiceClientFailure::AuthenticationRejected,
        ),
        (
            429,
            "capacity_unavailable",
            LogQueryServiceClientFailure::CapacityUnavailable,
        ),
        (
            503,
            "query_unavailable",
            LogQueryServiceClientFailure::QueryUnavailable,
        ),
    ] {
        if status == candidate
            && let Ok(expected) = query_rejection(candidate, code)
            && let Ok(expected) = serde_json::from_slice::<PublicError>(&expected)
            && actual == expected
        {
            return failure;
        }
    }
    LogQueryServiceClientFailure::Transport
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogQueryWireFailure;
impl std::fmt::Display for LogQueryWireFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid bounded Log Query wire message")
    }
}
impl std::error::Error for LogQueryWireFailure {}
impl LogQueryRequest {
    pub fn validate(&self) -> Result<(), LogQueryWireFailure> {
        if self.pipeline.is_empty() || self.pipeline.len() > 4096 {
            return Err(LogQueryWireFailure);
        }
        let budget = self.budget.as_ref().ok_or(LogQueryWireFailure)?;
        if budget.scanned_bytes == 0
            || budget.scanned_bytes > 1 << 30
            || budget.decoded_records == 0
            || budget.decoded_records > 1024
            || budget.output_rows == 0
            || budget.output_rows > 128
            || budget.output_bytes == 0
            || budget.output_bytes > 16_384
            || budget.memory_bytes == 0
            || budget.memory_bytes > 1_048_576
            || budget.cpu_work_units == 0
            || budget.cpu_work_units > 1024
            || budget.wall_seconds == 0
            || budget.wall_seconds > 5
            || budget.maximum_time_range_nanoseconds == 0
            || budget.maximum_time_range_nanoseconds > 2_678_400_000_000_000
        {
            return Err(LogQueryWireFailure);
        }
        Ok(())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, LogQueryWireFailure> {
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(LogQueryWireFailure);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| LogQueryWireFailure)?;
        value.validate()?;
        Ok(value)
    }
    pub fn encode(&self) -> Result<Vec<u8>, LogQueryWireFailure> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| LogQueryWireFailure)?;
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(LogQueryWireFailure);
        }
        Ok(bytes)
    }
}
