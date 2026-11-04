//! Bounded adapters over the canonical Prost Log Query wire types.
pub use crate::api_keys::ApiKeyTransport as LogQueryTransport;
pub use crate::api_keys::protobuf::{
    LogQueryAcknowledgement, LogQueryAffectedRange, LogQueryArray, LogQueryBatch, LogQueryBudget,
    LogQueryCancelRequest, LogQueryCancelResponse, LogQueryCell, LogQueryColumn, LogQueryEvent,
    LogQueryHeader, LogQueryKeyValue, LogQueryLease, LogQueryMarker, LogQueryMissing, LogQueryNull,
    LogQueryObject, LogQueryOccurrences, LogQueryOrdering, LogQueryRequest, LogQueryResponse,
    LogQueryRow, LogQuerySessionRequest, LogQuerySnapshot, LogQueryStats, LogQueryStopReason,
    LogQueryTailRequest, LogQueryTerminal, LogQueryTimestamp, LogQueryTruncated, LogQueryValue,
    log_query_cancel_request, log_query_cell, log_query_event, log_query_session_request,
    log_query_value,
};

mod response;

mod client {
    include!(concat!(env!("OUT_DIR"), "/log_query_service_client.rs"));
}
pub use client::{
    CANCEL_HTTP_PATH, HTTP_PATH, LogQueryServiceClient, MAX_CANCEL_REQUEST_BYTES,
    MAX_CANCEL_RESPONSE_BYTES, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, MAX_SESSION_REQUEST_BYTES,
    SESSION_HTTP_PATH, is_query_path,
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogQueryServiceClientFailure {
    InvalidRequest,
    AuthenticationRejected,
    CapacityUnavailable,
    QueryUnavailable,
    SnapshotExpired,
    UnsupportedFeature,
    InvalidCursor,
    InvalidBudget,
    BudgetExhausted,
    AuthorizationChanged,
    Cancelled,
    UnsupportedQuery,
    IdempotencyConflict,
    StoreUnavailable,
    IncompleteData,
    MalformedPersistentData,
    Internal,
    AmbiguousCancellation(crate::api_keys::protobuf::PublicErrorCode),
    Transport,
}
impl LogQueryServiceClientFailure {
    /// Transport failures require explicit recovery rather than a blind replay.
    #[must_use]
    pub const fn completion_state(self) -> crate::api_keys::protobuf::CompletionState {
        use crate::api_keys::protobuf::CompletionState;
        match self {
            Self::Transport | Self::AmbiguousCancellation(_) => CompletionState::Ambiguous,
            _ => CompletionState::Rejected,
        }
    }
    /// Returns the canonical server retry class; this never performs a retry.
    #[must_use]
    pub const fn retry_class(self) -> crate::api_keys::protobuf::RetryClass {
        use crate::api_keys::protobuf::RetryClass;
        match self {
            Self::CapacityUnavailable | Self::QueryUnavailable => RetryClass::AfterBackoff,
            Self::InvalidRequest | Self::AuthenticationRejected => RetryClass::AfterInputCorrection,
            Self::SnapshotExpired
            | Self::UnsupportedFeature
            | Self::Transport
            | Self::AmbiguousCancellation(_) => RetryClass::Never,
            Self::InvalidCursor => RetryClass::AfterInputCorrection,
            Self::InvalidBudget => RetryClass::AfterInputCorrection,
            Self::BudgetExhausted => RetryClass::AfterInputCorrection,
            Self::AuthorizationChanged => RetryClass::AfterInputCorrection,
            Self::Cancelled => RetryClass::Never,
            Self::UnsupportedQuery => RetryClass::AfterInputCorrection,
            Self::IdempotencyConflict => RetryClass::AfterInputCorrection,
            Self::StoreUnavailable => RetryClass::AfterBackoff,
            Self::IncompleteData => RetryClass::AfterBackoff,
            Self::MalformedPersistentData => RetryClass::Never,
            Self::Internal => RetryClass::Never,
        }
    }
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
    serde_json::to_vec(&query_error(status, code)?).map_err(|_| LogQueryWireFailure)
}

/// Preserves the native cancellation disposition without changing its cause.
pub fn cancellation_rejection(
    status: u16,
    code: &str,
    completion: crate::api_keys::protobuf::CompletionState,
) -> Result<Vec<u8>, LogQueryWireFailure> {
    use crate::api_keys::protobuf::{CompletionState, RetryClass};
    let mut error = query_error(status, code)?;
    match completion {
        CompletionState::Rejected => {},
        CompletionState::Ambiguous => {
            error.completion_state = completion as i32;
            error.retry_class = RetryClass::Never as i32;
        },
        CompletionState::Unspecified => return Err(LogQueryWireFailure),
    }
    serde_json::to_vec(&error).map_err(|_| LogQueryWireFailure)
}

fn query_error(
    status: u16,
    code: &str,
) -> Result<crate::api_keys::protobuf::PublicError, LogQueryWireFailure> {
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
        (410, "snapshot_expired") => (
            Code::SnapshotExpired,
            Retry::Never,
            FailureSource::QueryExecution,
            Detail::SnapshotExpired,
        ),
        (400, "invalid_cursor") => (
            Code::InvalidCursor,
            Retry::AfterInputCorrection,
            FailureSource::QueryExecution,
            Detail::InvalidCursor,
        ),
        (400, "invalid_budget") => (
            Code::InvalidBudget,
            Retry::AfterInputCorrection,
            FailureSource::QueryExecution,
            Detail::InvalidBudget,
        ),
        (422, "budget_exhausted") => (
            Code::BudgetExhausted,
            Retry::AfterInputCorrection,
            FailureSource::QueryExecution,
            Detail::BudgetExhausted,
        ),
        (403, "authorization_changed") => (
            Code::AuthorizationChanged,
            Retry::AfterInputCorrection,
            FailureSource::QueryExecution,
            Detail::AuthorizationChanged,
        ),
        (409, "cancelled") => (
            Code::Cancelled,
            Retry::Never,
            FailureSource::QueryExecution,
            Detail::Cancelled,
        ),
        (400, "unsupported_query") => (
            Code::UnsupportedQuery,
            Retry::AfterInputCorrection,
            FailureSource::QueryExecution,
            Detail::UnsupportedQuery,
        ),
        (409, "idempotency_conflict") => (
            Code::IdempotencyConflict,
            Retry::AfterInputCorrection,
            FailureSource::QueryExecution,
            Detail::IdempotencyConflict,
        ),
        (503, "store_unavailable") => (
            Code::StoreUnavailable,
            Retry::AfterBackoff,
            FailureSource::QueryExecution,
            Detail::StoreUnavailable,
        ),
        (503, "incomplete_data") => (
            Code::IncompleteData,
            Retry::AfterBackoff,
            FailureSource::QueryExecution,
            Detail::IncompleteData,
        ),
        (500, "malformed_persistent_data") => (
            Code::MalformedPersistentData,
            Retry::Never,
            FailureSource::QueryExecution,
            Detail::MalformedPersistentData,
        ),
        (500, "internal") => (
            Code::Internal,
            Retry::Never,
            FailureSource::QueryExecution,
            Detail::Internal,
        ),
        _ => return Err(LogQueryWireFailure),
    };
    Ok(PublicError {
        code: code as i32,
        retry_class: retry as i32,
        completion_state: CompletionState::Rejected as i32,
        source: source as i32,
        safe_detail: detail as i32,
    })
}

/// Unknown enums, mismatched status and missing completion metadata fail closed.
pub fn decode_query_rejection(status: u16, bytes: &[u8]) -> LogQueryServiceClientFailure {
    decode_rejection(status, bytes, false)
}

/// Cancellation also accepts explicit native uncertainty, retaining its cause.
pub fn decode_cancellation_rejection(status: u16, bytes: &[u8]) -> LogQueryServiceClientFailure {
    decode_rejection(status, bytes, true)
}

fn decode_rejection(status: u16, bytes: &[u8], cancellation: bool) -> LogQueryServiceClientFailure {
    use crate::api_keys::protobuf::{CompletionState, PublicError, PublicErrorCode, RetryClass};
    if bytes.len() > 1024 {
        return LogQueryServiceClientFailure::Transport;
    }
    let Ok(actual) = serde_json::from_slice::<PublicError>(bytes) else {
        return LogQueryServiceClientFailure::Transport;
    };
    for (candidate, code, failure) in [
        (
            410,
            "snapshot_expired",
            LogQueryServiceClientFailure::SnapshotExpired,
        ),
        (
            400,
            "invalid_cursor",
            LogQueryServiceClientFailure::InvalidCursor,
        ),
        (
            400,
            "invalid_budget",
            LogQueryServiceClientFailure::InvalidBudget,
        ),
        (
            422,
            "budget_exhausted",
            LogQueryServiceClientFailure::BudgetExhausted,
        ),
        (
            403,
            "authorization_changed",
            LogQueryServiceClientFailure::AuthorizationChanged,
        ),
        (409, "cancelled", LogQueryServiceClientFailure::Cancelled),
        (
            400,
            "unsupported_query",
            LogQueryServiceClientFailure::UnsupportedQuery,
        ),
        (
            409,
            "idempotency_conflict",
            LogQueryServiceClientFailure::IdempotencyConflict,
        ),
        (
            503,
            "store_unavailable",
            LogQueryServiceClientFailure::StoreUnavailable,
        ),
        (
            503,
            "incomplete_data",
            LogQueryServiceClientFailure::IncompleteData,
        ),
        (
            500,
            "malformed_persistent_data",
            LogQueryServiceClientFailure::MalformedPersistentData,
        ),
        (500, "internal", LogQueryServiceClientFailure::Internal),
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
        if status != candidate {
            continue;
        }
        let Ok(mut expected) = query_error(candidate, code) else {
            continue;
        };
        if actual == expected {
            return failure;
        }
        if cancellation {
            expected.completion_state = CompletionState::Ambiguous as i32;
            expected.retry_class = RetryClass::Never as i32;
            if actual == expected
                && let Ok(code) = PublicErrorCode::try_from(actual.code)
            {
                return LogQueryServiceClientFailure::AmbiguousCancellation(code);
            }
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
        self.validate_with_wall_limit(5)
    }
    pub(crate) fn validate_session(&self) -> Result<(), LogQueryWireFailure> {
        self.validate_with_wall_limit(3600)
    }
    fn validate_with_wall_limit(
        &self,
        maximum_wall_seconds: u64,
    ) -> Result<(), LogQueryWireFailure> {
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
            || budget.wall_seconds > maximum_wall_seconds
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

mod session;
use session::require_capability;

mod delivery;
pub use delivery::BatchTracker;

mod terminal;
pub use terminal::{OpaqueCursor, QueryTerminalStatus};
