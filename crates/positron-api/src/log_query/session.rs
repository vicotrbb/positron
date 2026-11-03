use super::*;

impl LogQuerySessionRequest {
    pub fn encode(&self) -> Result<Vec<u8>, LogQueryWireFailure> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| LogQueryWireFailure)?;
        if bytes.len() > MAX_SESSION_REQUEST_BYTES {
            return Err(LogQueryWireFailure);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, LogQueryWireFailure> {
        if bytes.len() > MAX_SESSION_REQUEST_BYTES {
            return Err(LogQueryWireFailure);
        }
        let request: Self = serde_json::from_slice(bytes).map_err(|_| LogQueryWireFailure)?;
        request.validate()?;
        Ok(request)
    }
    pub fn validate(&self) -> Result<(), LogQueryWireFailure> {
        if !(1..=128).contains(&self.batch_limit) {
            return Err(LogQueryWireFailure);
        }
        match self.operation.as_ref() {
            Some(log_query_session_request::Operation::Execute(query)) => query.validate_session(),
            Some(log_query_session_request::Operation::Tail(tail)) if self.batch_limit == 1 => {
                tail.validate()
            },
            Some(log_query_session_request::Operation::Resume(cursor))
                if !cursor.is_empty() && cursor.len() <= 8192 =>
            {
                Ok(())
            },
            _ => Err(LogQueryWireFailure),
        }
    }
}

impl LogQueryCancelRequest {
    pub fn encode(&self) -> Result<Vec<u8>, LogQueryWireFailure> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| LogQueryWireFailure)?;
        if bytes.len() > MAX_CANCEL_REQUEST_BYTES {
            return Err(LogQueryWireFailure);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, LogQueryWireFailure> {
        if bytes.len() > MAX_CANCEL_REQUEST_BYTES {
            return Err(LogQueryWireFailure);
        }
        let request: Self = serde_json::from_slice(bytes).map_err(|_| LogQueryWireFailure)?;
        request.validate()?;
        Ok(request)
    }
    pub fn validate(&self) -> Result<(), LogQueryWireFailure> {
        let bytes = match self.cursor.as_ref() {
            Some(
                log_query_cancel_request::Cursor::Query(bytes)
                | log_query_cancel_request::Cursor::Tail(bytes),
            ) => bytes,
            None => return Err(LogQueryWireFailure),
        };
        if bytes.is_empty() || bytes.len() > 8192 {
            return Err(LogQueryWireFailure);
        }
        Ok(())
    }
}

impl LogQueryTailRequest {
    pub fn validate(&self) -> Result<(), LogQueryWireFailure> {
        self.query
            .as_ref()
            .ok_or(LogQueryWireFailure)?
            .validate_session()?;
        if self
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.is_empty() || cursor.len() > 8192)
            || self
                .historical_rows
                .is_some_and(|rows| rows == 0 || rows > 128)
            || (self.cursor.is_some() && self.historical_rows.is_some())
            || self
                .acknowledgement
                .as_ref()
                .is_some_and(|ack| self.cursor.is_none() || ack.digest.len() != 32)
        {
            return Err(LogQueryWireFailure);
        }
        Ok(())
    }
}

/// No capability cache: every added-feature call observes the current peer.
pub(super) fn require_capability(
    http: &crate::http_client::HttpClient,
    bearer: &str,
    capability: crate::generated::Capability,
) -> Result<(), LogQueryServiceClientFailure> {
    use crate::generated::{ApiVersion, CapabilityClient, CapabilityRequest, Transport};
    let request = CapabilityClient::encode(
        CapabilityRequest::for_capability(ApiVersion::V1, capability),
        Transport::HttpJson,
    );
    let (status, bytes) = http
        .post(bearer, request.path(), request.as_bytes().to_vec(), 1024)
        .map_err(|_| LogQueryServiceClientFailure::Transport)?;
    if status == 400 {
        let error: crate::api_keys::protobuf::PublicError =
            serde_json::from_slice(&bytes).map_err(|_| LogQueryServiceClientFailure::Transport)?;
        if matches!(
            crate::api_keys::protobuf::PublicErrorCode::try_from(error.code),
            Ok(
                crate::api_keys::protobuf::PublicErrorCode::CapabilityUnsupported
                    | crate::api_keys::protobuf::PublicErrorCode::UnsupportedApiVersion
            )
        ) {
            return Err(LogQueryServiceClientFailure::UnsupportedFeature);
        }
        return Err(LogQueryServiceClientFailure::Transport);
    }
    if status != 200 {
        return Err(decode_query_rejection(status, &bytes));
    }
    let response: crate::api_keys::protobuf::CapabilityResponse =
        serde_json::from_slice(&bytes).map_err(|_| LogQueryServiceClientFailure::Transport)?;
    if response.schema_digest.len() != 64
        || !response
            .schema_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(LogQueryServiceClientFailure::Transport);
    }
    if response.api_major != 1
        || response.capability != capability as i32
        || response.availability != crate::generated::CapabilityAvailability::Implemented as i32
        || response.refusal.is_some()
    {
        return Err(LogQueryServiceClientFailure::UnsupportedFeature);
    }
    Ok(())
}
