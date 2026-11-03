use super::*;

/// A continuation remains an opaque server-authenticated value, never a credential.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueCursor(Vec<u8>);
impl OpaqueCursor {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LogQueryWireFailure> {
        if bytes.is_empty() || bytes.len() > 8192 {
            return Err(LogQueryWireFailure);
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| LogQueryWireFailure)?;
        owned.extend_from_slice(bytes);
        Ok(Self(owned))
    }
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl std::fmt::Debug for OpaqueCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OpaqueCursor { <redacted> }")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryTerminalStatus {
    Complete,
    Continued,
    Incomplete(LogQueryStopReason),
}
impl LogQueryTerminal {
    /// Parses only canonical status/reason pairs; unknown future truth is refused.
    pub fn status(&self) -> Result<QueryTerminalStatus, LogQueryWireFailure> {
        match self.state.as_str() {
            "complete"
                if self.reason.is_empty()
                    && self.affected_ranges.is_empty()
                    && self.continuation_cursor.is_none()
                    && self
                        .stats
                        .as_ref()
                        .is_some_and(|stats| stats.result_digest.len() == 32) =>
            {
                Ok(QueryTerminalStatus::Complete)
            },
            "continued"
                if self.reason.is_empty()
                    && self.stats.is_none()
                    && self.affected_ranges.is_empty() =>
            {
                OpaqueCursor::from_bytes(
                    self.continuation_cursor
                        .as_deref()
                        .ok_or(LogQueryWireFailure)?,
                )?;
                Ok(QueryTerminalStatus::Continued)
            },
            "incomplete"
                if self.reason.len() <= 64
                    && self
                        .reason
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
                    && self
                        .stats
                        .as_ref()
                        .is_some_and(|stats| stats.result_digest.len() == 32) =>
            {
                let name = format!("LOG_QUERY_STOP_REASON_{}", self.reason.to_ascii_uppercase());
                let reason = LogQueryStopReason::from_str_name(&name)
                    .filter(|reason| *reason != LogQueryStopReason::Unspecified)
                    .ok_or(LogQueryWireFailure)?;
                if let Some(cursor) = self.continuation_cursor.as_deref() {
                    OpaqueCursor::from_bytes(cursor)?;
                }
                Ok(QueryTerminalStatus::Incomplete(reason))
            },
            _ => Err(LogQueryWireFailure),
        }
    }
    pub fn continuation(&self) -> Result<Option<OpaqueCursor>, LogQueryWireFailure> {
        self.status()?;
        self.continuation_cursor
            .as_deref()
            .map(OpaqueCursor::from_bytes)
            .transpose()
    }
}
