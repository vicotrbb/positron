use super::*;

impl LogQueryResponse {
    pub fn decode(bytes: &[u8]) -> Result<Self, LogQueryWireFailure> {
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(LogQueryWireFailure);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| LogQueryWireFailure)?;
        value.validate()?;
        Ok(value)
    }
    pub fn encode_session(&self) -> Result<Vec<u8>, LogQueryWireFailure> {
        self.validate_inner(true, false)?;
        self.encode_bounded()
    }
    pub fn decode_session(bytes: &[u8]) -> Result<Self, LogQueryWireFailure> {
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(LogQueryWireFailure);
        }
        let response: Self = serde_json::from_slice(bytes).map_err(|_| LogQueryWireFailure)?;
        response.validate_inner(true, false)?;
        Ok(response)
    }
    pub fn encode_tail(&self) -> Result<Vec<u8>, LogQueryWireFailure> {
        self.validate_inner(true, true)?;
        self.encode_bounded()
    }
    pub fn decode_tail(bytes: &[u8]) -> Result<Self, LogQueryWireFailure> {
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(LogQueryWireFailure);
        }
        let response: Self = serde_json::from_slice(bytes).map_err(|_| LogQueryWireFailure)?;
        response.validate_inner(true, true)?;
        Ok(response)
    }
    pub fn validate_session(&self) -> Result<(), LogQueryWireFailure> {
        self.validate_inner(true, false)
    }
    pub fn validate_tail(&self) -> Result<(), LogQueryWireFailure> {
        self.validate_inner(true, true)
    }
    pub fn validate(&self) -> Result<(), LogQueryWireFailure> {
        self.validate_inner(false, false)
    }
    fn validate_inner(&self, session: bool, tail: bool) -> Result<(), LogQueryWireFailure> {
        use log_query_event::Event;
        let Some(Event::Header(header)) =
            self.events.first().and_then(|value| value.event.as_ref())
        else {
            return Err(LogQueryWireFailure);
        };
        if self.events.len() < 2
            || self.events.len() > 130
            || (tail
                && header.tail_phase.as_deref().is_none_or(|phase| {
                    !matches!(
                        phase,
                        "live_commit_vector" | "historical_temporal_then_live_commit_vector"
                    )
                }))
            || (!tail && header.tail_phase.is_some())
            || header.columns.is_empty()
            || header.columns.len() > 128
            || header.ordering.is_empty()
            || header
                .snapshot
                .as_ref()
                .is_none_or(|snapshot| snapshot.identity.len() != 32)
            || header
                .lease
                .as_ref()
                .is_none_or(|lease| lease.identity.len() != 16 || lease.expiry_unix_seconds == 0)
            || header.columns.iter().any(|column| {
                column.name.is_empty()
                    || column.name.len() > 4096
                    || !value_type(&column.value_type)
            })
            || header.ordering.len() > 128
            || header.ordering.iter().any(|order| {
                order.column.is_empty()
                    || order.column.len() > 4096
                    || !value_type(&order.value_type)
                    || !matches!(order.direction.as_str(), "ascending" | "descending")
            })
            || header
                .effective_budget
                .as_ref()
                .is_none_or(|budget| !valid_budget(budget, session))
            || header
                .initial_cursor
                .as_ref()
                .is_some_and(|cursor| cursor.is_empty() || cursor.len() > 8192)
        {
            return Err(LogQueryWireFailure);
        }
        let first_batch = self
            .events
            .get(1)
            .and_then(|event| match event.event.as_ref() {
                Some(Event::Batch(batch)) => Some(batch),
                _ => None,
            });
        let mut sequence = if session {
            first_batch.map_or(0, |batch| batch.sequence)
        } else {
            0
        };
        let mut digest = if session {
            first_batch.map_or_else(|| vec![0; 32], |batch| batch.prior_digest.clone())
        } else {
            vec![0; 32]
        };
        if digest.len() != 32 {
            return Err(LogQueryWireFailure);
        }
        let mut row_count = 0_u64;
        for event in self.events.iter().skip(1).take(self.events.len() - 2) {
            let Some(Event::Batch(batch)) = event.event.as_ref() else {
                return Err(LogQueryWireFailure);
            };
            if batch.sequence != sequence
                || batch.digest.len() != 32
                || batch.prior_digest != digest
                || batch.rows.is_empty()
                || batch
                    .rows
                    .iter()
                    .any(|row| row.cells.len() != header.columns.len())
            {
                return Err(LogQueryWireFailure);
            }
            for row in &batch.rows {
                for (cell, column) in row.cells.iter().zip(&header.columns) {
                    validate_cell_type(cell, column)?;
                    validate_cell(cell)?;
                }
            }
            row_count = row_count
                .checked_add(batch.rows.len() as u64)
                .ok_or(LogQueryWireFailure)?;
            if row_count > 128 {
                return Err(LogQueryWireFailure);
            }
            sequence = sequence.checked_add(1).ok_or(LogQueryWireFailure)?;
            digest.clone_from(&batch.digest);
        }
        let Some(Event::Terminal(terminal)) =
            self.events.last().and_then(|value| value.event.as_ref())
        else {
            return Err(LogQueryWireFailure);
        };
        match terminal.state.as_str() {
            "complete" | "incomplete" => {
                let stats = terminal.stats.as_ref().ok_or(LogQueryWireFailure)?;
                let prior_only =
                    session && first_batch.is_none() && header.initial_cursor.is_some();
                if prior_only
                    && (stats.result_digest.len() != 32
                        || ((stats.records == 0) != stats.last_sequence.is_none()))
                {
                    return Err(LogQueryWireFailure);
                }
                let pending_tail = tail && first_batch.is_some();
                if pending_tail
                    && first_batch.is_some_and(|batch| {
                        stats.result_digest != batch.prior_digest
                            || stats.last_sequence != batch.sequence.checked_sub(1)
                    })
                {
                    return Err(LogQueryWireFailure);
                }
                if (!tail
                    && (if session {
                        stats.records < row_count
                    } else {
                        stats.records != row_count
                    }))
                    || (!pending_tail && !prior_only && stats.result_digest != digest)
                    || (!pending_tail
                        && !prior_only
                        && stats.last_sequence != sequence.checked_sub(1))
                    || stats
                        .cumulative_budget
                        .as_ref()
                        .is_none_or(|budget| !valid_budget(budget, session))
                    || stats
                        .limiting_budget
                        .as_ref()
                        .is_some_and(|value| !budget_dimension(value))
                    || terminal.affected_ranges.len() > 1024
                    || terminal.affected_ranges.iter().any(|range| {
                        !matches!(
                            range.temporal_axis.as_str(),
                            "query_time" | "event_time" | "ingest_time"
                        ) || match (range.earliest_nanoseconds, range.latest_nanoseconds) {
                            (None, None) => false,
                            (Some(first), Some(last)) => first > last,
                            _ => true,
                        }
                    })
                    || (terminal.continuation_cursor.is_some() && !tail)
                    || (tail
                        && terminal
                            .continuation_cursor
                            .as_ref()
                            .is_some_and(|cursor| cursor.is_empty() || cursor.len() > 8192))
                    || (tail && terminal.state == "complete")
                    || (terminal.state == "complete"
                        && (!terminal.reason.is_empty() || !terminal.affected_ranges.is_empty()))
                    || (terminal.state == "incomplete"
                        && !reason(&terminal.reason)
                        && !(tail
                            && matches!(
                                terminal.reason.as_str(),
                                "disconnected" | "consumer_lagged"
                            )))
                {
                    return Err(LogQueryWireFailure);
                }
            },
            "continued"
                if terminal.stats.is_none()
                    && terminal.reason.is_empty()
                    && terminal
                        .continuation_cursor
                        .as_ref()
                        .is_some_and(|cursor| !cursor.is_empty() && cursor.len() <= 8192) => {},
            _ => return Err(LogQueryWireFailure),
        }
        Ok(())
    }
}
fn valid_budget(budget: &LogQueryBudget, session: bool) -> bool {
    let query = LogQueryRequest {
        pipeline: "logs".into(),
        budget: Some(*budget),
    };
    if session {
        query.validate_session()
    } else {
        query.validate()
    }
    .is_ok()
}
fn value_type(value: &str) -> bool {
    matches!(
        value,
        "native_value"
            | "unix_nanoseconds"
            | "optional_unix_nanoseconds"
            | "query_time"
            | "event_time"
            | "ingest_time"
            | "commit_position"
            | "record_ordinal"
            | "unsigned_integer"
            | "attribute_occurrence_set"
    )
}
fn budget_dimension(value: &str) -> bool {
    matches!(
        value,
        "scanned_bytes"
            | "decoded_records"
            | "output_rows"
            | "output_bytes"
            | "memory_bytes"
            | "cpu_work_units"
            | "wall_seconds"
            | "maximum_time_range_nanoseconds"
    )
}
fn reason(value: &str) -> bool {
    matches!(
        value,
        "unauthorized"
            | "idempotency_conflict"
            | "invalid_budget"
            | "budget_exhausted"
            | "invalid_cursor"
            | "snapshot_expired"
            | "authorization_changed"
            | "cancelled"
            | "resource_admission_refused"
            | "resource_exhausted"
            | "unsupported_query"
            | "store_unavailable"
            | "incomplete_data"
            | "malformed_persistent_data"
            | "internal"
    )
}
fn validate_cell_type(
    cell: &LogQueryCell,
    column: &LogQueryColumn,
) -> Result<(), LogQueryWireFailure> {
    use log_query_cell::Value;
    let valid = match cell.value.as_ref().ok_or(LogQueryWireFailure)? {
        Value::Missing(_) => column.nullable,
        Value::NativeValue(_) => column.value_type == "native_value",
        Value::Occurrences(_) => column.value_type == "attribute_occurrence_set",
        Value::UnsignedInteger(value) => {
            matches!(
                column.value_type.as_str(),
                "commit_position" | "unsigned_integer"
            ) || (column.value_type == "record_ordinal" && u32::try_from(*value).is_ok())
        },
        Value::Timestamp(time) => match column.value_type.as_str() {
            "query_time" => matches!(time.provenance.as_str(), "event" | "observed" | "ingest"),
            "event_time" => time.provenance.is_empty(),
            "ingest_time" => time.provenance == "kernel",
            "unix_nanoseconds" | "optional_unix_nanoseconds" => time.unix_nanoseconds.is_some(),
            _ => false,
        },
    };
    if valid {
        Ok(())
    } else {
        Err(LogQueryWireFailure)
    }
}

fn validate_cell(cell: &LogQueryCell) -> Result<(), LogQueryWireFailure> {
    match cell.value.as_ref().ok_or(LogQueryWireFailure)? {
        log_query_cell::Value::NativeValue(value) => validate_value(value, 0),
        log_query_cell::Value::Occurrences(values) => {
            if values.values.is_empty() || values.values.len() > 1024 {
                return Err(LogQueryWireFailure);
            }
            for value in &values.values {
                validate_value(value, 0)?;
            }
            Ok(())
        },
        log_query_cell::Value::Timestamp(timestamp) => {
            let query_time = matches!(
                timestamp.provenance.as_str(),
                "event" | "observed" | "ingest" | "kernel"
            ) && timestamp.quality.is_empty()
                && timestamp.unix_nanoseconds.is_some()
                && timestamp.source_value.is_none();
            let source_time = timestamp.provenance.is_empty()
                && matches!(
                    timestamp.quality.as_str(),
                    "usable" | "missing" | "zero" | "outlier" | "contradictory"
                );
            if query_time || source_time {
                Ok(())
            } else {
                Err(LogQueryWireFailure)
            }
        },
        log_query_cell::Value::UnsignedInteger(_) | log_query_cell::Value::Missing(_) => Ok(()),
    }
}
fn validate_value(value: &LogQueryValue, depth: u8) -> Result<(), LogQueryWireFailure> {
    if depth > 32 {
        return Err(LogQueryWireFailure);
    }
    match value.value.as_ref().ok_or(LogQueryWireFailure)? {
        // ProtoJSON builds a base64 temporary before passing bytes to the writer.
        log_query_value::Value::BytesValue(bytes) if bytes.len() > MAX_RESPONSE_BYTES => {
            return Err(LogQueryWireFailure);
        },
        log_query_value::Value::ArrayValue(array) => {
            for value in &array.values {
                validate_value(value, depth + 1)?;
            }
        },
        log_query_value::Value::ObjectValue(object) => {
            for entry in &object.entries {
                validate_value(entry.value.as_ref().ok_or(LogQueryWireFailure)?, depth + 1)?;
            }
        },
        log_query_value::Value::TruncatedValue(truncated) => {
            if !matches!(
                truncated.action.as_str(),
                "truncated_bytes" | "truncated_elements"
            ) {
                return Err(LogQueryWireFailure);
            }
            validate_value(
                truncated.value.as_deref().ok_or(LogQueryWireFailure)?,
                depth + 1,
            )?;
        },
        log_query_value::Value::MarkerValue(marker)
            if !matches!(marker.action.as_str(), "removed" | "redacted")
                || !matches!(
                    marker.original_kind.as_str(),
                    "null"
                        | "boolean"
                        | "signed_integer"
                        | "floating_point_bits"
                        | "string"
                        | "bytes"
                        | "array"
                        | "key_value_list"
                        | "marker"
                ) =>
        {
            return Err(LogQueryWireFailure);
        },
        _ => {},
    }
    Ok(())
}

impl LogQueryResponse {
    /// Serializes into one pre-reserved bounded buffer; the transport owns its
    /// governed capacity before invoking this encoder.
    pub fn encode(&self) -> Result<Vec<u8>, LogQueryWireFailure> {
        self.validate()?;
        self.encode_bounded()
    }
    fn encode_bounded(&self) -> Result<Vec<u8>, LogQueryWireFailure> {
        let mut output = BoundedOutput(Vec::new());
        output
            .0
            .try_reserve_exact(MAX_RESPONSE_BYTES)
            .map_err(|_| LogQueryWireFailure)?;
        serde_json::to_writer(&mut output, self).map_err(|_| LogQueryWireFailure)?;
        Ok(output.0)
    }
}
struct BoundedOutput(Vec<u8>);
impl std::io::Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_RESPONSE_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
