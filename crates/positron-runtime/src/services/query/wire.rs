//! Bounded public projection of the existing Log Query event contract.
mod result;
mod value;
use super::{ServiceFailure, ServiceHandle};
use positron_api::log_query as api;
use positron_kernel::{
    ResourceAmounts, ResourceDimension, TransferredResourceReservation, WorkClaim, WorkKind,
};
use positron_query::{QueryBudget, QueryEvent, QueryHeader, QueryTerminal};

// Includes generated wire rows, recursive value containers and the fixed JSON
// buffer. Logical output is capped at 16 KiB and 128 rows by the wire contract.
const RESPONSE_WORKSPACE_BYTES: u64 = (api::MAX_RESPONSE_BYTES as u64) * 16;

pub(in crate::services) fn execute(
    services: &ServiceHandle,
    bearer: &str,
    body: &[u8],
) -> Result<(Vec<u8>, TransferredResourceReservation), ServiceFailure> {
    services.require_data_or_mutation_admission()?;
    let context = super::authorize(services, bearer)?;
    let request = api::LogQueryRequest::decode(body).map_err(|_| ServiceFailure::InvalidRequest)?;
    let requested = request
        .budget
        .as_ref()
        .ok_or(ServiceFailure::InvalidRequest)?;
    let budget = QueryBudget::new(
        requested.scanned_bytes,
        requested.decoded_records,
        requested.output_rows,
        requested.output_bytes,
        requested.memory_bytes,
        requested.wall_seconds,
    )
    .and_then(|budget| budget.with_cpu_work_units(requested.cpu_work_units))
    .and_then(|budget| {
        budget.with_maximum_time_range_nanoseconds(requested.maximum_time_range_nanoseconds)
    })
    .map_err(|_| ServiceFailure::InvalidRequest)?;
    let tenant = crate::services::context_tenant(context)?;
    let claim = WorkClaim::authenticated(
        tenant,
        context.principal_id(),
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, RESPONSE_WORKSPACE_BYTES)
            .map_err(|_| ServiceFailure::Internal)?,
    )
    .map_err(|_| ServiceFailure::Internal)?;
    let reservation = services
        .instance
        .resource_governor()
        .reserve(claim)
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    // Revalidation in the shared executor closes revocation races after bounded
    // request decoding and response admission, without a second authority.
    static PROBE_SELECTED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    let probe_started = (std::env::var_os("POSITRON_117_QUERY_PHASE_PROBE").as_deref()
        == Some(std::ffi::OsStr::new("1"))
        && !PROBE_SELECTED.swap(true, std::sync::atomic::Ordering::Relaxed))
    .then(std::time::Instant::now);
    let bytes = super::with_log_query_events(
        services,
        bearer,
        services.instance.logs_shard,
        &request.pipeline,
        budget,
        probe_started,
        render,
    )?;
    Ok((bytes, reservation.transfer()))
}
fn render(events: &mut dyn Iterator<Item = QueryEvent>) -> Result<Vec<u8>, ServiceFailure> {
    let mut response = api::LogQueryResponse { events: Vec::new() };
    let mut header: Option<QueryHeader> = None;
    let mut terminal = false;
    for event in events {
        if terminal || response.events.len() >= 130 {
            return Err(ServiceFailure::Internal);
        }
        let event = match event {
            QueryEvent::Header(value) if header.is_none() => {
                let output = result::header(&value)?;
                header = Some(value);
                api::log_query_event::Event::Header(output)
            },
            QueryEvent::Header(_) => return Err(ServiceFailure::Internal),
            QueryEvent::Batch(batch) => {
                let header = header.as_ref().ok_or(ServiceFailure::Internal)?;
                let mut rows = Vec::new();
                rows.try_reserve_exact(batch.records().len())
                    .map_err(|_| ServiceFailure::CapacityUnavailable)?;
                for row in batch.records() {
                    rows.push(result::row(row, header.schema().types())?);
                }
                api::log_query_event::Event::Batch(api::LogQueryBatch {
                    sequence: batch.sequence(),
                    rows,
                    prior_digest: batch.prior_digest().to_vec(),
                    digest: batch.digest().to_vec(),
                })
            },
            QueryEvent::Terminal(value) => {
                if header.is_none() {
                    return Err(ServiceFailure::Internal);
                }
                terminal = true;
                api::log_query_event::Event::Terminal(terminal_result(value))
            },
        };
        response
            .events
            .try_reserve(1)
            .map_err(|_| ServiceFailure::CapacityUnavailable)?;
        response
            .events
            .push(api::LogQueryEvent { event: Some(event) });
    }
    if !terminal {
        return Err(ServiceFailure::Internal);
    }
    response
        .encode()
        .map_err(|_| ServiceFailure::CapacityUnavailable)
}
fn terminal_result(terminal: QueryTerminal) -> api::LogQueryTerminal {
    match terminal {
        QueryTerminal::Complete(stats) => api::LogQueryTerminal {
            state: "complete".into(),
            stats: Some(result::stats(stats)),
            ..api::LogQueryTerminal::default()
        },
        QueryTerminal::Continued(cursor) => api::LogQueryTerminal {
            state: "continued".into(),
            continuation_cursor: Some(cursor.as_bytes().to_vec()),
            ..api::LogQueryTerminal::default()
        },
        QueryTerminal::Incomplete(incomplete) => api::LogQueryTerminal {
            state: "incomplete".into(),
            reason: reason(incomplete.code()).into(),
            stats: Some(result::stats(incomplete.stats())),
            affected_ranges: incomplete
                .affected_ranges()
                .iter()
                .map(|range| {
                    let (axis, earliest, latest) = match *range {
                        positron_query::QueryAffectedRange::Known {
                            axis,
                            earliest_nanoseconds,
                            latest_nanoseconds,
                        } => (axis, Some(earliest_nanoseconds), Some(latest_nanoseconds)),
                        positron_query::QueryAffectedRange::Unknown { axis } => (axis, None, None),
                    };
                    api::LogQueryAffectedRange {
                        temporal_axis: match axis {
                            positron_query::TemporalAxis::QueryTime => "query_time",
                            positron_query::TemporalAxis::EventTime => "event_time",
                            positron_query::TemporalAxis::IngestTime => "ingest_time",
                        }
                        .into(),
                        earliest_nanoseconds: earliest,
                        latest_nanoseconds: latest,
                    }
                })
                .collect(),
            continuation_cursor: None,
        },
    }
}
const fn reason(code: positron_query::QueryFailureCode) -> &'static str {
    use positron_query::QueryFailureCode::*;
    match code {
        Unauthorized => "unauthorized",
        IdempotencyConflict => "idempotency_conflict",
        InvalidBudget => "invalid_budget",
        BudgetExhausted => "budget_exhausted",
        InvalidCursor => "invalid_cursor",
        SnapshotExpired => "snapshot_expired",
        AuthorizationChanged => "authorization_changed",
        Cancelled => "cancelled",
        ResourceAdmissionRefused => "resource_admission_refused",
        ResourceExhausted => "resource_exhausted",
        UnsupportedQuery => "unsupported_query",
        StoreUnavailable => "store_unavailable",
        IncompleteData => "incomplete_data",
        MalformedPersistentData => "malformed_persistent_data",
        Internal => "internal",
    }
}
