//! Bounded aggregation and the single pending operational output queue.

use super::events::{OperationalEvent, REQUEST_ROLES, RequestOutcome, listener_label};
use super::metrics::{counter_type, gauge};

const QUERY_BUDGETS: [(positron_query::QueryBudgetDimension, &str); 8] = [
    (
        positron_query::QueryBudgetDimension::ScannedBytes,
        "scanned_bytes",
    ),
    (
        positron_query::QueryBudgetDimension::DecodedRecords,
        "decoded_records",
    ),
    (
        positron_query::QueryBudgetDimension::OutputRows,
        "output_rows",
    ),
    (
        positron_query::QueryBudgetDimension::OutputBytes,
        "output_bytes",
    ),
    (
        positron_query::QueryBudgetDimension::MemoryBytes,
        "memory_bytes",
    ),
    (
        positron_query::QueryBudgetDimension::CpuWorkUnits,
        "cpu_work_units",
    ),
    (
        positron_query::QueryBudgetDimension::WallSeconds,
        "wall_seconds",
    ),
    (
        positron_query::QueryBudgetDimension::MaximumTimeRangeNanoseconds,
        "maximum_time_range_nanoseconds",
    ),
];
#[derive(Default)]
struct Buffer {
    ingest_records: [[u64; 4]; 2],
    query_budgets: [u64; 8],
    queries: [u64; 5],
    query_duration_micros: u64,
    records: std::collections::VecDeque<(std::time::Instant, OperationalEvent)>,
    last_evicted_record: Option<std::time::Instant>,
    pending: std::collections::VecDeque<OperationalEvent>,
    requests: [[u64; 5]; 4],
    duration_micros: [u64; 4],
}

/// One bounded aggregation owner; process/maintenance/resource truth stays with its owners.
#[derive(Default)]
pub(crate) struct OperationalTelemetry {
    buffer: std::sync::Mutex<Buffer>,
    next_request: std::sync::atomic::AtomicU64,
    pub(crate) dropped: std::sync::atomic::AtomicU64,
    pub(crate) log_failures: std::sync::atomic::AtomicU64,
    pub(crate) trace_exported: std::sync::atomic::AtomicU64,
    pub(crate) trace_failed: std::sync::atomic::AtomicU64,
    pub(crate) trace_refused: std::sync::atomic::AtomicU64,
}
impl OperationalTelemetry {
    pub(crate) fn record_query(&self, outcome: RequestOutcome, elapsed: std::time::Duration) {
        let duration_micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        match self.buffer.lock() {
            Ok(mut buffer) => {
                if let Some(count) = buffer.queries.get_mut(outcome.index()) {
                    *count = count.saturating_add(1);
                }
                buffer.query_duration_micros =
                    buffer.query_duration_micros.saturating_add(duration_micros);
            },
            Err(_) => {
                self.dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            },
        }
        self.record(OperationalEvent::QueryCompleted {
            outcome,
            duration_micros,
        });
    }
    pub(crate) fn record_query_budget(&self, dimension: positron_query::QueryBudgetDimension) {
        let index = QUERY_BUDGETS
            .iter()
            .position(|(candidate, _)| *candidate == dimension);
        if let Some(index) = index {
            match self.buffer.lock() {
                Ok(mut buffer) => {
                    if let Some(count) = buffer.query_budgets.get_mut(index) {
                        *count = count.saturating_add(1);
                    }
                },
                Err(_) => {
                    self.dropped
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                },
            }
        }
    }
    pub(crate) fn record_ingest(
        &self,
        signal: positron_domain::routing::SignalKind,
        outcome: &positron_ingest::IngestRequestOutcome,
    ) {
        let counts = [
            u64::try_from(outcome.accepted_records()).unwrap_or(u64::MAX),
            u64::try_from(outcome.permanently_rejected_records()).unwrap_or(u64::MAX),
            outcome
                .groups()
                .iter()
                .filter_map(|group| match group.outcome() {
                    positron_ingest::IngestOutcome::Retryable(_) => {
                        Some(u64::try_from(group.attempted_records()).unwrap_or(u64::MAX))
                    },
                    _ => None,
                })
                .fold(0_u64, u64::saturating_add),
            outcome
                .groups()
                .iter()
                .filter_map(|group| match group.outcome() {
                    positron_ingest::IngestOutcome::Ambiguous(_) => {
                        Some(u64::try_from(group.attempted_records()).unwrap_or(u64::MAX))
                    },
                    _ => None,
                })
                .fold(0_u64, u64::saturating_add),
        ];
        let index = match signal {
            positron_domain::routing::SignalKind::Logs => 0,
            positron_domain::routing::SignalKind::Traces => 1,
        };
        match self.buffer.lock() {
            Ok(mut buffer) => {
                if let Some(totals) = buffer.ingest_records.get_mut(index) {
                    for (total, count) in totals.iter_mut().zip(counts) {
                        *total = total.saturating_add(count);
                    }
                }
            },
            Err(_) => {
                self.dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            },
        }
    }
    pub(crate) fn record(&self, event: OperationalEvent) {
        let Ok(mut buffer) = self.buffer.lock() else {
            self.dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        };
        if buffer.records.len() == 32 {
            buffer.last_evicted_record = buffer.records.pop_front().map(|(at, _)| at);
        }
        if buffer.pending.len() == 32 {
            buffer.pending.pop_front();
            self.dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        buffer.records.push_back((std::time::Instant::now(), event));
        buffer.pending.push_back(event);
    }
    pub(crate) fn record_request(
        &self,
        role: crate::ListenerRole,
        status: u16,
        elapsed: std::time::Duration,
    ) {
        let Some(index) = REQUEST_ROLES
            .iter()
            .position(|candidate| *candidate == role)
        else {
            return;
        };
        let outcome = RequestOutcome::from_status(status);
        let duration_micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        if let Ok(mut buffer) = self.buffer.lock() {
            if let Some(count) = buffer
                .requests
                .get_mut(index)
                .and_then(|counts| counts.get_mut(outcome.index()))
            {
                *count = count.saturating_add(1);
            }
            if let Some(sum) = buffer.duration_micros.get_mut(index) {
                *sum = sum.saturating_add(duration_micros);
            }
        } else {
            self.dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let request_id = self
            .next_request
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .saturating_add(1);
        self.record(OperationalEvent::RequestCompleted {
            role,
            outcome,
            request_id,
            duration_micros,
        });
    }
    pub(crate) fn snapshot(
        &self,
    ) -> Result<Vec<OperationalEvent>, crate::health::OperationalLogFailure> {
        self.buffer
            .lock()
            .map(|buffer| buffer.records.iter().map(|(_, event)| *event).collect())
            .map_err(|_| crate::health::OperationalLogFailure::Unavailable)
    }
    pub(crate) fn snapshot_since(
        &self,
        cutoff: std::time::Instant,
    ) -> Result<(Vec<OperationalEvent>, usize, bool), crate::health::OperationalLogFailure> {
        let buffer = self
            .buffer
            .lock()
            .map_err(|_| crate::health::OperationalLogFailure::Unavailable)?;
        let events: Vec<_> = buffer
            .records
            .iter()
            .filter(|(at, _)| *at >= cutoff)
            .map(|(_, event)| *event)
            .collect();
        let omitted = buffer.records.len().saturating_sub(events.len());
        let history_truncated = buffer.last_evicted_record.is_some_and(|at| at >= cutoff);
        Ok((events, omitted, history_truncated))
    }
    pub(crate) fn take_pending(&self) -> Result<Option<OperationalEvent>, crate::TaskFailure> {
        self.buffer
            .lock()
            .map(|mut buffer| buffer.pending.pop_front())
            .map_err(|_| crate::TaskFailure::JoinUnavailable)
    }
    pub(crate) fn metrics(&self, output: &mut String, openmetrics: bool) {
        use std::sync::atomic::Ordering::Relaxed;
        for (name, value) in [
            (
                "operational_events_dropped_total",
                self.dropped.load(Relaxed),
            ),
            (
                "operational_log_failures_total",
                self.log_failures.load(Relaxed),
            ),
            (
                "operational_trace_exported_total",
                self.trace_exported.load(Relaxed),
            ),
            (
                "operational_trace_failures_total",
                self.trace_failed.load(Relaxed),
            ),
            (
                "operational_trace_refused_total",
                self.trace_refused.load(Relaxed),
            ),
        ] {
            counter_type(output, name, openmetrics);
            output.push_str(&format!("positron_{name} {value}\n"));
        }
        match self.buffer.lock() {
            Ok(buffer) => {
                counter_type(output, "queries_total", openmetrics);
                for (outcome, count) in RequestOutcome::ALL.iter().zip(buffer.queries.iter()) {
                    output.push_str(&format!(
                        "positron_queries_total{{outcome=\"{}\"}} {count}\n",
                        outcome.label()
                    ));
                }
                counter_type(output, "query_duration_seconds_total", openmetrics);
                output.push_str(&format!(
                    "positron_query_duration_seconds_total {}\n",
                    buffer.query_duration_micros as f64 / 1_000_000.0
                ));
                counter_type(output, "query_budget_failures_total", openmetrics);
                for ((_, dimension), count) in QUERY_BUDGETS.iter().zip(buffer.query_budgets.iter())
                {
                    output.push_str(&format!("positron_query_budget_failures_total{{dimension=\"{dimension}\"}} {count}\n"));
                }
                counter_type(output, "ingest_records_total", openmetrics);
                for (signal, counts) in ["logs", "traces"].iter().zip(buffer.ingest_records.iter())
                {
                    for (outcome, count) in [
                        "committed",
                        "permanently_rejected",
                        "retryable",
                        "ambiguous",
                    ]
                    .iter()
                    .zip(counts)
                    {
                        output.push_str(&format!("positron_ingest_records_total{{signal=\"{signal}\",outcome=\"{outcome}\"}} {count}\n"));
                    }
                }
                gauge(output, "operational_snapshot_available", 1);
                counter_type(output, "requests_total", openmetrics);
                for (role, counts) in REQUEST_ROLES.iter().zip(buffer.requests.iter()) {
                    let listener = listener_label(*role);
                    for (outcome, count) in RequestOutcome::ALL.iter().zip(counts.iter()) {
                        output.push_str(&format!("positron_requests_total{{listener=\"{listener}\",outcome=\"{}\"}} {count}\n", outcome.label()));
                    }
                }
                counter_type(output, "request_duration_seconds_total", openmetrics);
                for (role, duration) in REQUEST_ROLES.iter().zip(buffer.duration_micros.iter()) {
                    let listener = listener_label(*role);
                    output.push_str(&format!(
                        "positron_request_duration_seconds_total{{listener=\"{listener}\"}} {}\n",
                        *duration as f64 / 1_000_000.0
                    ));
                }
            },
            Err(_) => gauge(output, "operational_snapshot_available", 0),
        }
    }
}

#[cfg(fuzzing)]
pub(crate) fn fuzz_state(data: &[u8]) {
    let telemetry = OperationalTelemetry::default();
    let statuses = [200, 401, 403, 400, 429, 503];
    let mut recorded = 0_usize;
    for chunk in data.chunks(2).take(2048) {
        let role = REQUEST_ROLES
            .get(usize::from(chunk.first().copied().unwrap_or(0) % 4))
            .copied()
            .expect("closed listener");
        let status = statuses
            .get(usize::from(chunk.get(1).copied().unwrap_or(0) % 6))
            .copied()
            .expect("closed status");
        telemetry.record_request(
            role,
            status,
            std::time::Duration::from_micros(u64::from(status)),
        );
        recorded += 1;
    }
    let snapshot = telemetry.snapshot().expect("unpoisoned bounded owner");
    assert_eq!(snapshot.len(), recorded.min(32));
    assert_eq!(
        telemetry.dropped.load(std::sync::atomic::Ordering::Relaxed),
        u64::try_from(recorded.saturating_sub(32)).expect("bounded input")
    );
    for event in snapshot {
        let encoded = serde_json::to_vec(&event.json()).expect("closed JSON");
        assert!(encoded.len() < 512);
        assert_eq!(event.name(), "request_completed");
    }
    let mut output = String::new();
    telemetry.metrics(&mut output, true);
    assert!(output.len() < 8192);
    assert!(output.contains("# TYPE positron_requests counter\n"));
    let mut drained = 0;
    while telemetry.take_pending().expect("bounded queue").is_some() {
        drained += 1;
    }
    assert_eq!(drained, recorded.min(32));
}
