//! One bounded transport window over the native Tail owner.
use super::*;
use positron_query::{TailEvent, TailStats, TailTerminal};

pub(super) fn execute(
    services: &ServiceHandle,
    bearer: &str,
    request: &api::LogQueryTailRequest,
) -> Result<Vec<u8>, ServiceFailure> {
    let query = request
        .query
        .as_ref()
        .ok_or(ServiceFailure::InvalidRequest)?;
    let budget = native_budget(
        query
            .budget
            .as_ref()
            .ok_or(ServiceFailure::InvalidRequest)?,
    )?;
    super::super::with_native_query_service(
        services,
        bearer,
        services.instance.logs_shard,
        128,
        |service, context| {
            let query = service
                .plan_pipeline(context, &query.pipeline, budget)
                .map_err(|failure| ServiceFailure::QueryRejected(failure.code()))?;
            let tenant = crate::services::context_tenant(context)?;
            let _drain = services
                .instance
                .enter_query_execution_for(tenant, query.cancellation())
                .map_err(|_| ServiceFailure::Unauthorized)?;
            let mut tail = match request.cursor.as_ref() {
                Some(bytes) => {
                    let cursor = positron_query::TailCursor::from_bytes(bytes)
                        .map_err(|_| ServiceFailure::InvalidRequest)?;
                    service.resume_tail(query, &cursor)
                },
                None => service.tail(
                    query,
                    match request.historical_rows {
                        Some(rows) => positron_query::TailStart::Historical {
                            max_rows: usize::try_from(rows)
                                .map_err(|_| ServiceFailure::InvalidRequest)?,
                        },
                        None => positron_query::TailStart::Now,
                    },
                ),
            }
            .map_err(|failure| ServiceFailure::QueryRejected(failure.code()))?;
            services.notify_maintenance_worker();
            let initial_cursor = tail.cursor().as_bytes().to_vec();
            let mut response = api::LogQueryResponse {
                events: Vec::with_capacity(3),
            };
            let mut header = None;
            let mut acknowledgement = request.acknowledgement.as_ref();
            let mut delivery_cursor = None;
            // Header, optional replay acknowledgement, one delivery/idle, terminal.
            // The native pending batch is never acknowledged before caller receipt.
            for _ in 0..6 {
                match tail.poll().ok_or(ServiceFailure::Internal)? {
                    TailEvent::Header(value) => {
                        let mut wire = result::header(&value)?;
                        wire.initial_cursor = Some(initial_cursor.clone());
                        header = Some(value);
                        response.events.push(api::LogQueryEvent {
                            event: Some(api::log_query_event::Event::Header(wire)),
                        });
                    },
                    TailEvent::Batch(batch) => {
                        if let Some(receipt) = acknowledgement.take() {
                            let digest: [u8; 32] = receipt
                                .digest
                                .as_slice()
                                .try_into()
                                .map_err(|_| ServiceFailure::InvalidRequest)?;
                            tail.acknowledge(receipt.sequence, digest)
                                .map_err(|failure| ServiceFailure::QueryRejected(failure.code()))?;
                            continue;
                        }
                        let schema = header.as_ref().ok_or(ServiceFailure::Internal)?;
                        let rows = batch
                            .records()
                            .iter()
                            .map(|row| result::row(row, schema.schema().types()))
                            .collect::<Result<Vec<_>, _>>()?;
                        response.events.push(api::LogQueryEvent {
                            event: Some(api::log_query_event::Event::Batch(api::LogQueryBatch {
                                sequence: batch.sequence(),
                                rows,
                                prior_digest: batch.prior_digest().to_vec(),
                                digest: batch.digest().to_vec(),
                            })),
                        });
                        delivery_cursor = Some(tail.cursor().as_bytes().to_vec());
                        tail.disconnect();
                    },
                    TailEvent::Idle => {
                        if acknowledgement.is_some() {
                            return Err(ServiceFailure::InvalidRequest);
                        }
                        tail.disconnect();
                    },
                    TailEvent::Terminal(terminal) => {
                        if acknowledgement.is_some() {
                            return Err(ServiceFailure::InvalidRequest);
                        }
                        let mut wire = terminal_result(terminal);
                        if wire.continuation_cursor.is_some()
                            && let Some(cursor) = delivery_cursor
                        {
                            wire.continuation_cursor = Some(cursor);
                        }
                        response.events.push(api::LogQueryEvent {
                            event: Some(api::log_query_event::Event::Terminal(wire)),
                        });
                        return response.encode_tail().map_err(|_| ServiceFailure::Internal);
                    },
                }
            }
            Err(ServiceFailure::Internal)
        },
    )
}
fn terminal_result(value: TailTerminal) -> api::LogQueryTerminal {
    let (reason, cursor, stats) = match value {
        TailTerminal::ConsumerLagged { cursor, stats } => ("consumer_lagged", cursor, stats),
        TailTerminal::BudgetExhausted { cursor, stats } => ("budget_exhausted", cursor, stats),
        TailTerminal::Expired { cursor, stats } => ("snapshot_expired", cursor, stats),
        TailTerminal::AuthorizationChanged { cursor, stats } => {
            ("authorization_changed", cursor, stats)
        },
        TailTerminal::Cancelled { cursor, stats } => ("cancelled", cursor, stats),
        TailTerminal::Disconnected { cursor, stats } => ("disconnected", cursor, stats),
        TailTerminal::StoreUnavailable { cursor, stats } => ("store_unavailable", cursor, stats),
    };
    api::LogQueryTerminal {
        state: "incomplete".into(),
        reason: reason.into(),
        stats: Some(tail_stats(stats)),
        continuation_cursor: cursor.map(|cursor| cursor.as_bytes().to_vec()),
        affected_ranges: Vec::new(),
    }
}
fn tail_stats(value: TailStats) -> api::LogQueryStats {
    api::LogQueryStats {
        records: value.emitted_records(),
        scanned_bytes: value.scanned_bytes(),
        decoded_records: value.decoded_records(),
        output_bytes: value.emitted_bytes(),
        memory_peak_bytes: value.memory_peak_bytes(),
        cpu_work_units: value.cpu_work_units(),
        wall_seconds: value.elapsed_seconds(),
        last_sequence: value.last_sequence(),
        result_digest: value.result_digest().to_vec(),
        cumulative_budget: Some(result::budget(value.cumulative_budget())),
        resume_count: value.resume_count(),
        repeated_batch_count: value.repeated_batch_count(),
        limiting_budget: value
            .limiting_budget()
            .map(|budget| result::budget_name(budget).into()),
        reduced_pruning: value.reduced_pruning(),
    }
}
