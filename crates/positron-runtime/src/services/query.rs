mod wire;
use std::sync::Arc;
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};
pub(super) use wire::{cancel, execute, execute_session};

use positron_domain::routing::SignalKind;
use positron_kernel::{ActiveSegmentLedger, Catalog, SegmentScope};
use positron_query::{QueryBudget, QueryService};
#[cfg(test)]
use positron_query::{QueryClock, QueryClockFailure, QueryCursor, QueryEvent, QueryFailureCode};

use super::{
    ServiceFailure, ServiceHandle, classify_bootstrap_failure_code, classify_catalog_failure_code,
    classify_ledger_failure_code, collect_query_bodies, map_query_failure, schema_bootstrap,
};
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};

// TEMPORARY SDK127 wall observation. Remove after the platform experiment.
// stage_millis fixed order (each saturates at 999999ms): initial admission/auth,
// decode/admission, Catalog gate, reauth, Catalog/identity/key, ledger open,
// plan/schema setup, schema view entry wait, query Catalog revalidation,
// query guards/clock, source lease/state setup, eager page incl persist/validation,
// schema callback return tail, stream iteration/lease release/render.
// Entry wait is not assumed IO; return tail is not assumed cleanup; none is CPU.
#[derive(Default)]
pub(super) struct QueryTimings {
    initial_auth: std::cell::Cell<u64>,
    decode_admission: std::cell::Cell<u64>,
    catalog_gate: std::cell::Cell<u64>,
    reauthorize: std::cell::Cell<u64>,
    catalog_identity: std::cell::Cell<u64>,
    ledger_open: std::cell::Cell<u64>,
    plan_schema: std::cell::Cell<u64>,
    schema_entry: std::cell::Cell<u64>,
    eager: [std::cell::Cell<u64>; 4],
    schema_return: std::cell::Cell<u64>,
    consume_render: std::cell::Cell<u64>,
    terminal: std::cell::Cell<u64>,
    wall_seconds: std::cell::Cell<u64>,
    limiting_budget: std::cell::Cell<u64>,
}
impl QueryTimings {
    pub(super) fn snapshot(
        &self,
        _elapsed: std::time::Duration,
    ) -> crate::operational::FiniteQueryObservation {
        crate::operational::FiniteQueryObservation {
            stage_millis: [
                self.initial_auth.get(),
                self.decode_admission.get(),
                self.catalog_gate.get(),
                self.reauthorize.get(),
                self.catalog_identity.get(),
                self.ledger_open.get(),
                self.plan_schema.get(),
                self.schema_entry.get(),
                self.eager[0].get(),
                self.eager[1].get(),
                self.eager[2].get(),
                self.eager[3].get(),
                self.schema_return.get(),
                self.consume_render.get(),
            ]
            .map(|micros| (micros / 1000).min(999_999)),
            terminal: self.terminal.get(),
            wall_seconds: self.wall_seconds.get(),
            limiting_budget: self.limiting_budget.get(),
        }
    }
    // Native iterator truth after its existing release/cancellation handling; never client receipt.
    fn observe_terminal(&self, event: &positron_query::QueryEvent) {
        use positron_query::{QueryBudgetDimension as B, QueryEvent, QueryTerminal};
        let stats = match event {
            QueryEvent::Terminal(QueryTerminal::Complete(stats)) => {
                self.terminal.set(1);
                Some(*stats)
            },
            QueryEvent::Terminal(QueryTerminal::Incomplete(value)) => {
                self.terminal.set(2);
                Some(value.stats())
            },
            QueryEvent::Terminal(QueryTerminal::Continued(_)) => {
                self.terminal.set(3);
                None
            },
            _ => None,
        };
        if let Some(stats) = stats {
            self.wall_seconds.set(stats.wall_seconds());
            self.limiting_budget.set(match stats.limiting_budget() {
                None => 0,
                Some(B::ScannedBytes) => 1,
                Some(B::DecodedRecords) => 2,
                Some(B::OutputRows) => 3,
                Some(B::OutputBytes) => 4,
                Some(B::MemoryBytes) => 5,
                Some(B::CpuWorkUnits) => 6,
                Some(B::WallSeconds) => 7,
                Some(B::MaximumTimeRangeNanoseconds) => 8,
            });
        }
    }
}
fn timed<T>(slot: Option<&std::cell::Cell<u64>>, work: impl FnOnce() -> T) -> T {
    let Some(slot) = slot else {
        return work();
    };
    let started = std::time::Instant::now();
    let result = work();
    slot.set(
        slot.get()
            .saturating_add(u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)),
    );
    result
}

#[cfg(test)]
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum QueryTestOutcome {
    Events(Vec<QueryEvent>),
    Failure(QueryFailureCode),
}

#[cfg(test)]
struct RuntimeTestQueryClock;

#[cfg(test)]
impl QueryClock for RuntimeTestQueryClock {
    fn now_seconds(&self) -> Result<u64, QueryClockFailure> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| QueryClockFailure)
    }
}

#[cfg(test)]
pub(super) fn query_events_for_test(
    services: &ServiceHandle,
    context: positron_governance::AuthorizedContext,
    shard: positron_domain::routing::VirtualShardId,
    source: &str,
    budget: QueryBudget,
    page_limit: Option<u16>,
) -> Result<QueryTestOutcome, ServiceFailure> {
    let _catalog_operation = services.catalog_operation()?;
    let instance = &services.instance;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| ServiceFailure::KeyUnavailable)?,
    )
    .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let snapshot = catalog
        .pin()
        .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let identity =
        positron_governance::Identity::open(&snapshot).map_err(|_| ServiceFailure::CorruptState)?;
    let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, shard);
    let protection = super::tenant_segment_key(instance, &identity, scope)?;
    let ledger = ActiveSegmentLedger::open_for_query_with_retention_time(
        &instance._authority,
        &instance.retention_time,
        &catalog,
        scope,
        protection,
    )
    .map_err(|failure| classify_ledger_failure_code(failure.code()))?;
    let service = QueryService::with_clock(
        instance.resource_governor(),
        &ledger,
        page_limit.unwrap_or(100),
        Arc::new(RuntimeTestQueryClock),
    );
    let query = match service.plan_pipeline(context, source, budget) {
        Ok(query) => query,
        Err(failure) => return Ok(QueryTestOutcome::Failure(failure.code())),
    };
    let tenant = super::context_tenant(context)?;
    let _drain = instance
        .enter_query_execution_for(tenant, query.cancellation())
        .map_err(|_| ServiceFailure::Unauthorized)?;
    let schema = services
        .schema_sessions
        .session(instance.tenant, instance.resource_governor())
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    let events = schema
        .with_catalog_view(instance.tenant, |view| match page_limit {
            Some(_) => service.execute_page(query),
            None => service.execute_with_schema(query, view),
        })
        .map_err(schema_bootstrap::classify_replay_failure)?
        .map_err(|failure| QueryTestOutcome::Failure(failure.code()));
    match events {
        Ok(events) => Ok(QueryTestOutcome::Events(events.collect::<Vec<_>>())),
        Err(outcome) => Ok(outcome),
    }
}

#[cfg(test)]
pub(super) fn resume_query_events_for_test(
    services: &ServiceHandle,
    context: positron_governance::AuthorizedContext,
    cursor: &QueryCursor,
    shard: positron_domain::routing::VirtualShardId,
    batch_limit: u16,
) -> Result<QueryTestOutcome, ServiceFailure> {
    let _catalog_operation = services.catalog_operation()?;
    let instance = &services.instance;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| ServiceFailure::KeyUnavailable)?,
    )
    .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let snapshot = catalog
        .pin()
        .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let identity =
        positron_governance::Identity::open(&snapshot).map_err(|_| ServiceFailure::CorruptState)?;
    let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, shard);
    let protection = super::tenant_segment_key(instance, &identity, scope)?;
    let ledger = ActiveSegmentLedger::open_for_query_with_retention_time(
        &instance._authority,
        &instance.retention_time,
        &catalog,
        scope,
        protection,
    )
    .map_err(|failure| classify_ledger_failure_code(failure.code()))?;
    let service = QueryService::with_clock(
        instance.resource_governor(),
        &ledger,
        batch_limit,
        Arc::new(RuntimeTestQueryClock),
    );
    let events = service
        .resume(context, cursor)
        .map_err(|failure| QueryTestOutcome::Failure(failure.code()));
    match events {
        Ok(events) => Ok(QueryTestOutcome::Events(events.collect::<Vec<_>>())),
        Err(outcome) => Ok(outcome),
    }
}

pub(super) fn query_log_bodies(
    services: &ServiceHandle,
    bearer: &str,
    shard: positron_domain::routing::VirtualShardId,
    source: &str,
    budget: QueryBudget,
) -> Result<Vec<String>, ServiceFailure> {
    with_log_query_events(services, bearer, shard, source, budget, None, |events| {
        collect_query_bodies(events)
    })
}

fn authorize(
    services: &ServiceHandle,
    bearer: &str,
) -> Result<positron_governance::AuthorizedContext, ServiceFailure> {
    let instance = &services.instance;
    let initial_identity = instance
        .durable_identity()
        .map_err(|failure| classify_bootstrap_failure_code(failure.code()))?;
    initial_identity
        .attribute(
            &instance.key,
            PresentedCredential::parse(bearer).map_err(|_| ServiceFailure::Unauthorized)?,
            RequestedIntent::Query,
            CompatibilityHints::none(),
        )
        .map_err(|_| ServiceFailure::Unauthorized)
}

fn with_log_query_events<T>(
    services: &ServiceHandle,
    bearer: &str,
    shard: positron_domain::routing::VirtualShardId,
    source: &str,
    budget: QueryBudget,
    timings: Option<&QueryTimings>,
    consume: impl FnOnce(
        &mut dyn Iterator<Item = positron_query::QueryEvent>,
    ) -> Result<T, ServiceFailure>,
) -> Result<T, ServiceFailure> {
    with_log_query_events_mode(
        services,
        bearer,
        shard,
        QueryMode::Finite { source, budget },
        timings,
        consume,
    )
}

#[derive(Clone, Copy)]
pub(super) enum QueryMode<'a> {
    Finite {
        source: &'a str,
        budget: QueryBudget,
    },
    Page {
        source: &'a str,
        budget: QueryBudget,
        batch_limit: u16,
    },
    Resume {
        cursor: &'a positron_query::QueryCursor,
        batch_limit: u16,
    },
}

fn with_log_query_events_mode<T>(
    services: &ServiceHandle,
    bearer: &str,
    shard: positron_domain::routing::VirtualShardId,
    mode: QueryMode<'_>,
    timings: Option<&QueryTimings>,
    consume: impl FnOnce(
        &mut dyn Iterator<Item = positron_query::QueryEvent>,
    ) -> Result<T, ServiceFailure>,
) -> Result<T, ServiceFailure> {
    let classify = |failure: &positron_query::QueryFailure| {
        if matches!(mode, QueryMode::Finite { .. }) {
            map_query_failure(failure)
        } else {
            ServiceFailure::QueryRejected(failure.code())
        }
    };
    let batch_limit = match mode {
        QueryMode::Finite { .. } => 100,
        QueryMode::Page { batch_limit, .. } | QueryMode::Resume { batch_limit, .. } => batch_limit,
    };
    with_native_query_service(
        services,
        bearer,
        shard,
        batch_limit,
        timings,
        |service, context| {
            let instance = &services.instance;
            let tenant = super::context_tenant(context)?;
            let _drain;
            let events = match mode {
                QueryMode::Resume { cursor, .. } => {
                    let cancellation = positron_query::QueryCancellation::new();
                    _drain = instance
                        .enter_query_execution_for(tenant, cancellation.clone())
                        .map_err(|_| ServiceFailure::Unauthorized)?;
                    service
                        .resume_with_cancellation(context, cursor, cancellation)
                        .map_err(|failure| classify(&failure))?
                },
                QueryMode::Finite { source, budget } | QueryMode::Page { source, budget, .. } => {
                    let query = timed(timings.map(|timings| &timings.plan_schema), || {
                        service.plan_pipeline(context, source, budget)
                    })
                    .map_err(|failure| {
                        services.record_query_budget(failure.limiting_budget());
                        classify(&failure)
                    })?;
                    _drain = timed(timings.map(|timings| &timings.plan_schema), || {
                        instance.enter_query_execution_for(tenant, query.cancellation())
                    })
                    .map_err(|_| ServiceFailure::Unauthorized)?;
                    #[cfg(test)]
                    services.await_query_execution_test_hook()?;
                    if matches!(mode, QueryMode::Page { .. }) {
                        service
                            .execute_page(query)
                            .map_err(|failure| classify(&failure))?
                    } else {
                        let schema = timed(timings.map(|timings| &timings.plan_schema), || {
                            services
                                .schema_sessions
                                .session(tenant, instance.resource_governor())
                        })
                        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
                        let entered = timings.map(|_| std::time::Instant::now());
                        let returned = std::cell::Cell::new(None);
                        let result = schema.with_catalog_view(tenant, |catalog| {
                            if let (Some(timings), Some(entered)) = (timings, entered) {
                                timings.schema_entry.set(
                                    u64::try_from(entered.elapsed().as_micros())
                                        .unwrap_or(u64::MAX),
                                );
                                let result = service.execute_with_schema_observed(
                                    query,
                                    catalog,
                                    &timings.eager,
                                );
                                returned.set(Some(std::time::Instant::now()));
                                result
                            } else {
                                service.execute_with_schema(query, catalog)
                            }
                        });
                        if let Some(timings) = timings {
                            // If the callback was not entered, retain the whole failed entry wait.
                            let (slot, started) = match returned.get() {
                                Some(started) => (&timings.schema_return, Some(started)),
                                None => (&timings.schema_entry, entered),
                            };
                            if let Some(started) = started {
                                slot.set(
                                    u64::try_from(started.elapsed().as_micros())
                                        .unwrap_or(u64::MAX),
                                );
                            }
                        }
                        result
                            .map_err(schema_bootstrap::classify_replay_failure)?
                            .map_err(|failure| {
                                services.record_query_budget(failure.limiting_budget());
                                classify(&failure)
                            })?
                    }
                },
            };
            // QueryService publishes the source lease and its expiry task atomically
            // before yielding this stream. Wake only after that durable transition so
            // the registered worker cannot consume a pre-publication signal.
            services.notify_maintenance_worker();
            timed(timings.map(|timings| &timings.consume_render), || {
                consume(&mut events.inspect(|event| {
                    if let Some(timings) = timings {
                        timings.observe_terminal(event);
                    }
                    if let positron_query::QueryEvent::Terminal(
                        positron_query::QueryTerminal::Incomplete(incomplete),
                    ) = event
                    {
                        services.record_query_budget(incomplete.stats().limiting_budget());
                    }
                }))
            })
        },
    )
}

fn with_native_query_service<T>(
    services: &ServiceHandle,
    bearer: &str,
    shard: positron_domain::routing::VirtualShardId,
    batch_limit: u16,
    timings: Option<&QueryTimings>,
    consume: impl FnOnce(
        &QueryService<'_, '_, '_>,
        positron_governance::AuthorizedContext,
    ) -> Result<T, ServiceFailure>,
) -> Result<T, ServiceFailure> {
    let _catalog_operation = timed(timings.map(|timings| &timings.catalog_gate), || {
        services.catalog_operation()
    })?;
    let instance = &services.instance;
    let context = timed(timings.map(|timings| &timings.reauthorize), || {
        authorize(services, bearer)
    })?;
    let (catalog, scope, protection) =
        timed(timings.map(|timings| &timings.catalog_identity), || {
            let catalog = Catalog::open(
                &instance._authority,
                instance.instance,
                instance
                    .key
                    .catalog_secret(instance.instance)
                    .map_err(|_| ServiceFailure::KeyUnavailable)?,
            )
            .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
            let identity = positron_governance::Identity::open(
                &catalog
                    .pin()
                    .map_err(|failure| classify_catalog_failure_code(failure.code()))?,
            )
            .map_err(|_| ServiceFailure::CorruptState)?;
            identity
                .revalidate_query_context(context)
                .map_err(|_| ServiceFailure::Unauthorized)?;
            let tenant = super::context_tenant(context)?;
            let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
            let protection = super::tenant_segment_key(instance, &identity, scope)?;
            Ok::<_, ServiceFailure>((catalog, scope, protection))
        })?;
    let ledger = timed(timings.map(|timings| &timings.ledger_open), || {
        ActiveSegmentLedger::open_for_query_with_retention_time(
            &instance._authority,
            &instance.retention_time,
            &catalog,
            scope,
            protection,
        )
        .map_err(|failure| classify_ledger_failure_code(failure.code()))
    })?;
    let service = QueryService::new(instance._authority.governor(), &ledger, batch_limit)
        .with_maintenance_coordinator(instance.maintenance_coordinator());
    let service = match &services.export_destination_resolver {
        Some(resolver) => service.with_export_destination_resolver(Arc::clone(resolver)),
        None => service,
    };
    consume(&service, context)
}
