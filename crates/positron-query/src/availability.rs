use positron_kernel::{
    AuthenticatedEventRange, AuthenticatedIngestRange, IntegrityQuarantineFinding,
};

use crate::{LogicalPlan, QueryAffectedRange, TemporalAxis};

/// Converts kernel-owned quarantines into query-semantic completeness facts.
/// The kernel never interprets a query range and query never decodes payloads.
pub(crate) fn affected_ranges(
    plan: &LogicalPlan,
    holes: &[IntegrityQuarantineFinding],
) -> Vec<QueryAffectedRange> {
    let mut affected = Vec::new();
    for hole in holes {
        let range = match plan.temporal_axis() {
            // Commit order cannot prove wall-clock coverage, so every Query
            // Time request is conservatively incomplete when its source has a hole.
            TemporalAxis::QueryTime => Some(QueryAffectedRange::Unknown {
                axis: TemporalAxis::QueryTime,
            }),
            TemporalAxis::EventTime => event_intersection(plan, hole.event_range()),
            TemporalAxis::IngestTime => ingest_intersection(plan, hole.ingest_range()),
        };
        if let Some(range) = range {
            affected.push(range);
        }
    }
    affected
}

fn event_intersection(
    plan: &LogicalPlan,
    range: AuthenticatedEventRange,
) -> Option<QueryAffectedRange> {
    match range {
        AuthenticatedEventRange::Known { earliest, latest }
            if plan.temporal_range().start_nanoseconds() <= latest.value()
                && earliest.value() < plan.temporal_range().end_nanoseconds() =>
        {
            Some(QueryAffectedRange::Known {
                axis: TemporalAxis::EventTime,
                earliest_nanoseconds: earliest.value(),
                latest_nanoseconds: latest.value(),
            })
        },
        AuthenticatedEventRange::Known { .. } => None,
        AuthenticatedEventRange::Unavailable(_) => Some(QueryAffectedRange::Unknown {
            axis: TemporalAxis::EventTime,
        }),
    }
}

fn ingest_intersection(
    plan: &LogicalPlan,
    range: AuthenticatedIngestRange,
) -> Option<QueryAffectedRange> {
    match range {
        AuthenticatedIngestRange::Known { earliest, latest }
            if plan.temporal_range().start_nanoseconds() <= latest.value()
                && earliest.value() < plan.temporal_range().end_nanoseconds() =>
        {
            Some(QueryAffectedRange::Known {
                axis: TemporalAxis::IngestTime,
                earliest_nanoseconds: earliest.value(),
                latest_nanoseconds: latest.value(),
            })
        },
        AuthenticatedIngestRange::Known { .. } => None,
        AuthenticatedIngestRange::Unavailable => Some(QueryAffectedRange::Unknown {
            axis: TemporalAxis::IngestTime,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::affected_ranges;
    use crate::{LogicalPlan, TemporalAxis, TemporalRange};

    #[test]
    fn query_time_holes_are_conservative_without_a_wall_clock_claim() {
        let plan = LogicalPlan::logs(
            TemporalAxis::QueryTime,
            TemporalRange::new(10, 20).expect("fixed range"),
            1,
        );
        assert!(affected_ranges(&plan, &[]).is_empty());
    }
}
