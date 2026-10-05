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
    affected_ranges_with_intersection(plan, holes, true)
}

/// Converts quarantines for a source consumed as a query dependency.
///
/// Log-to-trace correlation constrains its log input by the user plan but
/// scans its trace dependency by frontier. A trace hole can therefore omit a
/// matching target even when its own timestamps fall outside the log range.
pub(crate) fn dependency_affected_ranges(
    plan: &LogicalPlan,
    holes: &[IntegrityQuarantineFinding],
) -> Vec<QueryAffectedRange> {
    affected_ranges_with_intersection(plan, holes, false)
}

fn affected_ranges_with_intersection(
    plan: &LogicalPlan,
    holes: &[IntegrityQuarantineFinding],
    require_intersection: bool,
) -> Vec<QueryAffectedRange> {
    let mut affected = Vec::new();
    for hole in holes {
        let range = match plan.temporal_axis() {
            // Commit order cannot prove wall-clock coverage, so every Query
            // Time request is conservatively incomplete when its source has a hole.
            TemporalAxis::QueryTime => Some(QueryAffectedRange::Unknown {
                axis: TemporalAxis::QueryTime,
            }),
            TemporalAxis::EventTime => {
                event_affected_range(plan, hole.event_range(), require_intersection)
            },
            TemporalAxis::IngestTime => {
                ingest_affected_range(plan, hole.ingest_range(), require_intersection)
            },
        };
        if let Some(range) = range {
            affected.push(range);
        }
    }
    affected
}

fn event_affected_range(
    plan: &LogicalPlan,
    range: AuthenticatedEventRange,
    require_intersection: bool,
) -> Option<QueryAffectedRange> {
    match range {
        AuthenticatedEventRange::Known { earliest, latest }
            if !require_intersection
                || (plan.temporal_range().start_nanoseconds() <= latest.value()
                    && earliest.value() < plan.temporal_range().end_nanoseconds()) =>
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

fn ingest_affected_range(
    plan: &LogicalPlan,
    range: AuthenticatedIngestRange,
    require_intersection: bool,
) -> Option<QueryAffectedRange> {
    match range {
        AuthenticatedIngestRange::Known { earliest, latest }
            if !require_intersection
                || (plan.temporal_range().start_nanoseconds() <= latest.value()
                    && earliest.value() < plan.temporal_range().end_nanoseconds()) =>
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
