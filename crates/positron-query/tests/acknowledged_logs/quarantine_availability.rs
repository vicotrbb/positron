use std::error::Error;

use positron_kernel::{
    ActiveSegmentLedger, IntegrityCancellation, IntegrityScrubBudget, IntegrityVerificationMode,
    IntegrityVerificationOutcome, SegmentProtectionKey, TransactionId,
};
use positron_query::{
    QueryAffectedRange, QueryBudget, QueryEvent, QueryFailureCode, QueryTerminal, TemporalAxis,
};

use super::terminal_and_bounds::QueryFixture;

#[test]
fn reopened_query_uses_authenticated_holes_without_hiding_healthy_same_scope_data()
-> Result<(), Box<dyn Error>> {
    QueryFixture::scoped_compaction("quarantine-query-availability", |fixture| {
        fixture.kernel.append_log("quarantined", 10, 1)?;
        let sealed = fixture.kernel.seal_and_reopen_with_segment()?;
        fixture.kernel.append_log("healthy", 40, 2)?;
        fixture.kernel.corrupt_sealed_segment_for_test(sealed)?;

        let scope = fixture.kernel.ledger()?.scope();
        let report = ActiveSegmentLedger::verify_catalog_integrity(
            fixture.kernel.authority,
            fixture.kernel.catalog_for_test(),
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x34; 32])),
            IntegrityVerificationMode::Online,
            IntegrityScrubBudget::new(8).map_err(|_| "valid scrub budget rejected")?,
            &IntegrityCancellation::new(),
            TransactionId::new([0xe1; 16])?,
            None,
        )?;
        assert_eq!(report.outcome(), IntegrityVerificationOutcome::Quarantined);
        let live_snapshot = fixture.kernel.ledger()?.snapshot()?;
        assert_eq!(live_snapshot.quarantined_holes().len(), 1);
        assert_eq!(live_snapshot.blocks().len(), 1);
        fixture.kernel.reopen_ledger()?;

        let budget = QueryBudget::new(1_048_576, 1_024, 1_024, 1_048_576, 1_048_576, 60)?;
        let service = fixture.service(16)?;

        let healthy = service
            .execute(service.plan_pipeline(
                fixture.context,
                "logs | range event_time 40 50 | limit 16",
                budget,
            )?)?
            .collect::<Vec<_>>();
        assert!(matches!(
            healthy.last(),
            Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
        ));
        assert!(healthy.iter().any(|event| {
            matches!(event, QueryEvent::Batch(batch) if batch.records().iter().any(|record| record.body_text() == Some("healthy")))
        }));

        let event_intersection = service
            .execute(service.plan_pipeline(
                fixture.context,
                "logs | range event_time 10 20 | limit 16",
                budget,
            )?)?
            .collect::<Vec<_>>();
        assert_incomplete(
            &event_intersection,
            QueryAffectedRange::Known {
                axis: TemporalAxis::EventTime,
                earliest_nanoseconds: 10,
                latest_nanoseconds: 10,
            },
        );

        let query_time = service
            .execute(service.plan_pipeline(
                fixture.context,
                "logs | range query_time -100 100 | limit 16",
                budget,
            )?)?
            .collect::<Vec<_>>();
        assert_incomplete(
            &query_time,
            QueryAffectedRange::Unknown {
                axis: TemporalAxis::QueryTime,
            },
        );

        let holes = fixture
            .kernel
            .ledger()?
            .snapshot()?
            .quarantined_holes()
            .to_vec();
        let hole = holes.first().ok_or("quarantine hole missing")?;
        let (ingest_start, ingest_end) = match hole.ingest_range() {
            positron_kernel::AuthenticatedIngestRange::Known { earliest, latest } => (
                earliest.value(),
                latest
                    .value()
                    .checked_add(1)
                    .ok_or("ingest range overflow")?,
            ),
            positron_kernel::AuthenticatedIngestRange::Unavailable => {
                return Err("fixture must retain an authenticated ingest range".into());
            },
        };
        let ingest_intersection = service
            .execute(service.plan_pipeline(
                fixture.context,
                &format!("logs | range ingest_time {ingest_start} {ingest_end} | limit 16"),
                budget,
            )?)?
            .collect::<Vec<_>>();
        assert_incomplete(
            &ingest_intersection,
            QueryAffectedRange::Known {
                axis: TemporalAxis::IngestTime,
                earliest_nanoseconds: ingest_start,
                latest_nanoseconds: ingest_end - 1,
            },
        );

        let nonintersect_start = ingest_end;
        let nonintersect_end = nonintersect_start
            .checked_add(1)
            .ok_or("ingest non-intersection overflow")?;
        let ingest_nonintersect = service
            .execute(service.plan_pipeline(
                fixture.context,
                &format!(
                    "logs | range ingest_time {nonintersect_start} {nonintersect_end} | limit 16"
                ),
                budget,
            )?)?
            .collect::<Vec<_>>();
        assert!(matches!(
            ingest_nonintersect.last(),
            Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
        ));
        Ok(())
    })
}

fn assert_incomplete(events: &[QueryEvent], expected: QueryAffectedRange) {
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::IncompleteData
                && incomplete.affected_ranges() == [expected]
    ));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_))),
        "a query with an affected hole must never stream a partial result as complete data"
    );
}
