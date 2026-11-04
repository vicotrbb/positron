use super::super::terminal_and_bounds::QueryFixture;
use positron_kernel::{
    CatalogPublicationFault, LedgerCompletionState, LedgerFailureCode, MaintenanceCoordinator,
    SnapshotLeaseId, with_catalog_publication_fault_after,
};
use positron_query::{QueryEvent, QueryFailureCode, QueryTerminal};
use std::error::Error;

#[test]
fn paired_cursor_cancellation_cannot_claim_rejection_after_releasing_one_source()
-> Result<(), Box<dyn Error>> {
    QueryFixture::scoped("paired-cancel-partial", |fixture| {
        fixture.kernel.append_trace([0x81; 16], [0x82; 8], 20, 1)?;
        fixture
            .kernel
            .append_log_with_trace("first", 20, [0x81; 16], [0x82; 8], 2)?;
        fixture.kernel.append_trace([0x83; 16], [0x84; 8], 21, 3)?;
        fixture
            .kernel
            .append_log_with_trace("second", 21, [0x83; 16], [0x84; 8], 4)?;
        let coordinator = MaintenanceCoordinator::new();
        let service = fixture
            .correlation_service(1)?
            .with_maintenance_coordinator(&coordinator);
        let query = service.plan_pipeline(
            fixture.context,
            "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 2",
            super::budget(),
        )?;
        let events = service.execute_page(query)?.collect::<Vec<_>>();
        let header = events
            .iter()
            .find_map(|event| match event {
                QueryEvent::Header(value) => Some(value),
                _ => None,
            })
            .ok_or("header")?;
        let trace_lease = SnapshotLeaseId::new(
            header
                .correlation_snapshot()
                .ok_or("paired snapshot")?
                .trace_lease()
                .identity(),
        )?;
        let source_lease = SnapshotLeaseId::new(header.lease().identity())?;
        let cursor = events
            .iter()
            .find_map(|event| match event {
                QueryEvent::Terminal(QueryTerminal::Continued(cursor)) => Some(cursor.clone()),
                _ => None,
            })
            .ok_or("paired cursor")?;
        let failure =
            with_catalog_publication_fault_after(CatalogPublicationFault::RenameMarker, 1, || {
                service.cancel_cursor(fixture.context, &cursor)
            })
            .expect_err("second source publication is rejected after the first was released");
        assert_eq!(failure.code(), QueryFailureCode::StoreUnavailable);
        assert_eq!(
            failure.completion_state(),
            LedgerCompletionState::RecoveryRequired
        );
        assert_eq!(
            fixture
                .kernel
                .trace_ledger()?
                .snapshot_lease_usage(trace_lease, 100)
                .expect_err("first source was already released")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );
        assert!(
            fixture
                .kernel
                .ledger()?
                .snapshot_lease_usage(source_lease, 100)
                .is_ok()
        );
        service.cancel_cursor(fixture.context, &cursor)?;
        Ok(())
    })
}
