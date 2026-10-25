use std::error::Error;

use positron_kernel::{LedgerFailureCode, SnapshotLeaseId, WorkClass};
use positron_query::{
    QueryBudget, QueryBudgetDimension, QueryEvent, QueryFailureCode, QueryTerminal,
};

use super::support::{SequenceClock, zero_work_clock_service};
use super::terminal_and_bounds::QueryFixture;

#[test]
fn deadline_expiring_during_snapshot_admission_retains_the_typed_result_header()
-> Result<(), Box<dyn Error>> {
    for (label, observed, paged) in [
        ("admission-exact-expiry", 105, false),
        ("admission-past-expiry", 106, false),
        ("paged-admission-exact-expiry", 105, true),
        ("paged-admission-past-expiry", 106, true),
    ] {
        QueryFixture::scoped(label, |fixture| {
            fixture.kernel.append_log("retained", 20, 1)?;
            let service = zero_work_clock_service(
                fixture.kernel.authority.governor(),
                fixture.kernel.ledger()?,
                1,
                SequenceClock::shared([100, 100, 100, observed]),
            );
            let query = service.plan_pipeline(
                fixture.context,
                "logs | range query_time 0 100 | limit 1",
                QueryBudget::new(1_048_576, 16, 16, 16_384, 1_048_576, 5)?,
            )?;
            let stream = if paged {
                service.execute_page(query)?
            } else {
                service.execute(query)?
            };
            let events = stream.collect::<Vec<_>>();
            assert!(
                matches!(events.first(), Some(QueryEvent::Header(_))),
                "an admitted query must frame its incomplete result"
            );
            assert!(matches!(events.as_slice(), [QueryEvent::Header(_),
                QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete))]
                if incomplete.code() == QueryFailureCode::BudgetExhausted
                    && incomplete.stats().limiting_budget() == Some(QueryBudgetDimension::WallSeconds)
                    && incomplete.stats().records() == 0
                    && incomplete.stats().output_bytes() == 0
                    && incomplete.stats().wall_seconds() == observed - 100));
            let Some(QueryEvent::Header(header)) = events.first() else {
                return Err("missing query header".into());
            };
            assert_eq!(
                fixture
                    .kernel
                    .ledger()?
                    .resume_snapshot_lease(SnapshotLeaseId::new(header.lease().identity())?, 100)
                    .expect_err("non-resumable incomplete result releases its durable lease")
                    .code(),
                LedgerFailureCode::SnapshotExpired
            );
            assert_eq!(
                fixture
                    .kernel
                    .authority
                    .governor()
                    .inspect()?
                    .outstanding_for(WorkClass::InteractiveQueryTail),
                0
            );
            Ok(())
        })?;
    }
    Ok(())
}
