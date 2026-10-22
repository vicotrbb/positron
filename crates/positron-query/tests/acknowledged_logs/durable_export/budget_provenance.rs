use super::*;
use positron_query::{ExportTerminal, QueryBudgetDimension};

#[test]
fn exhausted_export_budgets_retain_signed_terminal_provenance_after_cold_retry()
-> Result<(), Box<dyn Error>> {
    for (dimension, scanned, decoded, output_bytes) in [
        (QueryBudgetDimension::ScannedBytes, 1, 16, 1_048_576),
        (
            QueryBudgetDimension::DecodedRecords,
            1_048_576,
            1,
            1_048_576,
        ),
        (QueryBudgetDimension::OutputBytes, 1_048_576, 16, 1),
    ] {
        QueryFixture::scoped(
            &format!("durable-export-budget-retry-{dimension:?}"),
            |fixture| {
                for (body, timestamp, position) in
                    [("first", 20, 1), ("second", 21, 2), ("third", 22, 3)]
                {
                    fixture.kernel.append_log(body, timestamp, position)?;
                }
                let signer = fixture.export_manifest_signer()?;
                let source = "logs | range query_time -100 100 | limit 3";
                let budget = QueryBudget::new(scanned, decoded, 16, output_bytes, 16_384, 60)?;
                let key = positron_governance::AdministrativeIdempotencyKey::new([0xb4; 16])?;
                let service = zero_work_clock_service(
                    fixture.kernel.authority.governor(),
                    fixture.kernel.ledger()?,
                    1,
                    TestClock::shared(100),
                )
                .with_export_destination_resolver(Arc::new(TestExportDestinationResolver));
                let receipt = service.export_pipeline_as_operation(
                    fixture.kernel.catalog_for_test(),
                    &signer,
                    fixture.context,
                    key,
                    source,
                    budget,
                    "configured",
                    &mut RecordingSink::default(),
                )?;
                let ExportTerminal::Incomplete(failure) = receipt.manifest().terminal() else {
                    panic!("exhausted scan budget must not publish complete export truth");
                };
                assert_eq!(failure.code(), QueryFailureCode::BudgetExhausted);
                assert_eq!(failure.stats().limiting_budget(), Some(dimension));
                service.verify_export_manifest(receipt.manifest())?;
                let operation = positron_governance::DurableOperationAdministration::inspect(
                    fixture.kernel.catalog_for_test(),
                    receipt.operation_id(),
                )?
                .ok_or("durable export operation")?;
                assert_eq!(
                    operation.status(),
                    positron_governance::DurableOperationStatus::Failed
                );
                assert_eq!(
                    operation.irreversible_boundary(),
                    positron_governance::DurableOperationBoundary::ExportManifestPublished
                );
                assert_eq!(
                    operation.terminal_error(),
                    Some(positron_governance::DurableOperationTerminalError::HandlerRejected)
                );
                let audit_count = fixture
                    .kernel
                    .catalog_for_test()
                    .governance_audit_records()?
                    .len();
                let original = receipt.manifest().clone();
                let operation_id = receipt.operation_id();
                let output_identity = original
                    .output_identity()
                    .ok_or("published output identity")?;
                fixture.kernel.seal_and_reopen()?;
                let restarted = zero_work_clock_service(
                    fixture.kernel.authority.governor(),
                    fixture.kernel.ledger()?,
                    1,
                    TestClock::shared(100),
                )
                .with_export_destination_resolver(Arc::new(TestExportDestinationResolver));
                let mut replay_sink = RecordingSink::default();
                let retry = restarted.export_pipeline_as_operation(
                    fixture.kernel.catalog_for_test(),
                    &signer,
                    fixture.context,
                    key,
                    source,
                    budget,
                    "configured",
                    &mut replay_sink,
                )?;
                assert_eq!(retry.operation_id(), operation_id);
                assert_same_durable_manifest(retry.manifest(), &original);
                assert!(!replay_sink.started);
                assert!(replay_sink.batches.is_empty());
                let resolved = restarted.resolve_durable_export(
                    fixture.kernel.catalog_for_test(),
                    fixture.context,
                    operation_id,
                    output_identity,
                    "configured",
                )?;
                assert_same_durable_manifest(resolved.manifest(), &original);
                assert_eq!(
                    fixture
                        .kernel
                        .catalog_for_test()
                        .governance_audit_records()?
                        .len(),
                    audit_count
                );
                Ok(())
            },
        )?;
    }
    Ok(())
}
