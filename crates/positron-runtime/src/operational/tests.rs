use super::*;
use crate::services::ServiceFailure;

#[test]
fn query_failure_details_are_closed_optional_and_keep_the_existing_ring_and_counters()
-> Result<(), Box<dyn std::error::Error>> {
    let telemetry = OperationalTelemetry::default();
    for failure in [
        ServiceFailure::CatalogUnavailable,
        ServiceFailure::StorageUnavailable,
        ServiceFailure::KeyUnavailable,
        ServiceFailure::CorruptState,
    ] {
        telemetry.record_query(
            RequestOutcome::from_status(503),
            std::time::Duration::from_micros(7),
            Some(failure),
        );
        let event = telemetry
            .take_pending()
            .map_err(|_| "pending")?
            .ok_or("event")?
            .json();
        assert_eq!(
            event.get("outcome").and_then(serde_json::Value::as_str),
            Some("unavailable")
        );
        assert_eq!(
            event.get("failure").and_then(serde_json::Value::as_str),
            crate::services::maintenance_failure_category(failure)
        );
        assert_eq!(
            event
                .get("duration_micros")
                .and_then(serde_json::Value::as_u64),
            Some(7)
        );
    }
    for (status, failure) in [(200, None), (503, Some(ServiceFailure::Cancelled))] {
        telemetry.record_query(
            RequestOutcome::from_status(status),
            std::time::Duration::ZERO,
            failure,
        );
        let event = telemetry
            .take_pending()
            .map_err(|_| "pending")?
            .ok_or("event")?
            .json();
        assert!(event.get("failure").is_none());
    }
    for _ in 0..33 {
        telemetry.record_query(
            RequestOutcome::from_status(503),
            std::time::Duration::ZERO,
            Some(ServiceFailure::Internal),
        );
    }
    assert_eq!(telemetry.snapshot().map_err(|_| "ring")?.len(), 32);
    assert_eq!(
        telemetry.dropped.load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    let mut metrics = String::new();
    telemetry.metrics(&mut metrics, false);
    assert!(
        metrics.contains("positron_queries_total{outcome=\"success\"} 1"),
        "{metrics}"
    );
    assert!(
        metrics.contains("positron_queries_total{outcome=\"unavailable\"} 38"),
        "{metrics}"
    );
    Ok(())
}
