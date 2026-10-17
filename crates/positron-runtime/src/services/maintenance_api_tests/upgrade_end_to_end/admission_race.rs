//! Queue a same-key native lookup at the existing intent publication seam.
use super::*;
use positron_api::upgrade::{UpgradeRequest as WireRequest, UpgradeResponse};

pub(super) fn start_with_queued_lookup(
    process: &crate::RunningProcess,
    endpoint: std::net::SocketAddr,
    administrator: &str,
    request: &WireRequest,
) -> Result<UpgradeResponse, Box<dyn std::error::Error>> {
    let services = process.services().ok_or("source services")?;
    let lookup_services = services.clone();
    let (published, publication) = std::sync::mpsc::sync_channel(1);
    let (queued, queue) = std::sync::mpsc::sync_channel(1);
    let mut lookup = request.clone();
    lookup.action = "lookup".into();
    lookup.candidate_manifest = None;
    lookup.repository_id = None;
    lookup.retention_seconds = None;
    lookup.expected_catalog_generation = None;
    let bytes = request.encode()?;
    std::thread::scope(|scope| {
        let reader = scope.spawn(move || {
            publication
                .recv_timeout(Duration::from_secs(30))
                .expect("intent publication");
            assert!(
                lookup_services
                    .try_catalog_operation()
                    .expect("shared gate")
                    .is_none(),
                "start must still own the publication gate"
            );
            queued.send(()).expect("start observer");
            let client = positron_api::upgrade::UpgradeServiceClient::new(
                positron_api::upgrade::UpgradeTransport::PlaintextOptOut { endpoint },
            )
            .expect("lookup client");
            client.manage(administrator, &lookup)
        });
        let started = positron_kernel::with_catalog_publication_event_hook_after(
            positron_kernel::CatalogPublicationFault::SynchronizeCommit,
            0,
            move || {
                published.send(()).expect("lookup observer");
                queue
                    .recv_timeout(Duration::from_secs(30))
                    .expect("queued lookup");
            },
            || services.manage_upgrade(administrator, &bytes),
        );
        let looked_up = reader
            .join()
            .map_err(|_| "lookup thread panicked")?
            .map_err(|error| format!("queued native lookup: {error:?}"))?;
        let started = started.map_err(|error| format!("concurrent accepted start: {error:?}"))?;
        assert_eq!(started.operation, looked_up.operation);
        assert_eq!(started.details, looked_up.details);
        assert_eq!(
            started.catalog_generation, looked_up.catalog_generation,
            "read-only lookup must not publish another generation"
        );
        Ok(started)
    })
}
