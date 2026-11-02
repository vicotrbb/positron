use super::initialization::Roots;
use crate::{InitializationPlan, InstanceBootstrap};
use std::{error::Error, sync::Arc};

#[test]
fn process_health_tracks_system_lease_expiry_and_automatic_owner_refresh()
-> Result<(), Box<dyn Error>> {
    use crate::{Liveness, ProcessPhase, Readiness};
    use std::time::{Duration, Instant};

    let roots = Roots::new()?;
    let paths = roots
        .paths()
        .map_err(|code| format!("paths: {code:?}"))?
        .with_key_cache_lease(positron_kernel::key_provider::KeyCacheLease::new(
            Duration::from_secs(1),
        )?);
    let initialized = Arc::new(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let services = crate::services::ServiceHandle::new(Arc::clone(&initialized))?;
    let state = crate::health::ProcessState::starting();
    state
        .set_inspection_authority(Arc::clone(&initialized))
        .map_err(|_| "inspection authority unavailable")?;
    state.transition(ProcessPhase::Serving);
    let health = state.health();
    services.attach_health(health.clone());
    state.set_plaintext_listener_warnings(&[
        crate::PublicPlaintextApiStartupIntent::configuration_file("127.0.0.1:8080".parse()?),
    ]);
    assert_eq!(health.readiness(), Readiness::Ready);
    let warnings = health.security_warnings();
    let in_flight_health = health.clone();
    let admission = positron_kernel::RootRewrapSession::admit_provider(&initialized._authority)?;
    drop(
        positron_kernel::RootRewrapSession::with_key_admission_action(
            move || {
                assert_eq!(in_flight_health.readiness(), Readiness::NotReady);
                assert_eq!(in_flight_health.security_warnings(), warnings);
                assert!(in_flight_health.admits_data_or_mutation());
                assert_eq!(in_flight_health.pending_integrity_fence_request(), None);
                assert_eq!(in_flight_health.liveness(), Liveness::Live);
                assert_eq!(in_flight_health.diagnostic_status(), "degraded");
            },
            || initialized.key.catalog_secret(initialized.instance),
        )?,
    );
    drop(admission);
    assert_eq!(health.readiness(), Readiness::Ready);
    assert!(!health.security_warnings().is_empty());
    state.set_plaintext_listener_warnings(&[]);
    assert_eq!(health.readiness(), Readiness::Ready);
    let deadline = Instant::now() + Duration::from_secs(3);
    while initialized.data_protection_health()?.system_ready {
        assert!(Instant::now() < deadline, "system lease did not expire");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(health.liveness(), Liveness::Live);
    assert_eq!(health.readiness(), Readiness::NotReady);
    assert_eq!(health.diagnostic_status(), "degraded");

    let cancellation = crate::TaskCancellation::new();
    let worker_cancellation = cancellation.clone();
    let worker = std::thread::spawn(move || services.run_maintenance_worker(&worker_cancellation));
    let deadline = Instant::now() + Duration::from_secs(3);
    while health.readiness() != Readiness::Ready && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let recovered = health.readiness();
    cancellation.cancel();
    worker.join().map_err(|_| "maintenance worker panicked")??;
    assert_eq!(recovered, Readiness::Ready);
    assert_eq!(health.liveness(), Liveness::Live);
    assert_eq!(health.diagnostic_status(), "healthy");
    Ok(())
}
