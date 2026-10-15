use super::*;
use opentelemetry_proto::tonic::{
    collector::logs::v1::ExportLogsServiceRequest,
    common::v1::{AnyValue, any_value},
    logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
};
use positron_query::QueryBudget;
use prost::Message;
struct HeldQuery {
    entered: std::sync::mpsc::Sender<()>,
    release: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}
impl crate::services::QueryExecutionTestHook for HeldQuery {
    fn after_admission(&self) {
        if let Some(release) = self.release.lock().expect("query fixture lock").take() {
            self.entered.send(()).expect("query fixture entered");
            release.recv().expect("query fixture release");
        }
    }
}

fn request(body: &str) -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    time_unix_nano: 42,
                    body: Some(AnyValue {
                        value: Some(any_value::Value::StringValue(body.to_owned())),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}
fn budget() -> Result<QueryBudget, Box<dyn std::error::Error>> {
    Ok(QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?.with_cpu_work_units(16)?)
}
fn history(
    services: &crate::ServiceHandle,
    claim: &crate::BootstrapClaim,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    services
        .query_log_bodies(
            claim.query_secret().ok_or("query credential unavailable")?,
            "logs | range query_time 0 100 | limit 16",
            budget()?,
        )
        .map_err(|e| format!("history request: {e:?}").into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_cutover_preserves_log_history_and_retires_only_after_live_references_release()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|e| format!("paths: {e:?}"))?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let mut instance = InstanceBootstrap::reopen(&paths)?;
    // Begin at midnight, when a discovered scrub may be scheduled for later.
    let (retention_time, elapsed) =
        positron_kernel::RetentionTimeAuthority::establish_with_manual_elapsed(
            positron_domain::time::UnixNanoseconds::new(86_400_000_000_000),
        );
    instance.install_retention_time_for_test(retention_time)?;
    let instance = Arc::new(instance);
    let services = crate::ServiceHandle::new(Arc::clone(&instance))?;
    let ingest = claim
        .ingest_secret()
        .ok_or("ingest credential unavailable")?;
    assert_eq!(
        services
            .ingest_otlp_logs(ingest, request("before cutover").encode_to_vec())?
            .accepted_records(),
        1
    );
    assert_eq!(history(&services, &claim)?, ["before cutover"]);
    let credentials = roots
        .data
        .parent()
        .ok_or("fixture parent")?
        .join("credentials");
    std::fs::create_dir(&credentials)?;
    std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o700))?;
    let (port, server) = transcript_transport(
        |port| migration_replies(&instance, port, "immutable-id", 4),
        &[&rustls::version::TLS13],
    )
    .await?;
    let target = ProviderKeyUri::new(
        ProviderFamily::Kmip21,
        &format!("kmip://localhost:{port}/objects/immutable-id"),
        PIN,
    )?;
    let config = || -> Result<_, Box<dyn std::error::Error>> {
        Ok(NativeRootConfiguration::Kmip {
            identity: target.clone(),
            credentials: model(&credentials)?,
        })
    };
    instance.begin_key_provider_migration(config()?)?;
    instance.activate_key_provider_migration(config()?)?;
    assert_eq!(
        instance.key_provider_migration_status()?.active_provider(),
        &target
    );
    assert_eq!(
        services
            .ingest_otlp_logs(ingest, request("after cutover").encode_to_vec())?
            .accepted_records(),
        1
    );
    assert_eq!(
        history(&services, &claim)?,
        ["before cutover", "after cutover"]
    );
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    services.install_query_execution_test_hook(Arc::new(HeldQuery {
        entered: entered_tx,
        release: std::sync::Mutex::new(Some(release_rx)),
    }))?;
    let query_services = services.clone();
    let query_secret = zeroize::Zeroizing::new(
        claim
            .query_secret()
            .ok_or("query credential unavailable")?
            .to_owned(),
    );
    let query = std::thread::spawn(move || {
        query_services.query_log_bodies(
            &query_secret,
            "logs | range query_time 0 100 | limit 16",
            budget().expect("query fixture budget"),
        )
    });
    entered_rx.recv()?;
    let refused = instance.retire_key_provider_predecessor(config()?);
    release_tx.send(())?;
    assert_eq!(
        query.join().map_err(|_| "query fixture panicked")??,
        ["before cutover", "after cutover"]
    );
    assert_eq!(refused, Err(crate::LocalKeyRotationFailure::Busy));
    assert!(
        roots
            .data
            .parent()
            .ok_or("fixture parent")?
            .join("secrets/local-root-key.v1")
            .exists()
    );
    services.prepare_shutdown_schema_checkpoint()?;
    services.publish_prepared_shutdown_schema_checkpoint(&mut || false)?;
    // Make every scrub in this daily scheduling window due before draining.
    // A false wake alone does not mean a future scheduled task is terminal.
    elapsed.advance(900_000_000_000)?;
    let mut quiescent = false;
    for _ in 0..32 {
        if !services.wake_maintenance_worker()? {
            quiescent = true;
            break;
        }
    }
    assert!(quiescent, "bounded maintenance work reaches quiescence");
    drop(services);
    assert!(
        instance
            .maintenance_coordinator()
            .statuses()
            .map_err(|e| format!("maintenance inspection: {e:?}"))?
            .iter()
            .any(|task| task.task().class()
                == positron_kernel::MaintenanceTaskClass::RetentionPublication
                && task.phase() == positron_kernel::MaintenanceTaskPhase::Succeeded
                && task.checkpoint().is_some())
    );
    instance
        .retire_key_provider_predecessor(config()?)
        .map_err(|e| format!("retirement after service release: {e:?}"))?;
    assert!(
        !roots
            .data
            .parent()
            .ok_or("fixture parent")?
            .join("secrets/local-root-key.v1")
            .exists()
    );
    drop(instance);
    let reopened = Arc::new(
        InstanceBootstrap::reopen_with_provider(&paths, config()?)
            .map_err(|e| format!("target cold reopen: {e:?}"))?,
    );
    let services =
        crate::ServiceHandle::new(reopened).map_err(|e| format!("target cold services: {e:?}"))?;
    assert_eq!(
        history(&services, &claim).map_err(|e| format!("target cold history: {e}"))?,
        ["before cutover", "after cutover"]
    );
    let mut successor = request("cold successor");
    successor.resource_logs[0].scope_logs[0].log_records[0].time_unix_nano = 142;
    assert_eq!(
        services
            .ingest_otlp_logs(ingest, successor.encode_to_vec())
            .map_err(|e| format!("target cold ingest: {e:?}"))?
            .accepted_records(),
        1
    );
    assert_eq!(
        history(&services, &claim).map_err(|e| format!("target new history: {e}"))?,
        ["before cutover", "after cutover"]
    );
    assert_eq!(
        services.query_log_bodies(
            claim.query_secret().ok_or("query credential unavailable")?,
            "logs | range query_time 100 200 | limit 16",
            budget()?
        )?,
        ["cold successor"]
    );
    assert_eq!(server.await?.len(), 25);
    Ok(())
}
