use std::collections::VecDeque;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::collector::trace::v1::trace_service_client::TraceServiceClient;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use positron_config::NetworkListenerRole;
use positron_ingest::{
    AdmissionGroupOutcome, IngestFailureCode, IngestOutcome, IngestRequestOutcome,
    NativeLogAdmissionGroups,
};
use positron_kernel::MountQualification;
use tonic::Code;

use super::super::serve;
use crate::native_host::{Admission, NativeListener, TransportProfile, compiled_http2_profile};
use crate::services::ReceiverTestBackend;
use crate::{
    BootstrapPaths, InitializationPlan, InstanceBootstrap, ListenerRole, ServiceHandle,
    TaskCancellation,
};

#[tokio::test(flavor = "current_thread")]
async fn live_receiver_distinguishes_precommit_retry_from_postcommit_ambiguity()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(ScriptedBackend::new([
        Completion::RetryableBeforeCommit,
        Completion::Committed,
        Completion::AmbiguousAfterCommit,
        Completion::Committed,
    ]));
    let harness = ReceiverHarness::start(backend.clone())?;
    let mut client = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        LogsServiceClient::connect(format!("http://{}", harness.endpoint)),
    )
    .await??;

    let retryable = harness.authorize(request("retryable"))?;
    let failure = tokio::time::timeout(std::time::Duration::from_secs(2), client.export(retryable))
        .await?
        .expect_err("pre-commit failure must remain retryable");
    assert_eq!(
        failure.code(),
        Code::Unavailable,
        "{failure}; backend calls={}",
        backend.calls()
    );
    assert_eq!(
        failure.message(),
        "OTLP Logs ingest is temporarily unavailable"
    );
    assert_eq!(backend.committed_records(), 0);

    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.export(harness.authorize(request("retryable"))?),
    )
    .await??;
    assert_eq!(backend.committed_records(), 1);

    let ambiguous = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.export(harness.authorize(request("ambiguous"))?),
    )
    .await?
    .expect_err("post-commit failure must expose ambiguity");
    assert_eq!(ambiguous.code(), Code::Unavailable);
    assert_eq!(
        ambiguous.message(),
        "OTLP Logs commit outcome is ambiguous; retry may duplicate records"
    );
    assert_eq!(backend.committed_records(), 2);

    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.export(harness.authorize(request("ambiguous"))?),
    )
    .await??;
    assert_eq!(backend.committed_records(), 3);
    drop(client);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn live_trace_receiver_accepts_authenticated_protobuf_and_gzip_clients()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = ReceiverHarness::start(Arc::new(ScriptedBackend::new([])))?;
    let mut client = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        TraceServiceClient::connect(format!("http://{}", harness.endpoint)),
    )
    .await??;

    let response = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.export(harness.authorize_trace(trace_request(0x31))?),
    )
    .await??;
    assert!(response.into_inner().partial_success.is_none());

    let mut unsupported = trace_request(0x39);
    unsupported
        .get_mut()
        .resource_spans
        .first_mut()
        .and_then(|resource| resource.scope_spans.first_mut())
        .and_then(|scope| scope.spans.first_mut())
        .ok_or("trace fixture span missing")?
        .attributes
        .push(KeyValue {
            key: "profile-only".to_owned(),
            key_strindex: 1,
            ..KeyValue::default()
        });
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.export(harness.authorize_trace(unsupported)?),
    )
    .await?
    .expect("unsupported development field is a per-span rejection");
    let partial = response
        .into_inner()
        .partial_success
        .expect("per-span rejection is reported as partial success");
    assert_eq!(partial.rejected_spans, 1);
    assert_eq!(
        partial.error_message,
        "some spans were permanently rejected"
    );

    let mut gzip_client = client.send_compressed(tonic::codec::CompressionEncoding::Gzip);
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        gzip_client.export(harness.authorize_trace(trace_request(0x41))?),
    )
    .await??;
    assert!(response.into_inner().partial_success.is_none());

    drop(gzip_client);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn live_trace_receiver_rejects_missing_authentication()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = ReceiverHarness::start(Arc::new(ScriptedBackend::new([])))?;
    let mut client = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        TraceServiceClient::connect(format!("http://{}", harness.endpoint)),
    )
    .await??;
    let failure = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.export(trace_request(0x51)),
    )
    .await?
    .expect_err("trace authentication is required");
    assert_eq!(failure.code(), Code::Unauthenticated);
    assert_eq!(
        failure.message(),
        "OTLP Traces request authentication was rejected"
    );
    drop(client);
    harness.finish()?;
    Ok(())
}

#[derive(Clone, Copy)]
enum Completion {
    RetryableBeforeCommit,
    Committed,
    AmbiguousAfterCommit,
}

struct ScriptedBackend {
    completions: Mutex<VecDeque<Completion>>,
    committed: AtomicUsize,
    calls: AtomicUsize,
}

impl ScriptedBackend {
    fn new(completions: impl IntoIterator<Item = Completion>) -> Self {
        Self {
            completions: Mutex::new(completions.into_iter().collect()),
            committed: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
        }
    }

    fn committed_records(&self) -> usize {
        self.committed.load(Ordering::Acquire)
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }
}

impl ReceiverTestBackend for ScriptedBackend {
    fn ingest(&self, groups: NativeLogAdmissionGroups<'_>) -> IngestRequestOutcome {
        self.calls.fetch_add(1, Ordering::AcqRel);
        let groups = groups
            .map(|group| (group.shard(), group.records()))
            .collect::<Vec<_>>();
        let completion = self
            .completions
            .lock()
            .expect("script lock")
            .pop_front()
            .expect("scripted completion");
        if matches!(
            completion,
            Completion::Committed | Completion::AmbiguousAfterCommit
        ) {
            self.committed.fetch_add(
                groups.iter().map(|(_, records)| records).sum(),
                Ordering::AcqRel,
            );
        }
        let outcome = match completion {
            Completion::RetryableBeforeCommit => Some(IngestOutcome::Retryable(
                IngestFailureCode::StorageUnavailable,
            )),
            Completion::AmbiguousAfterCommit => Some(IngestOutcome::Ambiguous(
                IngestFailureCode::StorageUnavailable,
            )),
            Completion::Committed => None,
        };
        IngestRequestOutcome::new(
            outcome
                .into_iter()
                .flat_map(|outcome| {
                    groups.iter().map(move |(shard, records)| {
                        AdmissionGroupOutcome::new(*shard, *records, outcome)
                    })
                })
                .collect(),
        )
    }
}

struct ReceiverHarness {
    endpoint: SocketAddr,
    bearer: String,
    cancellation: TaskCancellation,
    force: TaskCancellation,
    server: Option<JoinHandle<()>>,
    _roots: TestRoots,
}

impl ReceiverHarness {
    fn start(backend: Arc<dyn ReceiverTestBackend>) -> Result<Self, Box<dyn std::error::Error>> {
        let roots = TestRoots::new()?;
        let paths = roots.paths()?;
        drop(InstanceBootstrap::initialize(
            &paths,
            InitializationPlan::non_interactive(),
        )?);
        let bearer = InstanceBootstrap::claim(&paths)?
            .ingest_secret()
            .ok_or("ingest secret missing")?
            .to_owned();
        let services = ServiceHandle::new(Arc::new(InstanceBootstrap::reopen(&paths)?))?;
        services.install_receiver_test_backend(backend)?;
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let endpoint = listener.local_addr()?;
        let admission = Arc::new(Admission {
            role: ListenerRole::OtlpGrpc,
            listener: NativeListener::Tcp(listener),
            accepting: AtomicBool::new(true),
            #[cfg(unix)]
            control_acceptance: std::sync::Mutex::new(()),
            accepted_connections: AtomicUsize::new(0),
            control_path: None,
            transport: Some(TransportProfile::plaintext_opt_out()),
            trusted_proxy: None,
            connection_admission: None,
            connection_protection: None,
            http2_profile: compiled_http2_profile(NetworkListenerRole::OtlpGrpc)?,
            cors_allowed_origins: Vec::new(),
            control_diagnostics: None,
            #[cfg(unix)]
            accept_barrier: std::sync::Mutex::new(None),
        });
        let cancellation = TaskCancellation::new();
        let serve_cancellation = cancellation.clone();
        let force = TaskCancellation::new();
        let serve_force = force.clone();
        let server = std::thread::spawn(move || {
            serve(
                admission,
                serve_cancellation,
                serve_force,
                Some(services),
                None,
            )
            .expect("test OTLP gRPC server");
        });
        Ok(Self {
            endpoint,
            bearer,
            cancellation,
            force,
            server: Some(server),
            _roots: roots,
        })
    }

    fn authorize(
        &self,
        mut request: tonic::Request<ExportLogsServiceRequest>,
    ) -> Result<tonic::Request<ExportLogsServiceRequest>, Box<dyn std::error::Error>> {
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {}", self.bearer).parse()?);
        Ok(request)
    }

    fn authorize_trace(
        &self,
        mut request: tonic::Request<ExportTraceServiceRequest>,
    ) -> Result<tonic::Request<ExportTraceServiceRequest>, Box<dyn std::error::Error>> {
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {}", self.bearer).parse()?);
        Ok(request)
    }

    fn finish(mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.stop()
    }

    fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.cancellation.cancel();
        self.force.cancel();
        if let Some(server) = self.server.take() {
            server.join().map_err(|_| "server panicked")?;
        }
        Ok(())
    }
}

impl Drop for ReceiverHarness {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn request(body: &str) -> tonic::Request<ExportLogsServiceRequest> {
    tonic::Request::new(ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    time_unix_nano: 42,
                    observed_time_unix_nano: 84,
                    body: Some(AnyValue {
                        value: Some(any_value::Value::StringValue(body.to_owned())),
                    }),
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    })
}

fn trace_request(seed: u8) -> tonic::Request<ExportTraceServiceRequest> {
    tonic::Request::new(ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![seed; 16],
                    span_id: vec![seed.wrapping_add(1); 8],
                    name: "grpc-trace".to_owned(),
                    start_time_unix_nano: 42,
                    end_time_unix_nano: 84,
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    })
}

struct TestRoots {
    parent: PathBuf,
    data: PathBuf,
    secrets: PathBuf,
}

impl TestRoots {
    fn new() -> Result<Self, std::io::Error> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_nanos();
        Self::with_nonce(nonce)
    }

    fn with_nonce(nonce: u128) -> Result<Self, std::io::Error> {
        let parent = (0..64)
            .find_map(|attempt| {
                let parent = PathBuf::from("/tmp").join(format!(
                    "p-grpc-private-{}-{nonce}-{attempt}",
                    std::process::id()
                ));
                match fs::create_dir(&parent) {
                    Ok(()) => Some(Ok(parent)),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(error) => Some(Err(error)),
                }
            })
            .transpose()?
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "test root collision bound exhausted",
                )
            })?;
        let data = parent.join("data");
        let secrets = parent.join("secrets");
        fs::create_dir(&data)?;
        fs::create_dir(&secrets)?;
        set_owner_only(&secrets)?;
        Ok(Self {
            parent,
            data,
            secrets,
        })
    }

    fn paths(&self) -> Result<BootstrapPaths, crate::BootstrapFailure> {
        BootstrapPaths::new(&self.data, &self.secrets, MountQualification::LocalHost)
    }
}

#[test]
fn coincident_fixture_clocks_keep_bootstrap_and_cleanup_ownership_separate()
-> Result<(), Box<dyn std::error::Error>> {
    let first = TestRoots::with_nonce(0)?;
    let first_instance =
        InstanceBootstrap::initialize(&first.paths()?, InitializationPlan::non_interactive())?;
    let sentinel = first.parent.join("owner-sentinel");
    fs::write(&sentinel, b"first owner")?;
    let second = TestRoots::with_nonce(0)?;
    let second_instance =
        InstanceBootstrap::initialize(&second.paths()?, InitializationPlan::non_interactive())?;
    drop(second_instance);
    drop(second);
    assert_eq!(fs::read(&sentinel)?, b"first owner");
    drop(first_instance);
    Ok(())
}

#[test]
fn occupied_fixture_candidates_fail_without_adopting_or_removing_an_owner()
-> Result<(), Box<dyn std::error::Error>> {
    let owners = (0..64)
        .map(|_| TestRoots::with_nonce(1))
        .collect::<Result<Vec<_>, _>>()?;
    let sentinel = owners.first().ok_or("first owner")?.parent.join("sentinel");
    fs::write(&sentinel, b"existing owner")?;
    let failure = TestRoots::with_nonce(1).err().ok_or("collision bound")?;
    assert_eq!(failure.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&sentinel)?, b"existing owner");
    Ok(())
}

impl Drop for TestRoots {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.parent);
    }
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[test]
fn grpc_log_authentication_preserves_identity_read_capacity_refusal()
-> Result<(), Box<dyn std::error::Error>> {
    grpc_authentication_preserves_identity_read_capacity_refusal(false)
}

#[test]
fn grpc_trace_authentication_preserves_identity_read_capacity_refusal()
-> Result<(), Box<dyn std::error::Error>> {
    grpc_authentication_preserves_identity_read_capacity_refusal(true)
}

fn grpc_authentication_preserves_identity_read_capacity_refusal(
    traces: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new()?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let bearer = InstanceBootstrap::claim(&paths)?
        .ingest_secret()
        .ok_or("ingest secret missing")?
        .to_owned();
    let instance = Arc::new(InstanceBootstrap::reopen(&paths)?);
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    let generation = instance.catalog_generation();
    let before = instance.resource_governor().inspect()?;
    let authenticate = |credential: Option<&str>| -> Result<_, Box<dyn std::error::Error>> {
        let mut request = tonic::Request::new(());
        if let Some(credential) = credential {
            request
                .metadata_mut()
                .insert("authorization", format!("Bearer {credential}").parse()?);
        }
        Ok(if traces {
            super::super::authenticate_traces(request, &services, None)
        } else {
            super::super::authenticate(request, &services, None)
        })
    };
    for credential in [None, Some("invalid credential")] {
        assert_eq!(
            authenticate(credential)?
                .expect_err("invalid credential must be refused")
                .code(),
            Code::Unauthenticated
        );
    }
    let status = instance
        ._authority
        .with_control_contention_for_test(|| {
            let authorized = if traces {
                services.authorize_traces_with_hints(
                    &bearer,
                    positron_governance::CompatibilityHints::none(),
                )
            } else {
                services.authorize_logs_with_hints(
                    &bearer,
                    positron_governance::CompatibilityHints::none(),
                )
            };
            assert!(matches!(
                authorized,
                Err(crate::ServiceFailure::CapacityUnavailable)
            ));
            authenticate(Some(&bearer))
        })??
        .expect_err("identity read refusal must not admit the request");
    assert_eq!(status.code(), Code::Unavailable);
    assert_eq!(
        status.message(),
        if traces {
            "OTLP Traces ingest capacity is unavailable"
        } else {
            "OTLP Logs ingest capacity is unavailable"
        }
    );
    assert!(status.metadata().is_empty());
    assert_eq!(instance.catalog_generation(), generation);
    let after = instance.resource_governor().inspect()?;
    assert_eq!(
        after.outstanding_reservations(),
        before.outstanding_reservations()
    );
    for dimension in positron_kernel::ResourceDimension::ALL {
        assert_eq!(after.usage(dimension), before.usage(dimension));
    }
    Ok(())
}
