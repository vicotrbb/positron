//! The single registered operational task owns logging and bounded external export.

use std::io::{IsTerminal, Write};
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, trace_service_client::TraceServiceClient,
};
use opentelemetry_proto::tonic::common::v1::{AnyValue, InstrumentationScope, KeyValue, any_value};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};

use super::{AdmissionRegistry, NativeListener};
use crate::operational::OperationalEvent;
use crate::{HealthState, ProcessPhase, TaskCancellation, TaskFailure};

pub(super) fn run(
    cancellation: TaskCancellation,
    force: TaskCancellation,
    health: HealthState,
    admissions: AdmissionRegistry,
) -> Result<(), TaskFailure> {
    let mut sink = nonblocking_stderr();
    let terminal = std::io::stderr().is_terminal();
    let mut sequence = 0_u64;
    while !cancellation.is_cancelled() && !force.is_cancelled() {
        let Some(event) = health.operational_telemetry().take_pending()? else {
            std::thread::sleep(Duration::from_millis(5));
            continue;
        };
        let failed = health
            .operational_log_level()
            .map(|level| {
                log_enabled(level, event)
                    && sink
                        .as_mut()
                        .map_or(true, |sink| emit(sink, terminal, event).is_err())
            })
            .unwrap_or(true);
        if failed {
            health
                .operational_telemetry()
                .log_failures
                .fetch_add(1, Ordering::Relaxed);
        }
        let (destination, reservation) = match health.trace_export_context() {
            Ok(Some(context)) => context,
            Ok(None) => continue,
            Err(()) => {
                health
                    .operational_telemetry()
                    .trace_refused
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            },
        };
        if cancellation.is_cancelled()
            || force.is_cancelled()
            || health.phase() != ProcessPhase::Serving
        {
            drop(reservation);
            continue;
        }
        // Includes staged and draining descriptors, not only the latest generation.
        let allowed = destination_allowed(&admissions, destination)?;
        if !allowed {
            health
                .operational_telemetry()
                .trace_refused
                .fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| TaskFailure::SpawnUnavailable)?;
        sequence = sequence.saturating_add(1);
        let result = runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(1), async {
                let endpoint =
                    tonic::transport::Endpoint::from_shared(format!("http://{destination}"))
                        .map_err(|_| ())?
                        .connect_timeout(Duration::from_secs(1))
                        .timeout(Duration::from_secs(1))
                        .concurrency_limit(1)
                        .buffer_size(1)
                        .initial_stream_window_size(8192)
                        .initial_connection_window_size(16384)
                        .http2_adaptive_window(false)
                        .http2_header_table_size(4096)
                        .http2_max_header_list_size(4096);
                let channel = endpoint.connect().await.map_err(|_| ())?;
                if cancellation.is_cancelled()
                    || force.is_cancelled()
                    || health.phase() != ProcessPhase::Serving
                {
                    return Err(());
                }
                if !destination_allowed(&admissions, destination).map_err(|_| ())? {
                    health
                        .operational_telemetry()
                        .trace_refused
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(());
                }
                let response = TraceServiceClient::new(channel)
                    .max_decoding_message_size(4096)
                    .max_encoding_message_size(4096)
                    .export(trace(event, sequence))
                    .await
                    .map_err(|_| ())?;
                if response
                    .into_inner()
                    .partial_success
                    .is_some_and(|partial| partial.rejected_spans != 0)
                {
                    return Err(());
                }
                Ok(())
            })
            .await
            .map_err(|_| ())?
        });
        drop(runtime);
        drop(reservation);
        let counter = if result.is_ok() {
            &health.operational_telemetry().trace_exported
        } else {
            &health.operational_telemetry().trace_failed
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

pub(super) fn destination_allowed(
    admissions: &AdmissionRegistry,
    destination: std::net::SocketAddr,
) -> Result<bool, TaskFailure> {
    Ok(admissions
        .lock()
        .map_err(|_| TaskFailure::JoinUnavailable)?
        .iter()
        .all(|(_, admission)| match &admission.listener {
            NativeListener::Tcp(listener) => listener.local_addr().is_ok_and(|local| {
                !positron_config::operational_trace_conflicts(destination, local)
            }),
            #[cfg(unix)]
            NativeListener::Unix(_) => true,
        }))
}

#[cfg(unix)]
struct NonblockingSink<F: std::os::fd::AsFd>(F);
#[cfg(unix)]
impl<F: std::os::fd::AsFd> Write for NonblockingSink<F> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        rustix::io::write(&self.0, bytes).map_err(Into::into)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[cfg(unix)]
fn nonblocking_stderr() -> std::io::Result<NonblockingSink<std::io::Stderr>> {
    let stderr = std::io::stderr();
    let flags = rustix::fs::fcntl_getfl(&stderr)?;
    rustix::fs::fcntl_setfl(&stderr, flags | rustix::fs::OFlags::NONBLOCK)?;
    Ok(NonblockingSink(stderr))
}
#[cfg(not(unix))]
fn nonblocking_stderr() -> std::io::Result<std::io::Sink> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "nonblocking operational output unavailable",
    ))
}

pub(crate) fn write_diagnostic(
    diagnostic: crate::operational::OperationalDiagnostic,
) -> std::io::Result<()> {
    emit(
        &mut nonblocking_stderr()?,
        std::io::stderr().is_terminal(),
        OperationalEvent::Diagnostic(diagnostic),
    )
}

fn log_enabled(level: positron_config::LogLevel, event: OperationalEvent) -> bool {
    match level {
        positron_config::LogLevel::Error => event.severity() == "error",
        positron_config::LogLevel::Warn => matches!(event.severity(), "error" | "warn"),
        positron_config::LogLevel::Info | positron_config::LogLevel::Debug => true,
    }
}

pub(crate) fn emit(
    sink: &mut impl Write,
    terminal: bool,
    event: OperationalEvent,
) -> std::io::Result<()> {
    let line = if terminal {
        format!("positron: {} {}\n", event.severity(), event.name())
    } else {
        format!("{}\n", event.json())
    };
    // A closed record is below the minimum PIPE_BUF; emit it in one write so
    // concurrent terminal diagnostics cannot interleave JSON fields.
    sink.write_all(line.as_bytes())
}

fn trace(event: OperationalEvent, sequence: u64) -> ExportTraceServiceRequest {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| {
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
        });
    let mut trace_id = Vec::with_capacity(16);
    trace_id.extend_from_slice(&now.to_be_bytes());
    trace_id.extend_from_slice(&sequence.to_be_bytes());
    let duration = match event {
        OperationalEvent::RequestCompleted {
            duration_micros, ..
        }
        | OperationalEvent::QueryCompleted {
            duration_micros, ..
        } => duration_micros.saturating_mul(1000),
        _ => 0,
    };
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(Resource {
                attributes: vec![KeyValue {
                    key: "service.name".to_owned(),
                    value: Some(AnyValue {
                        value: Some(any_value::Value::StringValue("positron".to_owned())),
                    }),
                    ..KeyValue::default()
                }],
                ..Resource::default()
            }),
            scope_spans: vec![ScopeSpans {
                scope: Some(InstrumentationScope {
                    name: "positron.operational".to_owned(),
                    ..InstrumentationScope::default()
                }),
                spans: vec![Span {
                    trace_id,
                    span_id: sequence.to_be_bytes().to_vec(),
                    name: event.name().to_owned(),
                    kind: 1,
                    start_time_unix_nano: now.saturating_sub(duration),
                    end_time_unix_nano: now,
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn stalled_output_sink_returns_without_blocking_owned_worker()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_reader, writer) = rustix::pipe::pipe()?;
        rustix::fs::fcntl_setfl(&writer, rustix::fs::OFlags::NONBLOCK)?;
        let mut sink = NonblockingSink(writer);
        let bytes = [0_u8; 4096];
        for _ in 0..4096 {
            if sink.write(&bytes).is_err() {
                break;
            }
        }
        let started = std::time::Instant::now();
        assert!(emit(&mut sink, false, OperationalEvent::ProcessServing).is_err());
        assert!(started.elapsed() < Duration::from_millis(50));
        Ok(())
    }

    #[test]
    fn structured_operational_output_is_closed_json_and_sink_failure_is_explicit()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(!log_enabled(
            positron_config::LogLevel::Warn,
            OperationalEvent::ProcessServing
        ));
        assert!(log_enabled(
            positron_config::LogLevel::Error,
            OperationalEvent::ProcessFenced
        ));
        let mut output = Vec::new();
        emit(&mut output, false, OperationalEvent::ProcessServing)?;
        let value: serde_json::Value = serde_json::from_slice(&output)?;
        assert_eq!(value["event"], "process_serving");
        assert_eq!(value["severity"], "info");
        assert_eq!(value["component"], "runtime");
        emit(&mut output, true, OperationalEvent::ProcessFenced)?;
        assert!(output.ends_with(b"positron: error process_fenced\n"));
        assert!(
            emit(
                &mut std::io::Cursor::new(&mut [] as &mut [u8]),
                false,
                OperationalEvent::ProcessServing
            )
            .is_err()
        );
        Ok(())
    }
}
