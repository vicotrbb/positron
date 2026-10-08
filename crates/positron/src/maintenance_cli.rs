use std::collections::{BTreeMap, BTreeSet};
use std::io::{IsTerminal, Read};
use std::net::SocketAddr;
use std::process::ExitCode;

use positron_api::maintenance::{
    MAX_STATUS_PAGE_TASKS, MAX_TASKS, MaintenanceControlResponse, MaintenanceExplainRequest,
    MaintenancePauseRequest, MaintenanceResumeRequest, MaintenanceRunRequest,
    MaintenanceServiceClient, MaintenanceServiceClientFailure, MaintenanceStatusRequest,
    MaintenanceTaskAcknowledgement, MaintenanceTaskStatus, MaintenanceTransport,
    MaintenanceWindowRequest,
};
use zeroize::Zeroizing;

pub(super) fn run(arguments: impl Iterator<Item = String>) -> ExitCode {
    match execute(arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("positron: {message}");
            ExitCode::from(2)
        },
    }
}

fn execute(arguments: impl Iterator<Item = String>) -> Result<(), &'static str> {
    let (transport, command) = parse(arguments)?;
    let input = std::io::stdin();
    if input.is_terminal() {
        return Err("credential input must be a pipe; terminal input is refused to prevent echo");
    }
    let mut credential = Zeroizing::new(String::new());
    input
        .take(1025)
        .read_to_string(&mut credential)
        .map_err(|_| "credential input unavailable")?;
    let bearer = credential.trim_end_matches(['\r', '\n']);
    if credential.len() > 1024
        || bearer.is_empty()
        || bearer.len() > 1024
        || !bearer
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err("invalid credential input");
    }
    let client =
        MaintenanceServiceClient::new(transport).map_err(|_| "API endpoint unavailable")?;
    match command {
        Command::Status => {
            let completed = complete_status(&client, bearer)?;
            println!(
                "queued={} running={} deferred={} terminal={} total={} tasks={} pages={}",
                completed.status.queued,
                completed.status.running,
                completed.status.deferred,
                completed.status.terminal,
                completed.status.total,
                completed.tasks.len(),
                completed.pages,
            );
            for task in &completed.tasks {
                print_task(task);
            }
            let stdout = std::io::stdout();
            let mut output = stdout.lock();
            for finding in &completed.findings {
                write_integrity_finding(&mut output, finding)?;
            }
            flush_integrity_findings(&mut output)?;
        },
        Command::Explain(request) => {
            let response = client.explain(bearer, &request).map_err(client_failure)?;
            print_task(&response.task);
        },
        Command::Run(request) => {
            let response = client.run(bearer, &request).map_err(client_failure)?;
            print_acknowledgement(&response.task);
            println!("resource_generation={}", response.resource_generation);
        },
        Command::Pause(request) => {
            let response = client.pause(bearer, &request).map_err(client_failure)?;
            print_control(&response);
        },
        Command::Resume(request) => {
            let response = client.resume(bearer, &request).map_err(client_failure)?;
            print_control(&response);
        },
        Command::Window(request) => {
            let response = client.window(bearer, &request).map_err(client_failure)?;
            println!(
                "deferred_classes={} until_unix_seconds={} catalog_generation={} audit_position={}",
                response.deferred_classes.join(","),
                response.until_unix_seconds,
                response.catalog_generation,
                response.audit_position,
            );
        },
    }
    Ok(())
}

fn complete_status(
    client: &MaintenanceServiceClient,
    bearer: &str,
) -> Result<CompletedStatus, &'static str> {
    let mut request = MaintenanceStatusRequest::default();
    let mut cursors = BTreeSet::new();
    let mut identities = BTreeSet::new();
    let mut tasks = Vec::with_capacity(MAX_TASKS);
    let mut pages = 0;
    let mut findings = Vec::new();
    let status = loop {
        if pages == MAX_TASKS / MAX_STATUS_PAGE_TASKS {
            return Err("maintenance status pagination exceeded its bounded registry");
        }
        let response = client.status(bearer, &request).map_err(client_failure)?;
        let status = MaintenanceStatus::from(&response);
        for finding in response.integrity_findings {
            if !findings.contains(&finding) {
                findings.push(finding);
            }
        }
        pages += 1;
        if tasks.len() + response.tasks.len() > MAX_TASKS
            || response
                .tasks
                .iter()
                .any(|task| !identities.insert(task.identity.clone()))
        {
            return Err(
                "maintenance status pagination did not advance; inspect current state before retrying",
            );
        }
        tasks.extend(response.tasks);
        match response.next_cursor {
            Some(cursor) => {
                if !cursors.insert(cursor.clone()) {
                    return Err(
                        "maintenance status pagination did not advance; inspect current state before retrying",
                    );
                }
                request =
                    MaintenanceStatusRequest::page_after(cursor, MAX_STATUS_PAGE_TASKS as u32);
            },
            None => break status,
        }
    };
    Ok(CompletedStatus {
        status,
        tasks,
        findings,
        pages,
    })
}

struct CompletedStatus {
    status: MaintenanceStatus,
    tasks: Vec<MaintenanceTaskStatus>,
    findings: Vec<positron_api::maintenance::IntegrityQuarantineDescriptor>,
    pages: usize,
}

fn write_integrity_finding(
    output: &mut impl std::io::Write,
    finding: &positron_api::maintenance::IntegrityQuarantineDescriptor,
) -> Result<(), &'static str> {
    writeln!(
        output,
        "integrity_quarantine tenant={} signal={} shard={} segment={} base_position={} event_provenance={} event_earliest_unix_nanos={} event_latest_unix_nanos={} ingest_provenance={} ingest_earliest_unix_nanos={} ingest_latest_unix_nanos={}",
        finding.tenant,
        finding.signal,
        finding.shard,
        finding.segment,
        finding.base_position,
        finding.event_range.provenance,
        unknown(finding.event_range.earliest_unix_nanos),
        unknown(finding.event_range.latest_unix_nanos),
        finding.ingest_range.provenance,
        unknown(finding.ingest_range.earliest_unix_nanos),
        unknown(finding.ingest_range.latest_unix_nanos),
    )
    .map_err(|_| "output unavailable")
}

fn flush_integrity_findings(output: &mut impl std::io::Write) -> Result<(), &'static str> {
    output.flush().map_err(|_| "output unavailable")
}

struct MaintenanceStatus {
    queued: u32,
    running: u32,
    deferred: u32,
    terminal: u32,
    total: u32,
}

impl From<&positron_api::maintenance::MaintenanceStatusResponse> for MaintenanceStatus {
    fn from(response: &positron_api::maintenance::MaintenanceStatusResponse) -> Self {
        Self {
            queued: response.queued,
            running: response.running,
            deferred: response.deferred,
            terminal: response.terminal,
            total: response.total,
        }
    }
}

fn print_control(response: &MaintenanceControlResponse) {
    print_acknowledgement(&response.task);
    println!(
        "action={} resource_generation={} pause_until_unix_seconds={} audit_position={}",
        response.action,
        response
            .resource_generation
            .map_or_else(|| "none".to_owned(), |value| value.to_string()),
        response
            .pause_until_unix_seconds
            .map_or_else(|| "none".to_owned(), |value| value.to_string()),
        response.audit_position,
    );
}

fn print_acknowledgement(task: &MaintenanceTaskAcknowledgement) {
    println!(
        "identity={} class={} scope={} submitted_at_unix_seconds={}",
        task.identity, task.class, task.scope, task.submitted_at_unix_seconds,
    );
}

fn print_task(task: &MaintenanceTaskStatus) {
    println!(
        "identity={} class={} scope={} phase={} submitted_at_unix_seconds={} checkpoint_sequence={} checkpoint_completed_inputs={} last_progress_at_unix_seconds={} no_durable_progress_slo_breached={} no_durable_progress_slo_seconds={} resource_generation={} reservations={} expected_foreground_impact={} conflict_owner={} blocked_precondition={} backlog_age_seconds={} input_object_count={} output_object_count={} estimated_output_object_amplification_milli={} pause_until_unix_seconds={} maintenance_window_until_unix_seconds={} automatic_resume_at_unix_seconds={} capacity_risk={} retention_impact={} recovery_impact={} terminal_outcome={} terminal_failure_class={} safe_actions={} cancellation_requested={}",
        task.identity,
        task.class,
        task.scope,
        task.phase,
        task.submitted_at_unix_seconds,
        unknown(task.checkpoint_sequence),
        unknown(task.checkpoint_completed_inputs),
        unknown(task.last_progress_at_unix_seconds),
        unknown(task.no_durable_progress_slo_breached),
        unknown(task.no_durable_progress_slo_seconds),
        unknown(task.resource_generation),
        reservations(task.reservations.as_ref()),
        reservations(task.expected_foreground_impact.as_ref()),
        task.conflict_owner.as_deref().unwrap_or("unknown"),
        task.blocked_precondition.as_deref().unwrap_or("unknown"),
        unknown(task.backlog_age_seconds),
        task.input_object_count,
        task.output_object_count,
        unknown(task.estimated_output_object_amplification_milli),
        unknown(task.pause_until_unix_seconds),
        unknown(task.maintenance_window_until_unix_seconds),
        unknown(task.automatic_resume_at_unix_seconds),
        task.capacity_risk.as_deref().unwrap_or("unknown"),
        task.retention_impact.as_deref().unwrap_or("unknown"),
        task.recovery_impact.as_deref().unwrap_or("unknown"),
        task.terminal_outcome.as_deref().unwrap_or("unknown"),
        task.terminal_failure_class.as_deref().unwrap_or("unknown"),
        if task.safe_actions.is_empty() {
            "none".to_owned()
        } else {
            task.safe_actions.join(",")
        },
        task.cancellation_requested,
    );
}

fn unknown(value: Option<impl ToString>) -> String {
    value.map_or_else(|| "unknown".to_owned(), |value| value.to_string())
}

fn reservations(
    reservations: Option<&positron_api::maintenance::MaintenanceResourceReservations>,
) -> String {
    reservations.map_or_else(
        || "unknown".to_owned(),
        |reservations| {
            format!(
                "memory_bytes={},queue_slots={},task_slots={},buffer_cache_bytes={},batch_items={},lease_slots={},retry_slots={},io_permits={},cpu_work_units={},file_descriptors={},disk_headroom_bytes={}",
                reservations.memory_bytes,
                reservations.queue_slots,
                reservations.task_slots,
                reservations.buffer_cache_bytes,
                reservations.batch_items,
                reservations.lease_slots,
                reservations.retry_slots,
                reservations.io_permits,
                reservations.cpu_work_units,
                reservations.file_descriptors,
                reservations.disk_headroom_bytes,
            )
        },
    )
}

fn client_failure(failure: MaintenanceServiceClientFailure) -> &'static str {
    match failure {
        MaintenanceServiceClientFailure::InvalidRequest => "invalid maintenance request",
        MaintenanceServiceClientFailure::AuthenticationRejected => "authentication rejected",
        MaintenanceServiceClientFailure::SourceUnavailable => {
            "maintenance source unavailable; inspect current state before retrying"
        },
        MaintenanceServiceClientFailure::TaskUnavailable => {
            "maintenance task unavailable; inspect current state before retrying"
        },
        MaintenanceServiceClientFailure::PreconditionFailed => {
            "maintenance precondition failed; inspect current state before retrying"
        },
        MaintenanceServiceClientFailure::IdempotencyConflict => {
            "maintenance idempotency conflict; inspect current state before retrying"
        },
        MaintenanceServiceClientFailure::AdministrationUnavailable => {
            "maintenance administration unavailable; retry with the same idempotency key"
        },
        MaintenanceServiceClientFailure::Transport => "maintenance API transport failed",
    }
}

enum Command {
    Status,
    Explain(MaintenanceExplainRequest),
    Run(MaintenanceRunRequest),
    Pause(MaintenancePauseRequest),
    Resume(MaintenanceResumeRequest),
    Window(MaintenanceWindowRequest),
}

fn parse(
    mut arguments: impl Iterator<Item = String>,
) -> Result<(MaintenanceTransport, Command), &'static str> {
    let operation = arguments.next().ok_or(USAGE)?;
    if !matches!(
        operation.as_str(),
        "status" | "explain" | "run" | "pause" | "resume" | "window"
    ) {
        return Err(USAGE);
    }
    let mut options = BTreeMap::new();
    let mut credential_stdin = false;
    let mut allow_plaintext = false;
    while let Some(option) = arguments.next() {
        if option == "--credential-stdin" {
            if credential_stdin {
                return Err("duplicate maintenance option");
            }
            credential_stdin = true;
            continue;
        }
        if option == "--allow-plaintext" {
            if allow_plaintext {
                return Err("duplicate maintenance option");
            }
            allow_plaintext = true;
            continue;
        }
        if !matches!(
            option.as_str(),
            "--endpoint"
                | "--server-name"
                | "--trust-file"
                | "--task-id"
                | "--tenant"
                | "--signal"
                | "--shard"
                | "--resource-generation"
                | "--duration-seconds"
                | "--expected-catalog-generation"
                | "--deferred-classes"
                | "--idempotency-key"
        ) {
            return Err("unknown maintenance option");
        }
        let value = arguments.next().ok_or("missing maintenance option value")?;
        if options.insert(option, value).is_some() {
            return Err("duplicate maintenance option");
        }
    }
    if !credential_stdin {
        return Err(
            "--credential-stdin is required; secrets are never accepted as arguments or environment variables",
        );
    }
    let transport = transport(&mut options, allow_plaintext)?;
    let command = match operation.as_str() {
        "status" => Command::Status,
        "explain" => Command::Explain(MaintenanceExplainRequest {
            identity: take(&mut options, "--task-id")?,
        }),
        "run" => Command::Run(MaintenanceRunRequest::new(
            "compaction".to_owned(),
            take(&mut options, "--tenant")?,
            take(&mut options, "--signal")?,
            take(&mut options, "--shard")?
                .parse()
                .map_err(|_| "invalid maintenance shard")?,
            take(&mut options, "--idempotency-key")?,
        )),
        "pause" => Command::Pause(MaintenancePauseRequest::new(
            take(&mut options, "--task-id")?,
            take(&mut options, "--resource-generation")?
                .parse()
                .map_err(|_| "invalid resource generation")?,
            take(&mut options, "--duration-seconds")?
                .parse()
                .map_err(|_| "invalid maintenance pause duration")?,
            take(&mut options, "--idempotency-key")?,
        )),
        "resume" => Command::Resume(MaintenanceResumeRequest::new(
            take(&mut options, "--task-id")?,
            take(&mut options, "--idempotency-key")?,
        )),
        "window" => Command::Window(MaintenanceWindowRequest::new(
            take(&mut options, "--deferred-classes")?
                .split(',')
                .map(ToOwned::to_owned)
                .collect(),
            take(&mut options, "--expected-catalog-generation")?
                .parse()
                .map_err(|_| "invalid catalog generation")?,
            take(&mut options, "--duration-seconds")?
                .parse()
                .map_err(|_| "invalid maintenance window duration")?,
            take(&mut options, "--idempotency-key")?,
        )),
        _ => return Err(USAGE),
    };
    if !options.is_empty() {
        return Err("option does not apply to maintenance operation");
    }
    match &command {
        Command::Status | Command::Explain(_) => {},
        Command::Run(request) => request
            .validate()
            .map_err(|_| "invalid maintenance run request")?,
        Command::Pause(request) => request
            .validate()
            .map_err(|_| "invalid maintenance pause request")?,
        Command::Resume(request) => request
            .validate()
            .map_err(|_| "invalid maintenance resume request")?,
        Command::Window(request) => request
            .validate()
            .map_err(|_| "invalid maintenance window request")?,
    }
    Ok((transport, command))
}

fn transport(
    options: &mut BTreeMap<String, String>,
    allow_plaintext: bool,
) -> Result<MaintenanceTransport, &'static str> {
    let endpoint: SocketAddr = take(options, "--endpoint")?
        .parse()
        .map_err(|_| "invalid API endpoint")?;
    if endpoint.port() == 0 {
        return Err("invalid API endpoint");
    }
    if allow_plaintext {
        if options.contains_key("--server-name") || options.contains_key("--trust-file") {
            return Err("TLS options do not apply to plaintext opt-out");
        }
        Ok(MaintenanceTransport::PlaintextOptOut { endpoint })
    } else {
        Ok(MaintenanceTransport::Tls {
            endpoint,
            server_name: take(options, "--server-name")?,
            trust_file: take(options, "--trust-file")?.into(),
        })
    }
}

fn take(options: &mut BTreeMap<String, String>, name: &str) -> Result<String, &'static str> {
    options
        .remove(name)
        .ok_or("required maintenance option absent")
}

const USAGE: &str = "usage: positron maintenance status|explain|run|pause|resume|window --endpoint IP:PORT --credential-stdin [operation options] [--server-name NAME --trust-file PATH | --allow-plaintext]";

#[cfg(test)]
mod tests {
    use super::*;

    fn integrity_finding() -> positron_api::maintenance::IntegrityQuarantineDescriptor {
        positron_api::maintenance::IntegrityQuarantineDescriptor {
            tenant: "00000000-0000-0000-0000-000000000001".to_owned(),
            signal: "logs".to_owned(),
            shard: 1,
            segment: "00000000000000000000000000000001".to_owned(),
            base_position: 0,
            event_range: positron_api::maintenance::AuthenticatedTimeRangeDescriptor {
                provenance: "missing_source_time".to_owned(),
                earliest_unix_nanos: None,
                latest_unix_nanos: None,
            },
            ingest_range: positron_api::maintenance::AuthenticatedTimeRangeDescriptor {
                provenance: "known".to_owned(),
                earliest_unix_nanos: Some(10),
                latest_unix_nanos: Some(10),
            },
        }
    }

    #[test]
    fn integrity_finding_writer_reports_a_closed_stdout_sink() {
        struct ClosedOutput;

        impl std::io::Write for ClosedOutput {
            fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let finding = integrity_finding();
        let mut rendered = Vec::new();
        write_integrity_finding(&mut rendered, &finding).expect("available stdout");
        assert_eq!(
            String::from_utf8(rendered).expect("UTF-8 status row"),
            "integrity_quarantine tenant=00000000-0000-0000-0000-000000000001 signal=logs shard=1 segment=00000000000000000000000000000001 base_position=0 event_provenance=missing_source_time event_earliest_unix_nanos=unknown event_latest_unix_nanos=unknown ingest_provenance=known ingest_earliest_unix_nanos=10 ingest_latest_unix_nanos=10\n"
        );

        let mut output = ClosedOutput;
        assert_eq!(
            write_integrity_finding(&mut output, &finding),
            Err("output unavailable")
        );

        struct FlushFailingOutput;

        impl std::io::Write for FlushFailingOutput {
            fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
                Ok(buffer.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
        }

        let mut output = FlushFailingOutput;
        assert_eq!(
            flush_integrity_findings(&mut output),
            Err("output unavailable")
        );
    }

    #[test]
    fn every_maintenance_operation_defaults_to_tls_with_explicit_plaintext_opt_out() {
        for command in [
            "status",
            "explain --task-id abababababababababababababababab",
            "run --tenant 22222222-2222-2222-2222-222222222222 --signal logs --shard 1 --idempotency-key 01010101-0101-0101-0101-010101010101",
            "pause --task-id abababababababababababababababab --resource-generation 1 --duration-seconds 60 --idempotency-key 01010101-0101-0101-0101-010101010101",
            "resume --task-id abababababababababababababababab --idempotency-key 01010101-0101-0101-0101-010101010101",
            "window --deferred-classes compaction --expected-catalog-generation 1 --duration-seconds 60 --idempotency-key 01010101-0101-0101-0101-010101010101",
        ] {
            let parsed = parse(valid(command).split_whitespace().map(ToOwned::to_owned))
                .expect("TLS maintenance command");
            assert!(
                matches!(parsed.0, MaintenanceTransport::Tls { .. }),
                "{command}"
            );
        }
        let plaintext = parse(
            "status --endpoint 127.0.0.1:8080 --credential-stdin --allow-plaintext"
                .split_whitespace()
                .map(ToOwned::to_owned),
        )
        .expect("plaintext opt-out");
        assert!(matches!(
            plaintext.0,
            MaintenanceTransport::PlaintextOptOut { .. }
        ));
    }

    #[test]
    fn maintenance_transport_rejects_ambiguous_or_incomplete_tls_options() {
        for command in [
            "status --endpoint 127.0.0.1:8080 --credential-stdin --server-name localhost",
            "status --endpoint 127.0.0.1:8080 --credential-stdin --trust-file ca.pem",
            "status --endpoint 127.0.0.1:8080 --credential-stdin --allow-plaintext --server-name localhost",
            "status --endpoint 127.0.0.1:8080 --credential-stdin --allow-plaintext --trust-file ca.pem",
        ] {
            assert!(
                parse(command.split_whitespace().map(ToOwned::to_owned)).is_err(),
                "{command}"
            );
        }
    }

    fn valid(command: &str) -> String {
        format!(
            "{command} --endpoint 127.0.0.1:8080 --credential-stdin --server-name localhost --trust-file ca.pem"
        )
    }
}
