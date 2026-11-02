//! Offline restore owns a fresh target until its durable operation is released.
use positron_governance::{AdministrativeIdempotencyKey, DurableOperation, DurableOperationStatus};
use positron_kernel::{RecoveryPassphrase, RecoveryUnlock};
use positron_runtime::{
    BackupRestoreRequest, BackupRestoreSession, BootstrapFailureCode, BootstrapPaths,
    InstanceBootstrap,
};
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, Instant},
};
mod options;
use options::parse;
#[cfg(test)]
mod tests;
const USAGE: &str = "usage: positron backup restore start|status|wait|cancel --config PATH --repository-id UUID --snapshot-id HEX --expected-manifest-checksum HEX --idempotency-key UUID [--locator PATH | native repository target options] --instance HEX --root-key-id HEX --root-created-at N --root-fingerprint HEX --integrity-public-key HEX --integrity-fingerprint HEX [--bundle PATH --identity-file PATH | --bundle PATH --passphrase | configured provider and --source-root-key-id HEX --source-root-created-at N --source-root-fingerprint HEX --provider-epoch N] [--output json] [--wait-seconds N --operation-id HEX --expected-operation-revision N --cancellation-key UUID]";
#[derive(Clone, Copy, Eq, PartialEq)]
enum Action {
    Start,
    Status,
    Wait,
    Cancel,
}
enum Unlock {
    Bundle(Option<PathBuf>),
    Provider,
}
struct Options {
    json: bool,
    action: Action,
    paths: BootstrapPaths,
    configuration: positron_config::EffectiveConfiguration,
    request: BackupRestoreRequest,
    recovery: Unlock,
    cancellation: Option<(AdministrativeIdempotencyKey, u64)>,
    operation: Option<[u8; 16]>,
    wait: Option<Duration>,
}
pub(super) fn run(arguments: impl Iterator<Item = String>) -> ExitCode {
    crate::administrative_cli::exit(execute(arguments, &mut std::io::stdout().lock()))
}
fn execute(
    arguments: impl Iterator<Item = String>,
    output: &mut impl Write,
) -> Result<(), &'static str> {
    let options = parse(arguments)?;
    let passphrase = if matches!(options.recovery, Unlock::Bundle(None)) {
        Some(crate::recovery_cli::read_passphrase(false)?)
    } else {
        None
    };
    let existing = if options.action != Action::Start {
        let operation = inspect(&options, passphrase.as_ref())?;
        check_operation(&options, operation)?;
        if options.action == Action::Status {
            return render(output, operation, options.json);
        }
        Some(operation.operation_id())
    } else {
        None
    };
    let mut session = begin(&options, passphrase.as_ref())?;
    check_operation(&options, session.status())?;
    if existing.is_some_and(|id| id != session.status().operation_id()) {
        return Err("restore operation changed during ownership transfer");
    }
    if let Some((key, revision)) = options.cancellation {
        let operation = session.cancel(key, revision).map_err(|_| "restore cancellation refused; inspect the current operation revision and publication boundary");
        let operation = match operation {
            Ok(operation) => operation,
            Err(error) => {
                render(output, session.status(), options.json)?;
                return Err(error);
            },
        };
        return render(output, operation, options.json);
    }
    if let Some(duration) = options.wait {
        let deadline = Instant::now()
            .checked_add(duration)
            .ok_or("invalid restore wait duration")?;
        loop {
            if Instant::now() >= deadline {
                render(output, session.status(), options.json)?;
                return Err(
                    "restore remains durable; inspect and resume the same target and idempotency key",
                );
            }
            let operation = match session.step() {
                Ok(operation) => operation,
                Err(_) => {
                    render(output, session.status(), options.json)?;
                    return Err(
                        "restore step refused; target remains owned by the same durable operation, inspect before retrying",
                    );
                },
            };
            if operation.status().is_terminal() {
                render(output, operation, options.json)?;
                return match operation.status() {
                    DurableOperationStatus::Succeeded => Ok(()),
                    DurableOperationStatus::Cancelled => {
                        Err("restore was cancelled; target remains offline")
                    },
                    _ => Err("restore failed; target remains offline"),
                };
            }
        }
    }
    render(output, session.status(), options.json)
}
fn unlock<'a>(
    options: &'a Options,
    passphrase: Option<&'a RecoveryPassphrase>,
) -> Result<RecoveryUnlock<'a>, &'static str> {
    match &options.recovery {
        Unlock::Bundle(Some(identity)) => Ok(RecoveryUnlock::IdentityFile(identity)),
        Unlock::Bundle(None) => passphrase
            .map(RecoveryUnlock::Passphrase)
            .ok_or("interactive recovery passphrase is required"),
        Unlock::Provider => Err("native provider does not use local recovery secrets"),
    }
}
fn provider(
    options: &Options,
) -> Result<positron_kernel::key_provider::NativeRootConfiguration, &'static str> {
    positron_runtime::native_root_configuration(
        options
            .configuration
            .provider_access()
            .ok_or("native provider configuration is required")?,
    )
    .map_err(|_| "native provider configuration is unavailable")
}
fn inspect(
    options: &Options,
    passphrase: Option<&RecoveryPassphrase>,
) -> Result<DurableOperation, &'static str> {
    let result = match options.recovery {
        Unlock::Provider => InstanceBootstrap::inspect_restore_with_provider(
            &options.paths,
            &options.configuration,
            &options.request,
            provider(options)?,
        ),
        Unlock::Bundle(_) => InstanceBootstrap::inspect_restore(
            &options.paths,
            &options.configuration,
            &options.request,
            unlock(options, passphrase)?,
        ),
    };
    result.map_err(|_| "restore status unavailable; exact accepted source, target, configuration and recovery identity are required")
}
fn begin(
    options: &Options,
    passphrase: Option<&RecoveryPassphrase>,
) -> Result<BackupRestoreSession, &'static str> {
    let result = match options.recovery {
        Unlock::Provider => InstanceBootstrap::begin_restore_with_provider(
            &options.paths,
            &options.configuration,
            &options.request,
            provider(options)?,
        ),
        Unlock::Bundle(_) => InstanceBootstrap::begin_restore(
            &options.paths,
            &options.configuration,
            &options.request,
            unlock(options, passphrase)?,
        ),
    };
    result.map_err(|failure| {
        let mut diagnostic = std::io::stderr();
        let message = report_begin_failure(failure.code(), &mut diagnostic);
        if let Some(context) = failure.resource_diagnostic()
            && (write!(diagnostic, "positron: restore resource refusal; ").is_err()
                || serde_json::to_writer(&mut diagnostic, &context).is_err()
                || writeln!(diagnostic).is_err())
        {
            return "restore unavailable; begin failed and its diagnostic could not be written; inspect the same target before retrying";
        }
        message
    })
}
fn report_begin_failure(code: BootstrapFailureCode, diagnostic: &mut impl Write) -> &'static str {
    match writeln!(diagnostic, "positron: restore begin refused; code={code:?}") {
        Ok(()) => {
            "restore unavailable; require a fresh target or the exact accepted restore identity and sufficient admitted resources"
        },
        Err(_) => {
            "restore unavailable; begin failed and its diagnostic could not be written; inspect the same target before retrying"
        },
    }
}
fn check_operation(options: &Options, operation: DurableOperation) -> Result<(), &'static str> {
    if options
        .operation
        .is_some_and(|id| operation.operation_id().to_bytes() != id)
    {
        return Err("restore operation identity mismatch");
    }
    Ok(())
}
fn render(
    output: &mut impl Write,
    operation: DurableOperation,
    json: bool,
) -> Result<(), &'static str> {
    if json {
        use positron_governance::DurableOperationTerminalError;
        let terminal_error_code = match operation.terminal_error() {
            None => None,
            Some(DurableOperationTerminalError::HandlerRejected) => Some("handler_rejected"),
            Some(DurableOperationTerminalError::LegacyUnknown) => Some("legacy_unknown"),
            Some(_) => return Err("invalid restore terminal outcome"),
        };
        let report = operation.backup_restore_report().map(|report| {
            report
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        });
        let value = serde_json::json!({
            "kind": "backup_restore",
            "operation_revision": operation.revision(),
            "operation": positron_runtime::durable_operation_response(operation),
            "terminal_error_code": terminal_error_code,
            "verification_report": report,
        });
        serde_json::to_writer(&mut *output, &value).map_err(|_| "restore output unavailable")?;
        return writeln!(output).map_err(|_| "restore output unavailable");
    }
    let status = match operation.status() {
        DurableOperationStatus::Pending => "pending",
        DurableOperationStatus::Running => "running",
        DurableOperationStatus::Succeeded => "succeeded",
        DurableOperationStatus::Failed => "failed",
        DurableOperationStatus::Cancelled => "cancelled",
    };
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    writeln!(output, "kind=backup_restore operation_id={} status={status} phase={:?} progress_percent={} operation_revision={} cancellation={:?} irreversible_boundary={:?} retry={:?}",
        hex(&operation.operation_id().to_bytes()), operation.phase(), operation.progress_percent(), operation.revision(), operation.cancellation(), operation.irreversible_boundary(), operation.retry_guidance())
        .map_err(|_| "restore output unavailable")?;
    if let Some(report) = operation.backup_restore_report() {
        writeln!(output, "verification_report={}", hex(&report))
            .map_err(|_| "restore output unavailable")?;
    }
    Ok(())
}
