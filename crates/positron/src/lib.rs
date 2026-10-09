//! Thin native process composition.

#![forbid(unsafe_code)]

use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};
use std::{path::PathBuf, sync::Arc};

use positron_config::{ConfigurationInputs, NetworkListenerRole, NetworkTransport, resolve};
use positron_kernel::MountQualification;
use positron_runtime::{
    ApplicationRuntime, BootstrapPaths, ExitOutcome, HostInputs, InitializationMode,
    NativeBindings, NativeHost, PublicPlaintextApiStartupIntent, RecoveryAttempt,
    RecoveryAttemptHost, RecoveryDecision, ServeConfiguration, ShutdownTrigger,
};
use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

mod config_cli;
#[cfg(unix)]
mod control_socket;
mod doctor_cli;
mod keys;
mod maintenance_cli;
mod policy;
mod support_bundle;
mod tenant_alias_cli;
mod tenant_lifecycle;
mod tenant_quotas;
mod tenant_retention;
mod tenant_service_cli;
mod verify_cli;

#[doc(hidden)]
pub use support_bundle::{fuzz_live_bundle_request, fuzz_support_bundle_options};

/// Exercises the bounded, untrusted hexadecimal continuation boundary used
/// by `positron verify --offline` before any storage is opened.
#[doc(hidden)]
#[allow(dead_code, reason = "called by the external cargo-fuzz target")]
pub fn fuzz_offline_integrity_continuation_hex(bytes: &[u8]) {
    let Ok(value) = std::str::from_utf8(bytes) else {
        return;
    };
    verify_cli::fuzz_offline_continuation_hex(value);
}

const EXIT_OK: u8 = 0;
const EXIT_CONFIGURATION: u8 = 2;
const EXIT_STARTUP: u8 = 3;
const EXIT_FORCED: u8 = 4;
const STARTUP_RECOVERY_DEADLINE: Duration = Duration::from_secs(3);

pub fn run_native(
    arguments: impl IntoIterator<Item = String>,
    environment: impl IntoIterator<Item = (String, String)>,
) -> ExitCode {
    let mut arguments = arguments.into_iter().peekable();
    if arguments.peek().is_some_and(|argument| argument == "key") {
        arguments.next();
        return keys::run(arguments);
    }
    if arguments
        .peek()
        .is_some_and(|argument| argument == "tenant")
    {
        arguments.next();
        return match arguments.next().as_deref() {
            Some("lifecycle") => tenant_lifecycle::run(arguments),
            Some("alias") => tenant_alias_cli::run(arguments),
            Some("retention") => tenant_retention::run(arguments),
            Some(command @ ("create" | "inspect" | "list" | "update-display-name")) => {
                tenant_service_cli::run(std::iter::once(command.to_owned()).chain(arguments))
            },
            Some(command) => {
                tenant_quotas::run(std::iter::once(command.to_owned()).chain(arguments))
            },
            None => tenant_quotas::run(std::iter::empty()),
        };
    }
    if arguments
        .peek()
        .is_some_and(|argument| argument == "maintenance")
    {
        arguments.next();
        return maintenance_cli::run(arguments);
    }
    if arguments
        .peek()
        .is_some_and(|argument| argument == "doctor")
    {
        arguments.next();
        return doctor_cli::run(arguments, environment);
    }
    if arguments
        .peek()
        .is_some_and(|argument| argument == "support")
    {
        arguments.next();
        return support_bundle::run(arguments, environment);
    }
    if arguments
        .peek()
        .is_some_and(|argument| argument == "policy")
    {
        arguments.next();
        return policy::run(arguments);
    }
    if arguments
        .peek()
        .is_some_and(|argument| argument == "verify")
    {
        arguments.next();
        return verify_cli::run(arguments, environment);
    }
    if arguments
        .peek()
        .is_some_and(|argument| argument == "config")
    {
        arguments.next();
        return config_cli::run(arguments, environment);
    }
    match run(arguments, environment) {
        Ok(outcome) => exit_code(outcome),
        Err(failure) => {
            eprintln!("positron: {}", failure.message());
            ExitCode::from(failure.code())
        },
    }
}

fn run(
    arguments: impl IntoIterator<Item = String>,
    environment: impl IntoIterator<Item = (String, String)>,
) -> Result<ExitOutcome, LaunchFailure> {
    let arguments = Arguments::parse(arguments)?;
    let environment = environment.into_iter().collect::<Vec<_>>();
    let inputs = ConfigurationInputs::try_from_sources(
        arguments.config.as_deref().map(Path::new),
        environment.clone(),
        arguments.overrides.clone(),
    )
    .map_err(|_| LaunchFailure::Configuration)?;
    let effective = resolve(inputs).map_err(|_| LaunchFailure::Configuration)?;
    for warning in effective.security_warnings() {
        eprintln!("positron: warning: {}", warning.message());
    }
    let paths = BootstrapPaths::with_local_key(
        Path::new(effective.data_directory()),
        Path::new(effective.secrets_directory()),
        effective.local_key_file().as_path(),
        MountQualification::LocalHost,
    )
    .map_err(|_| LaunchFailure::Configuration)?;
    let bindings =
        NativeBindings::from_effective(&effective).map_err(|_| LaunchFailure::Configuration)?;
    let host = NativeHost::new(bindings)
        .with_control_diagnostics(Arc::new(support_bundle::LiveSupportBundleCollector));
    let recovery = NativeRecovery::new(
        Signals::new([SIGHUP, SIGINT, SIGTERM]).map_err(|_| LaunchFailure::Signal)?,
    );
    let mut configuration = ServeConfiguration::new(paths, arguments.initialization)
        .with_max_registered_tenants(effective.max_registered_tenants())
        .with_effective_configuration(Arc::new(effective.clone()));
    for (configuration_role, runtime_role) in [
        (
            NetworkListenerRole::Operations,
            positron_runtime::ListenerRole::Operations,
        ),
        (
            NetworkListenerRole::Api,
            positron_runtime::ListenerRole::Api,
        ),
        (
            NetworkListenerRole::OtlpGrpc,
            positron_runtime::ListenerRole::OtlpGrpc,
        ),
        (
            NetworkListenerRole::OtlpHttp,
            positron_runtime::ListenerRole::OtlpHttp,
        ),
        (
            NetworkListenerRole::LokiPush,
            positron_runtime::ListenerRole::LokiPush,
        ),
    ] {
        let Some(profile) = effective.network_listener_profile(configuration_role) else {
            continue;
        };
        if profile.transport() == NetworkTransport::PlaintextOptOut {
            configuration = configuration.with_plaintext_listener_intent(
                PublicPlaintextApiStartupIntent::configuration_file_listener(
                    runtime_role,
                    profile.bind_address(),
                ),
            );
        }
    }
    let process = match ApplicationRuntime::start(
        configuration,
        HostInputs::with_recovery(&host, &host, &recovery),
    ) {
        Ok(process) => process,
        Err(outcome @ (ExitOutcome::Graceful | ExitOutcome::Forced)) => return Ok(outcome),
        Err(outcome) => return Err(LaunchFailure::Startup(outcome)),
    };
    let signals = recovery.into_signals()?;
    let deadline = Duration::from_secs(u64::from(effective.shutdown_grace_seconds()));
    let reload = ReloadInputs {
        config: arguments.config,
        environment,
        overrides: arguments.overrides,
    };
    wait_for_shutdown(
        process,
        signals,
        deadline,
        &reload,
        PathBuf::from(effective.data_directory()),
    )
}

struct ReloadInputs {
    config: Option<PathBuf>,
    environment: Vec<(String, String)>,
    overrides: Vec<(String, String)>,
}

impl ReloadInputs {
    fn resolve(&self) -> Result<Arc<positron_config::EffectiveConfiguration>, ()> {
        let inputs = ConfigurationInputs::try_from_sources(
            self.config.as_deref().map(Path::new),
            self.environment.clone(),
            self.overrides.clone(),
        )
        .map_err(|_| ())?;
        resolve(inputs).map(Arc::new).map_err(|_| ())
    }
}

struct NativeRecovery {
    started: Instant,
    signals: std::sync::Mutex<Option<Signals>>,
}

impl NativeRecovery {
    fn new(signals: Signals) -> Self {
        Self {
            started: Instant::now(),
            signals: std::sync::Mutex::new(Some(signals)),
        }
    }

    fn into_signals(self) -> Result<Signals, LaunchFailure> {
        self.signals
            .into_inner()
            .map_err(|_| LaunchFailure::Signal)?
            .ok_or(LaunchFailure::Signal)
    }

    fn pending_trigger(signals: &mut Signals) -> Option<ShutdownTrigger> {
        pending_termination_trigger(signals)
    }
}

fn pending_termination_trigger(signals: &mut Signals) -> Option<ShutdownTrigger> {
    let count = signals
        .pending()
        .filter(|signal| matches!(*signal, SIGINT | SIGTERM))
        .take(2)
        .count();
    match count {
        0 => None,
        1 => Some(ShutdownTrigger::FirstSignal),
        _ => Some(ShutdownTrigger::SecondSignal),
    }
}

impl RecoveryAttemptHost for NativeRecovery {
    fn after_failure(&self, attempt: RecoveryAttempt) -> RecoveryDecision {
        if attempt.number() >= 32 || self.started.elapsed() >= STARTUP_RECOVERY_DEADLINE {
            return RecoveryDecision::Exhausted;
        }
        let delay =
            Duration::from_millis(10_u64.saturating_mul(u64::from(attempt.number())).min(100));
        let wait_until = Instant::now() + delay;
        while Instant::now() < wait_until && self.started.elapsed() < STARTUP_RECOVERY_DEADLINE {
            let trigger = self
                .signals
                .lock()
                .ok()
                .and_then(|mut signals| signals.as_mut().and_then(Self::pending_trigger));
            if let Some(trigger) = trigger {
                return RecoveryDecision::Terminate(trigger);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        if self.started.elapsed() >= STARTUP_RECOVERY_DEADLINE {
            RecoveryDecision::Exhausted
        } else {
            RecoveryDecision::Retry
        }
    }
}

fn wait_for_shutdown(
    mut process: positron_runtime::RunningProcess,
    mut signals: Signals,
    deadline: Duration,
    reload: &ReloadInputs,
    _crash_data_directory: PathBuf,
) -> Result<ExitOutcome, LaunchFailure> {
    let second_termination_seen = loop {
        // `Signals::forever` would prevent the process owner from consuming a
        // verified integrity-fence request until a later operating-system
        // signal. Polling remains bounded and preserves first/second signal
        // handling below.
        let iteration = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _applied_integrity_fence = process.apply_pending_integrity_fence();
            let mut termination_count = 0_u8;
            for signal in signals.pending() {
                if matches!(signal, SIGINT | SIGTERM) {
                    termination_count = termination_count.saturating_add(1);
                    continue;
                }
                if signal == SIGHUP {
                    match reload.resolve() {
                        Ok(candidate) => {
                            let outcome = process.reload_configuration(candidate);
                            if let Some(category) = reload_rejection_category(&outcome) {
                                let delivery = report_runtime_diagnostic(std::format_args!(
                                    "positron: configuration reload rejected category={category}"
                                ));
                                match delivery {
                                    RuntimeDiagnosticDelivery::Delivered
                                    | RuntimeDiagnosticDelivery::Unavailable => {},
                                }
                            }
                        },
                        Err(()) => {
                            if process.record_invalid_configuration_reload().is_err() {
                                let delivery = report_runtime_diagnostic(std::format_args!(
                                    "positron: configuration reload audit unavailable"
                                ));
                                match delivery {
                                    RuntimeDiagnosticDelivery::Delivered
                                    | RuntimeDiagnosticDelivery::Unavailable => {},
                                }
                            }
                            let delivery = report_runtime_diagnostic(std::format_args!(
                                "positron: configuration reload rejected category=source_rejected"
                            ));
                            match delivery {
                                RuntimeDiagnosticDelivery::Delivered
                                | RuntimeDiagnosticDelivery::Unavailable => {},
                            }
                        },
                    }
                }
            }
            termination_count
        }));
        match iteration {
            Ok(termination_count) if termination_count > 0 => break termination_count > 1,
            Ok(_) => std::thread::sleep(Duration::from_millis(5)),
            Err(_) => {
                return Ok(preserve_runtime_outcome(
                    capture_runtime_failure(&process, "serving", "runtime_serving_loop_panicked"),
                    process.shutdown(ShutdownTrigger::DeadlineExpired),
                ));
            },
        }
    };
    let mut draining = process.begin_shutdown();
    if second_termination_seen {
        return Ok(draining.finish(ShutdownTrigger::SecondSignal));
    }
    let deadline_at = Instant::now() + deadline;
    loop {
        if pending_termination_trigger(&mut signals).is_some() {
            return Ok(draining.finish(ShutdownTrigger::SecondSignal));
        }
        if Instant::now() >= deadline_at {
            return Ok(draining.finish(ShutdownTrigger::DeadlineExpired));
        }
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| draining.poll())) {
            Err(_) => {
                return Ok(preserve_runtime_outcome(
                    capture_draining_runtime_failure(
                        &draining,
                        "draining",
                        "runtime_poll_panicked",
                    ),
                    draining.finish(ShutdownTrigger::DeadlineExpired),
                ));
            },
            Ok(Ok(true)) => return Ok(draining.finish(ShutdownTrigger::FirstSignal)),
            Ok(Ok(false)) => std::thread::yield_now(),
            Ok(Err(failure)) => {
                let finding_code = if failure == positron_runtime::TaskFailure::JoinPanicked {
                    "joined_task_panicked"
                } else {
                    "runtime_drain_failed"
                };
                return Ok(preserve_runtime_outcome(
                    capture_draining_runtime_failure(&draining, "draining", finding_code),
                    draining.finish(ShutdownTrigger::DeadlineExpired),
                ));
            },
        }
    }
}

fn capture_runtime_failure(
    process: &positron_runtime::RunningProcess,
    phase: &'static str,
    finding_code: &'static str,
) -> RuntimeDiagnosticDelivery {
    if process
        .persist_crash_record(phase, finding_code, "runtime")
        .is_err()
    {
        return report_runtime_diagnostic(std::format_args!(
            "positron: unable to persist sanitized runtime crash record"
        ));
    }
    RuntimeDiagnosticDelivery::Delivered
}

fn capture_draining_runtime_failure(
    process: &positron_runtime::DrainingProcess,
    phase: &'static str,
    finding_code: &'static str,
) -> RuntimeDiagnosticDelivery {
    if process
        .persist_crash_record(phase, finding_code, "runtime")
        .is_err()
    {
        return report_runtime_diagnostic(std::format_args!(
            "positron: unable to persist sanitized runtime crash record"
        ));
    }
    RuntimeDiagnosticDelivery::Delivered
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeDiagnosticDelivery {
    Delivered,
    Unavailable,
}

fn preserve_runtime_outcome(
    delivery: RuntimeDiagnosticDelivery,
    primary: ExitOutcome,
) -> ExitOutcome {
    match delivery {
        RuntimeDiagnosticDelivery::Delivered | RuntimeDiagnosticDelivery::Unavailable => primary,
    }
}

fn report_runtime_diagnostic(message: std::fmt::Arguments<'_>) -> RuntimeDiagnosticDelivery {
    let mut stderr = std::io::stderr().lock();
    report_runtime_diagnostic_to(&mut stderr, message)
}

fn report_runtime_diagnostic_to(
    sink: &mut impl std::io::Write,
    message: std::fmt::Arguments<'_>,
) -> RuntimeDiagnosticDelivery {
    match writeln!(sink, "{message}") {
        Ok(()) => RuntimeDiagnosticDelivery::Delivered,
        Err(_) => RuntimeDiagnosticDelivery::Unavailable,
    }
}

fn reload_rejection_category(
    outcome: &Result<
        positron_runtime::ConfigurationReloadOutcome,
        positron_runtime::ConfigurationRuntimeFailure,
    >,
) -> Option<&'static str> {
    use positron_runtime::{ConfigurationReloadOutcome, ConfigurationRuntimeFailure};

    match outcome {
        Ok(
            ConfigurationReloadOutcome::NoChange { .. }
            | ConfigurationReloadOutcome::PublishedLive { .. }
            | ConfigurationReloadOutcome::PendingRestart { .. },
        ) => None,
        Ok(ConfigurationReloadOutcome::RejectedImmutable { .. })
        | Err(ConfigurationRuntimeFailure::ImmutableConfiguration) => {
            Some("immutable_configuration")
        },
        Ok(ConfigurationReloadOutcome::RequiresDrain { .. }) => Some("requires_drain"),
        Err(ConfigurationRuntimeFailure::Unavailable) => Some("runtime_unavailable"),
        Err(ConfigurationRuntimeFailure::PublicationUnavailable) => Some("publication_unavailable"),
        Err(ConfigurationRuntimeFailure::ListenerUnavailable) => Some("listener_unavailable"),
    }
}

#[derive(Debug)]
struct Arguments {
    config: Option<PathBuf>,
    overrides: Vec<(String, String)>,
    initialization: InitializationMode,
}

impl Arguments {
    fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Self, LaunchFailure> {
        let mut arguments = arguments.into_iter();
        if arguments.next().as_deref() != Some("serve") {
            return Err(LaunchFailure::Usage);
        }
        let mut config = None;
        let mut overrides = Vec::new();
        let mut initialization = InitializationMode::ExistingOnly;
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--init-if-empty" => initialization = InitializationMode::InitializeIfEmpty,
                "--config" if config.is_none() => {
                    config = Some(PathBuf::from(arguments.next().ok_or(LaunchFailure::Usage)?));
                },
                "--set" => {
                    let value = arguments.next().ok_or(LaunchFailure::Usage)?;
                    let (key, value) = value.split_once('=').ok_or(LaunchFailure::Usage)?;
                    overrides.push((key.to_owned(), value.to_owned()));
                },
                _ => return Err(LaunchFailure::Usage),
            }
        }
        Ok(Self {
            config,
            overrides,
            initialization,
        })
    }
}

#[derive(Clone, Copy, Debug)]
enum LaunchFailure {
    Usage,
    Configuration,
    Startup(ExitOutcome),
    Signal,
}

impl LaunchFailure {
    const fn code(self) -> u8 {
        match self {
            Self::Usage | Self::Configuration => EXIT_CONFIGURATION,
            Self::Startup(outcome) => match outcome {
                ExitOutcome::InvalidConfiguration => EXIT_CONFIGURATION,
                ExitOutcome::Forced => EXIT_FORCED,
                ExitOutcome::Graceful
                | ExitOutcome::StartupUnavailable(_)
                | ExitOutcome::ListenerUnavailable(_)
                | ExitOutcome::TaskUnavailable(_)
                | ExitOutcome::InternalCleanupFailure(_)
                | ExitOutcome::Fenced => EXIT_STARTUP,
            },
            Self::Signal => EXIT_STARTUP,
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::Usage => "invalid command line",
            Self::Configuration => "configuration rejected",
            Self::Startup(_) => "startup failed",
            Self::Signal => "signal handling unavailable",
        }
    }
}

fn exit_code(outcome: ExitOutcome) -> ExitCode {
    match outcome {
        ExitOutcome::Graceful => ExitCode::from(EXIT_OK),
        ExitOutcome::Forced => ExitCode::from(EXIT_FORCED),
        ExitOutcome::InvalidConfiguration => ExitCode::from(EXIT_CONFIGURATION),
        ExitOutcome::StartupUnavailable(_)
        | ExitOutcome::ListenerUnavailable(_)
        | ExitOutcome::TaskUnavailable(_)
        | ExitOutcome::InternalCleanupFailure(_)
        | ExitOutcome::Fenced => ExitCode::from(EXIT_STARTUP),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, SystemTime};

    use super::{
        ExitOutcome, LaunchFailure, NativeRecovery, RecoveryAttemptHost, RecoveryDecision,
        ReloadInputs, RuntimeDiagnosticDelivery, ShutdownTrigger, exit_code,
        pending_termination_trigger, preserve_runtime_outcome, reload_rejection_category,
        report_runtime_diagnostic_to, wait_for_shutdown,
    };
    use positron_runtime::{
        ApplicationRuntime, BootstrapFailureCode, BootstrapPaths, BoundEndpoint, BoundListener,
        ConfigurationReloadOutcome, ConfigurationRuntimeFailure, HostInputs, InitializationMode,
        InstanceBootstrap, ListenerFactory, ListenerFailure, ListenerRequest, ListenerRole,
        RecoveryAttempt, RegisteredTask, RunningTask, ServeConfiguration, TaskCancellation,
        TaskFailure, TaskJoinOutcome, TaskRegistrar, TaskRole,
    };
    use signal_hook::iterator::Signals;

    #[test]
    fn serve_arguments_require_one_leading_command() {
        for arguments in [
            Vec::new(),
            vec!["--init-if-empty"],
            vec!["serve", "serve"],
            vec!["--init-if-empty", "serve"],
            vec!["serve", "--init-if-empty", "serve"],
        ] {
            assert!(
                matches!(
                    super::Arguments::parse(arguments.iter().map(|value| (*value).to_owned())),
                    Err(LaunchFailure::Usage)
                ),
                "invalid serve invocation was accepted: {arguments:?}"
            );
        }
        assert!(super::Arguments::parse(["serve".to_owned()]).is_ok());
        assert!(
            super::Arguments::parse(
                [
                    "serve",
                    "--init-if-empty",
                    "--config",
                    "positron.toml",
                    "--set",
                    "runtime.drain_deadline_seconds=10"
                ]
                .into_iter()
                .map(str::to_owned)
            )
            .is_ok()
        );
    }

    #[test]
    fn every_typed_runtime_outcome_has_a_stable_native_exit() {
        for outcome in [
            ExitOutcome::Graceful,
            ExitOutcome::Forced,
            ExitOutcome::InvalidConfiguration,
            ExitOutcome::StartupUnavailable(BootstrapFailureCode::StorageUnavailable),
            ExitOutcome::ListenerUnavailable(ListenerRole::Api),
            ExitOutcome::TaskUnavailable(TaskRole::Api),
            ExitOutcome::InternalCleanupFailure(positron_runtime::CleanupFailure::none()),
            ExitOutcome::Fenced,
        ] {
            let code = exit_code(outcome);
            let launch = LaunchFailure::Startup(outcome);
            assert_eq!(launch.message(), "startup failed");
            assert!(launch.code() > 0);
            if outcome == ExitOutcome::Graceful {
                assert_eq!(code, std::process::ExitCode::SUCCESS);
            }
        }
        assert_eq!(LaunchFailure::Signal.code(), 3);
        assert_eq!(
            LaunchFailure::Signal.message(),
            "signal handling unavailable"
        );
    }

    #[test]
    fn reload_rejection_categories_are_static_and_typed() {
        let no_change = Ok(ConfigurationReloadOutcome::NoChange { generation: 1 });
        assert_eq!(reload_rejection_category(&no_change), None);

        for (outcome, expected) in [
            (
                Err(ConfigurationRuntimeFailure::Unavailable),
                "runtime_unavailable",
            ),
            (
                Err(ConfigurationRuntimeFailure::PublicationUnavailable),
                "publication_unavailable",
            ),
            (
                Err(ConfigurationRuntimeFailure::ListenerUnavailable),
                "listener_unavailable",
            ),
            (
                Err(ConfigurationRuntimeFailure::ImmutableConfiguration),
                "immutable_configuration",
            ),
        ] {
            assert_eq!(reload_rejection_category(&outcome), Some(expected));
        }
    }

    #[test]
    fn unavailable_runtime_diagnostic_preserves_the_forced_outcome() {
        struct ClosedDiagnosticSink;

        impl std::io::Write for ClosedDiagnosticSink {
            fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let message = "positron: unable to persist sanitized runtime crash record";
        let mut rendered = Vec::new();
        assert_eq!(
            report_runtime_diagnostic_to(&mut rendered, format_args!("{message}")),
            RuntimeDiagnosticDelivery::Delivered
        );
        assert_eq!(
            String::from_utf8(rendered).expect("UTF-8 diagnostic"),
            format!("{message}\n")
        );

        let mut sink = ClosedDiagnosticSink;
        let delivery = report_runtime_diagnostic_to(&mut sink, format_args!("{message}"));
        assert_eq!(delivery, RuntimeDiagnosticDelivery::Unavailable);
        assert_eq!(
            preserve_runtime_outcome(delivery, ExitOutcome::Forced),
            ExitOutcome::Forced
        );
    }

    #[test]
    fn native_recovery_retries_then_exhausts_at_the_attempt_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        let recovery = NativeRecovery::new(Signals::new(std::iter::empty::<i32>())?);

        assert_eq!(
            recovery.after_failure(RecoveryAttempt::for_test(1)),
            RecoveryDecision::Retry
        );
        assert_eq!(
            recovery.after_failure(RecoveryAttempt::for_test(32)),
            RecoveryDecision::Exhausted
        );
        assert!(recovery.into_signals().is_ok());
        Ok(())
    }

    #[test]
    fn native_recovery_preserves_typed_attempt_metadata() -> Result<(), Box<dyn std::error::Error>>
    {
        let recovery = NativeRecovery::new(Signals::new(std::iter::empty::<i32>())?);
        let attempt = RecoveryAttempt::for_test(2);
        assert_eq!(attempt.failure(), BootstrapFailureCode::StorageUnavailable);
        assert!(!attempt.ownership_held());
        assert_eq!(recovery.after_failure(attempt), RecoveryDecision::Retry);
        Ok(())
    }

    #[test]
    fn pending_native_termination_signal_interrupts_recovery_backoff()
    -> Result<(), Box<dyn std::error::Error>> {
        let recovery = NativeRecovery::new(Signals::new([signal_hook::consts::signal::SIGTERM])?);
        signal_hook::low_level::raise(signal_hook::consts::signal::SIGTERM)?;

        assert_eq!(
            recovery.after_failure(RecoveryAttempt::for_test(1)),
            RecoveryDecision::Terminate(ShutdownTrigger::FirstSignal)
        );
        Ok(())
    }

    #[test]
    fn native_recovery_keeps_sighup_out_of_termination_handling()
    -> Result<(), Box<dyn std::error::Error>> {
        let recovery = NativeRecovery::new(Signals::new([signal_hook::consts::signal::SIGHUP])?);
        signal_hook::low_level::raise(signal_hook::consts::signal::SIGHUP)?;

        assert_eq!(
            recovery.after_failure(RecoveryAttempt::for_test(1)),
            RecoveryDecision::Retry
        );
        let mut signals = recovery.into_signals().map_err(|_| "signals unavailable")?;
        assert_eq!(signals.pending().next(), None);
        Ok(())
    }

    #[test]
    fn native_drain_keeps_sighup_out_of_forced_exit_handling()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut signals = Signals::new([signal_hook::consts::signal::SIGHUP])?;
        signal_hook::low_level::raise(signal_hook::consts::signal::SIGHUP)?;

        assert_eq!(pending_termination_trigger(&mut signals), None);
        Ok(())
    }

    #[test]
    fn two_pending_native_termination_signals_force_the_drain()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut signals = Signals::new([
            signal_hook::consts::signal::SIGINT,
            signal_hook::consts::signal::SIGTERM,
        ])?;
        signal_hook::low_level::raise(signal_hook::consts::signal::SIGTERM)?;
        signal_hook::low_level::raise(signal_hook::consts::signal::SIGINT)?;

        assert_eq!(
            pending_termination_trigger(&mut signals),
            Some(ShutdownTrigger::SecondSignal)
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn owner_loop_turns_real_first_signal_into_drain_and_second_into_forced_exit()
    -> Result<(), Box<dyn std::error::Error>> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "positron-owner-loop-signal-{}-{nonce}",
            std::process::id()
        ));
        let data = root.join("data");
        let secrets = root.join("secrets");
        std::fs::create_dir_all(&data)?;
        std::fs::create_dir_all(&secrets)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700))?;
        let draining = Arc::new(AtomicBool::new(false));
        let host = SignalHost {
            draining: Arc::clone(&draining),
        };
        let paths = BootstrapPaths::new(
            &data,
            &secrets,
            positron_kernel::MountQualification::LocalHost,
        )?;
        let process = ApplicationRuntime::start(
            ServeConfiguration::new(paths.clone(), InitializationMode::InitializeIfEmpty),
            HostInputs::new(&host, &host),
        )
        .map_err(|failure| format!("start owner loop: {failure:?}"))?;
        let signals = Signals::new([
            signal_hook::consts::signal::SIGINT,
            signal_hook::consts::signal::SIGTERM,
        ])?;
        let sender = std::thread::spawn(move || -> Result<(), String> {
            std::thread::sleep(Duration::from_millis(20));
            signal_hook::low_level::raise(signal_hook::consts::signal::SIGTERM)
                .map_err(|error| error.to_string())?;
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            while !draining.load(Ordering::Acquire) {
                if std::time::Instant::now() >= deadline {
                    return Err("first signal did not enter draining".to_owned());
                }
                std::thread::yield_now();
            }
            signal_hook::low_level::raise(signal_hook::consts::signal::SIGINT)
                .map_err(|error| error.to_string())
        });
        let outcome = wait_for_shutdown(
            process,
            signals,
            Duration::from_secs(1),
            &ReloadInputs {
                config: None,
                environment: Vec::new(),
                overrides: Vec::new(),
            },
            data.clone(),
        )
        .map_err(|failure| format!("owner loop: {}", failure.message()))?;
        sender
            .join()
            .map_err(|_| "signal sender panicked")?
            .map_err(|error| format!("signal sender: {error}"))?;
        assert_eq!(outcome, ExitOutcome::Forced);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn owner_loop_persists_a_joined_task_panic_without_its_payload()
    -> Result<(), Box<dyn std::error::Error>> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "positron-owner-joined-panic-{}-{nonce}",
            std::process::id()
        ));
        let data = root.join("data");
        let secrets = root.join("secrets");
        std::fs::create_dir_all(&data)?;
        std::fs::create_dir_all(&secrets)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700))?;
        let host = JoinedPanicHost;
        let paths = BootstrapPaths::new(
            &data,
            &secrets,
            positron_kernel::MountQualification::LocalHost,
        )?;
        let process = ApplicationRuntime::start(
            ServeConfiguration::new(paths.clone(), InitializationMode::InitializeIfEmpty),
            HostInputs::new(&host, &host),
        )
        .map_err(|failure| format!("start owner loop: {failure:?}"))?;
        let signals = Signals::new([signal_hook::consts::signal::SIGTERM])?;
        signal_hook::low_level::raise(signal_hook::consts::signal::SIGTERM)?;
        let outcome = wait_for_shutdown(
            process,
            signals,
            Duration::from_secs(1),
            &ReloadInputs {
                config: None,
                environment: Vec::new(),
                overrides: Vec::new(),
            },
            data.clone(),
        )
        .map_err(|failure| format!("owner loop: {}", failure.message()))?;
        assert_ne!(outcome, ExitOutcome::Graceful);
        let records = std::fs::read_dir(data.join("diagnostics/crash-records"))?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(records.len(), 1, "joined panic record missing");
        let rendered = InstanceBootstrap::reopen(&paths)?
            .crash_records()?
            .read_recent(Duration::from_secs(60), 1, 384, SystemTime::now())
            .map_err(|failure| format!("authenticated crash records: {failure:?}"))?
            .render();
        assert!(rendered.contains("phase=draining"));
        assert!(rendered.contains("finding_code=joined_task_panicked"));
        let catalog_generation = rendered
            .lines()
            .find_map(|line| line.strip_prefix("catalog_generation="))
            .ok_or("catalog generation missing")?
            .parse::<u64>()?;
        assert!(
            catalog_generation > 0,
            "owner must capture its live catalog generation"
        );
        assert!(rendered.contains("backtrace_identity="));
        assert!(!rendered.contains("owner-loop-private-panic-canary"));
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn serving_owner_persists_a_sanitized_panic_only_after_it_owns_the_catalog()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "positron-serving-owner-panic-{}-{nonce}",
            std::process::id()
        ));
        let data = root.join("data");
        let secrets = root.join("secrets");
        std::fs::create_dir_all(&data)?;
        std::fs::create_dir_all(&secrets)?;
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700))?;
        let host = ServingPanicHost {
            panic_once: Arc::new(AtomicBool::new(true)),
        };
        let paths = BootstrapPaths::new(
            &data,
            &secrets,
            positron_kernel::MountQualification::LocalHost,
        )?;
        let process = ApplicationRuntime::start(
            ServeConfiguration::new(paths.clone(), InitializationMode::InitializeIfEmpty),
            HostInputs::new(&host, &host),
        )
        .map_err(|failure| format!("start serving owner: {failure:?}"))?;
        assert!(
            !data.join("diagnostics/crash-records").exists(),
            "no crash record may be written before the serving owner observes a failure"
        );
        let services = process.services().ok_or("serving services")?;
        services.request_integrity_fence();
        drop(services);

        let outcome = wait_for_shutdown(
            process,
            Signals::new(std::iter::empty::<i32>())?,
            Duration::from_secs(1),
            &ReloadInputs {
                config: None,
                environment: Vec::new(),
                overrides: Vec::new(),
            },
            data.clone(),
        )
        .map_err(|failure| format!("serving owner: {}", failure.message()))?;
        assert_eq!(outcome, ExitOutcome::Forced);
        let records = std::fs::read_dir(data.join("diagnostics/crash-records"))?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(
            std::fs::metadata(record.path())?.permissions().mode() & 0o777,
            0o600
        );
        let rendered = InstanceBootstrap::reopen(&paths)?
            .crash_records()?
            .read_recent(Duration::from_secs(60), 1, 384, SystemTime::now())
            .map_err(|failure| format!("authenticated crash records: {failure:?}"))?
            .render();
        assert!(rendered.contains("phase=serving"));
        assert!(rendered.contains("finding_code=runtime_serving_loop_panicked"));
        assert!(
            rendered
                .lines()
                .find_map(|line| line.strip_prefix("catalog_generation="))
                .is_some_and(|generation| generation.parse::<u64>().is_ok_and(|value| value > 0)),
            "the serving owner must capture its closed catalog-generation snapshot: {rendered}"
        );
        assert!(rendered.contains("backtrace_identity="));
        assert!(!rendered.contains("serving-owner-private-panic-canary"));
        assert!(!rendered.contains("panic_payload"));
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    struct SignalHost {
        draining: Arc<AtomicBool>,
    }

    #[cfg(unix)]
    struct JoinedPanicHost;

    #[cfg(unix)]
    struct ServingPanicHost {
        panic_once: Arc<AtomicBool>,
    }

    #[cfg(unix)]
    impl ListenerFactory for ServingPanicHost {
        fn bind(
            &self,
            request: ListenerRequest,
        ) -> Result<Box<dyn BoundListener>, ListenerFailure> {
            let endpoint = if request.role() == ListenerRole::Control {
                BoundEndpoint::control(PathBuf::from("/tmp/positron-serving-owner-panic.sock"))?
            } else {
                BoundEndpoint::tcp(
                    request.role(),
                    "127.0.0.1:42502"
                        .parse()
                        .map_err(|_| ListenerFailure::BindUnavailable)?,
                )?
            };
            Ok(Box::new(ServingPanicListener {
                endpoint,
                panic_once: Arc::clone(&self.panic_once),
            }))
        }
    }

    #[cfg(unix)]
    impl TaskRegistrar for ServingPanicHost {
        fn register(&self, _: TaskRole) -> Result<Box<dyn RegisteredTask>, TaskFailure> {
            Ok(Box::new(ServingPanicRegisteredTask))
        }
    }

    #[cfg(unix)]
    struct ServingPanicListener {
        endpoint: BoundEndpoint,
        panic_once: Arc<AtomicBool>,
    }

    #[cfg(unix)]
    impl BoundListener for ServingPanicListener {
        fn endpoint(&self) -> &BoundEndpoint {
            &self.endpoint
        }

        fn close(&mut self) -> Result<(), ListenerFailure> {
            if self.endpoint.role().is_data() && self.panic_once.swap(false, Ordering::AcqRel) {
                panic!("serving-owner-private-panic-canary");
            }
            Ok(())
        }
    }

    #[cfg(unix)]
    struct ServingPanicRegisteredTask;

    #[cfg(unix)]
    impl RegisteredTask for ServingPanicRegisteredTask {
        fn spawn(
            self: Box<Self>,
            _: TaskCancellation,
            _: positron_runtime::HealthState,
            _: Option<positron_runtime::ServiceHandle>,
        ) -> Result<Box<dyn RunningTask>, TaskFailure> {
            Ok(Box::new(ServingPanicRunningTask))
        }
    }

    #[cfg(unix)]
    struct ServingPanicRunningTask;

    #[cfg(unix)]
    impl RunningTask for ServingPanicRunningTask {
        fn poll_join(&mut self) -> Result<Option<TaskJoinOutcome>, TaskFailure> {
            Ok(Some(TaskJoinOutcome::Joined))
        }

        fn join_within(&mut self, _: Duration) -> Result<TaskJoinOutcome, TaskFailure> {
            Ok(TaskJoinOutcome::Joined)
        }

        fn abort(&mut self) -> Result<(), TaskFailure> {
            Ok(())
        }
    }

    #[cfg(unix)]
    impl ListenerFactory for JoinedPanicHost {
        fn bind(
            &self,
            request: ListenerRequest,
        ) -> Result<Box<dyn BoundListener>, ListenerFailure> {
            let endpoint = if request.role() == ListenerRole::Control {
                BoundEndpoint::control(PathBuf::from("/tmp/positron-owner-joined-panic.sock"))?
            } else {
                BoundEndpoint::tcp(
                    request.role(),
                    "127.0.0.1:42501"
                        .parse()
                        .map_err(|_| ListenerFailure::BindUnavailable)?,
                )?
            };
            Ok(Box::new(SignalListener(endpoint)))
        }
    }

    #[cfg(unix)]
    impl TaskRegistrar for JoinedPanicHost {
        fn register(&self, _: TaskRole) -> Result<Box<dyn RegisteredTask>, TaskFailure> {
            Ok(Box::new(JoinedPanicRegisteredTask))
        }
    }

    #[cfg(unix)]
    struct JoinedPanicRegisteredTask;

    #[cfg(unix)]
    impl RegisteredTask for JoinedPanicRegisteredTask {
        fn spawn(
            self: Box<Self>,
            _: TaskCancellation,
            _: positron_runtime::HealthState,
            _: Option<positron_runtime::ServiceHandle>,
        ) -> Result<Box<dyn RunningTask>, TaskFailure> {
            Ok(Box::new(JoinedPanicRunningTask {
                handle: Some(std::thread::spawn(|| {
                    panic!("owner-loop-private-panic-canary");
                })),
            }))
        }
    }

    #[cfg(unix)]
    struct JoinedPanicRunningTask {
        handle: Option<std::thread::JoinHandle<()>>,
    }

    #[cfg(unix)]
    impl RunningTask for JoinedPanicRunningTask {
        fn poll_join(&mut self) -> Result<Option<TaskJoinOutcome>, TaskFailure> {
            let Some(handle) = self.handle.as_ref() else {
                return Ok(Some(TaskJoinOutcome::Joined));
            };
            if !handle.is_finished() {
                return Ok(None);
            }
            let handle = self.handle.take().ok_or(TaskFailure::JoinUnavailable)?;
            handle.join().map_err(|_| TaskFailure::JoinPanicked)?;
            Ok(Some(TaskJoinOutcome::Joined))
        }

        fn join_within(&mut self, _: Duration) -> Result<TaskJoinOutcome, TaskFailure> {
            let Some(handle) = self.handle.take() else {
                return Ok(TaskJoinOutcome::Joined);
            };
            handle.join().map_err(|_| TaskFailure::JoinPanicked)?;
            Ok(TaskJoinOutcome::Joined)
        }

        fn abort(&mut self) -> Result<(), TaskFailure> {
            if let Some(handle) = self.handle.take() {
                handle.join().map_err(|_| TaskFailure::JoinPanicked)?;
            }
            Ok(())
        }
    }

    #[cfg(unix)]
    impl ListenerFactory for SignalHost {
        fn bind(
            &self,
            request: ListenerRequest,
        ) -> Result<Box<dyn BoundListener>, ListenerFailure> {
            let endpoint = if request.role() == ListenerRole::Control {
                BoundEndpoint::control(PathBuf::from("/tmp/positron-owner-loop-signal.sock"))?
            } else {
                BoundEndpoint::tcp(
                    request.role(),
                    "127.0.0.1:42498"
                        .parse()
                        .map_err(|_| ListenerFailure::BindUnavailable)?,
                )?
            };
            Ok(Box::new(SignalListener(endpoint)))
        }
    }

    #[cfg(unix)]
    struct SignalListener(BoundEndpoint);

    #[cfg(unix)]
    impl BoundListener for SignalListener {
        fn endpoint(&self) -> &BoundEndpoint {
            &self.0
        }
    }

    #[cfg(unix)]
    impl TaskRegistrar for SignalHost {
        fn register(&self, _: TaskRole) -> Result<Box<dyn RegisteredTask>, TaskFailure> {
            Ok(Box::new(SignalRegisteredTask {
                draining: Arc::clone(&self.draining),
            }))
        }
    }

    #[cfg(unix)]
    struct SignalRegisteredTask {
        draining: Arc<AtomicBool>,
    }

    #[cfg(unix)]
    impl RegisteredTask for SignalRegisteredTask {
        fn spawn(
            self: Box<Self>,
            _: TaskCancellation,
            health: positron_runtime::HealthState,
            _: Option<positron_runtime::ServiceHandle>,
        ) -> Result<Box<dyn RunningTask>, TaskFailure> {
            Ok(Box::new(SignalRunningTask {
                health,
                draining: self.draining,
            }))
        }
    }

    #[cfg(unix)]
    struct SignalRunningTask {
        health: positron_runtime::HealthState,
        draining: Arc<AtomicBool>,
    }

    #[cfg(unix)]
    impl RunningTask for SignalRunningTask {
        fn poll_join(&mut self) -> Result<Option<TaskJoinOutcome>, TaskFailure> {
            if self.health.phase() == positron_runtime::ProcessPhase::Draining {
                self.draining.store(true, Ordering::Release);
            }
            Ok(None)
        }

        fn join_within(&mut self, _: Duration) -> Result<TaskJoinOutcome, TaskFailure> {
            Ok(TaskJoinOutcome::DeadlineExpired)
        }

        fn abort(&mut self) -> Result<(), TaskFailure> {
            Ok(())
        }
    }
}
