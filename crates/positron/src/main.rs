//! Native Positron composition root.

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    if std::env::args().nth(1).as_deref() == Some(positron_runtime::OPERATIONAL_HELPER_ARGUMENT) {
        if std::env::args().count() != 2 {
            return std::process::ExitCode::from(70);
        }
        return positron_runtime::run_operational_output_helper();
    }
    positron::run_native(std::env::args().skip(1), std::env::vars())
}
