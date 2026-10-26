//! One native invocation owns one bounded, same-executable output helper.
use std::io::{self, Read, Write};
use std::sync::{
    Mutex, OnceLock,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::{
    os::{fd::OwnedFd, unix::net::UnixStream},
    process::{Child, Command, Stdio},
};

#[doc(hidden)]
pub const OPERATIONAL_HELPER_ARGUMENT: &str = "--positron-internal-operational-output";
const RECORD_BYTES: usize = 510;
const WAIT: Duration = Duration::from_secs(1);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static DEADLINE: AtomicU64 = AtomicU64::new(u64::MAX);
static EPOCH: OnceLock<Instant> = OnceLock::new();
static OUTPUT: OnceLock<Mutex<Output>> = OnceLock::new();

#[derive(Default)]
struct Output {
    attempted: bool,
    #[cfg(unix)]
    session: Option<Session>,
}

/// The native composition root keeps this owner until all startup/exit paths finish.
#[doc(hidden)]
pub struct NativeOperationalOutput {
    finished: bool,
}
impl NativeOperationalOutput {
    pub fn begin() -> io::Result<Self> {
        ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| io::Error::other("native output already owned"))?;
        EPOCH.get_or_init(Instant::now);
        Ok(Self { finished: false })
    }
    pub fn finish(mut self) -> io::Result<()> {
        self.finished = true;
        close()
    }
}
impl Drop for NativeOperationalOutput {
    fn drop(&mut self) {
        if !self.finished && close().is_err() {
            std::process::exit(4);
        }
    }
}

pub(crate) fn set_deadline(deadline: Instant) {
    if ACTIVE.load(Ordering::Acquire) {
        let duration = deadline.saturating_duration_since(*EPOCH.get_or_init(Instant::now));
        DEADLINE.store(
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX),
            Ordering::Release,
        );
    }
}
fn expired(started: Instant) -> bool {
    started.elapsed() >= WAIT
        || EPOCH.get_or_init(Instant::now).elapsed().as_nanos()
            >= u128::from(DEADLINE.load(Ordering::Acquire))
}
fn unavailable() -> io::Error {
    io::Error::other("operational output unavailable")
}

pub(crate) fn write(bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > RECORD_BYTES || !ACTIVE.load(Ordering::Acquire) {
        return Err(unavailable());
    }
    let mut output = OUTPUT
        .get_or_init(|| Mutex::new(Output::default()))
        .try_lock()
        .map_err(|_| unavailable())?;
    #[cfg(unix)]
    {
        if !output.attempted {
            output.attempted = true;
            output.session = Some(Session::spawn(&std::env::current_exe()?)?);
        }
        let session = output.session.as_mut().ok_or_else(unavailable)?;
        let result = session.record(bytes);
        if result.is_err() {
            finish_session(&mut output.session, false)?;
        }
        result
    }
    #[cfg(not(unix))]
    {
        output.attempted = true;
        Err(unavailable())
    }
}

pub(crate) fn close() -> io::Result<()> {
    if !ACTIVE.load(Ordering::Acquire) {
        return Ok(());
    }
    let Some(output) = OUTPUT.get() else {
        return Ok(());
    };
    let started = Instant::now();
    loop {
        if let Ok(mut output) = output.try_lock() {
            #[cfg(unix)]
            return finish_session(&mut output.session, true);
            #[cfg(not(unix))]
            return Ok(());
        }
        if expired(started) {
            std::process::exit(4);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(unix)]
struct Session {
    socket: UnixStream,
    child: Child,
}
#[cfg(unix)]
impl Session {
    fn spawn(executable: &std::path::Path) -> io::Result<Self> {
        let (parent, child) = UnixStream::pair()?;
        parent.set_nonblocking(true)?;
        let input: OwnedFd = child.try_clone()?.into();
        let output: OwnedFd = child.into();
        let child = Command::new(executable)
            .arg(OPERATIONAL_HELPER_ARGUMENT)
            .env_clear()
            .stdin(Stdio::from(input))
            .stdout(Stdio::from(output))
            .stderr(Stdio::inherit())
            .spawn()?;
        Ok(Self {
            socket: parent,
            child,
        })
    }
    fn exchange(&mut self, bytes: &[u8]) -> io::Result<()> {
        let length = u16::try_from(bytes.len()).map_err(|_| unavailable())?;
        let mut frame = [0_u8; RECORD_BYTES + 2];
        let header = frame.get_mut(..2).ok_or_else(unavailable)?;
        header.copy_from_slice(&length.to_be_bytes());
        frame
            .get_mut(2..bytes.len() + 2)
            .ok_or_else(unavailable)?
            .copy_from_slice(bytes);
        let mut remaining = frame.get(..bytes.len() + 2).ok_or_else(unavailable)?;
        let started = Instant::now();
        while !remaining.is_empty() {
            if expired(started) {
                return Err(unavailable());
            }
            match self.socket.write(remaining) {
                Ok(0) => return Err(unavailable()),
                Ok(count) => remaining = remaining.get(count..).ok_or_else(unavailable)?,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    std::thread::sleep(Duration::from_millis(1))
                },
                Err(error) => return Err(error),
            }
        }
        let mut ack = [0_u8; 1];
        loop {
            if expired(started) {
                return Err(unavailable());
            }
            match self.socket.read(&mut ack) {
                Ok(1) if ack == [b'A'] => return Ok(()),
                Ok(_) => return Err(unavailable()),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    std::thread::sleep(Duration::from_millis(1))
                },
                Err(error) => return Err(error),
            }
        }
    }
    fn record(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.exchange(bytes)
    }
}
#[cfg(unix)]
fn finish_session(session: &mut Option<Session>, graceful: bool) -> io::Result<()> {
    let Some(mut session) = session.take() else {
        return Ok(());
    };
    let normal = graceful && session.exchange(&[]).is_ok();
    // Consume the sole parent endpoint before any termination/reap decision.
    // No failed record can accidentally keep the death watcher alive.
    let Session { socket, mut child } = session;
    drop(socket);
    if !normal {
        // EOF already wakes the independent reader; kill is a second bounded request.
        if child.kill().is_err() && child.try_wait().is_ok_and(|status| status.is_some()) {
            return if graceful { Err(unavailable()) } else { Ok(()) };
        }
    }
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if graceful && (!normal || !status.success()) {
                    Err(unavailable())
                } else {
                    Ok(())
                };
            },
            Ok(None) => {},
            Err(_) => std::process::exit(4),
        }
        if expired(started) {
            // Hard exit closes IPC; no graceful marker or continuing detached owner.
            std::process::exit(4);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

mod helper;
/// Internal executable mode, before CLI/configuration dispatch.
#[doc(hidden)]
pub fn run_operational_output_helper() -> std::process::ExitCode {
    helper::run()
}

#[cfg(fuzzing)]
pub(crate) fn fuzz_frame(bytes: &[u8]) -> Option<usize> {
    helper::decode_frame(bytes)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn helper_spawn_failure_is_an_explicit_os_error_without_a_child() {
        let failure =
            match Session::spawn(std::path::Path::new("/positron-missing-output-executable")) {
                Ok(mut session) => {
                    session.child.kill().unwrap();
                    session.child.wait().unwrap();
                    panic!("missing executable spawned");
                },
                Err(failure) => failure,
            };
        assert_eq!(failure.kind(), io::ErrorKind::NotFound);
    }
}
