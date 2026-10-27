//! Closed helper dispatch, inherited-descriptor guard, and fixed record reader.
use super::{RECORD_BYTES, unavailable};
use std::{
    io::{self, Read},
    os::fd::AsRawFd,
    sync::atomic::{AtomicBool, Ordering},
};
#[cfg(unix)]
fn descriptors_allowed() -> io::Result<()> {
    use rustix::fs::{Dir, Mode, OFlags, open};
    let mut directory = Dir::new(open(
        "/dev/fd",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?)?;
    let own = directory.fd()?.as_raw_fd();
    for _ in 0..1024 {
        let Some(entry) = directory.next() else {
            return Ok(());
        };
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        let descriptor = std::str::from_utf8(name)
            .ok()
            .and_then(|name| name.parse::<i32>().ok())
            .ok_or_else(unavailable)?;
        if descriptor > 2 && descriptor != own {
            return Err(unavailable());
        }
    }
    Err(unavailable())
}

struct Record {
    length: usize,
    bytes: [u8; RECORD_BYTES],
}
fn read_record(reader: &mut impl Read) -> io::Result<Record> {
    let mut header = [0_u8; 2];
    reader.read_exact(&mut header)?;
    let length = usize::from(u16::from_be_bytes(header));
    let mut record = Record {
        length,
        bytes: [0_u8; RECORD_BYTES],
    };
    reader.read_exact(record.bytes.get_mut(..length).ok_or_else(unavailable)?)?;
    Ok(record)
}

/// Internal executable mode: no CLI, environment, configuration, or database reads.
#[doc(hidden)]
pub(super) fn run() -> std::process::ExitCode {
    #[cfg(unix)]
    {
        if descriptors_allowed().is_err() {
            return std::process::ExitCode::from(70);
        }
        if rustix::process::setrlimit(
            rustix::process::Resource::Core,
            rustix::process::Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )
        .is_err()
        {
            return std::process::ExitCode::from(70);
        }
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let idle = std::sync::Arc::new(AtomicBool::new(true));
        let reader_idle = std::sync::Arc::clone(&idle);
        let reader = std::thread::Builder::new()
            .name("positron-output-reader".into())
            .stack_size(64 * 1024)
            .spawn(move || {
                let mut input = std::io::stdin().lock();
                loop {
                    let record = match read_record(&mut input) {
                        Ok(record) => record,
                        Err(_) => terminate_helper(),
                    };
                    let closing = record.length == 0;
                    // A Close cannot retire the death watcher while stderr is
                    // blocked. Normal producers wait for the preceding ACK.
                    if (closing && !reader_idle.load(Ordering::Acquire))
                        || (!closing
                            && reader_idle
                                .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
                                .is_err())
                        || sender.try_send(record).is_err()
                    {
                        terminate_helper();
                    }
                    if closing {
                        return;
                    }
                }
            });
        let Ok(reader) = reader else {
            return std::process::ExitCode::from(70);
        };
        while let Ok(record) = receiver.recv() {
            let closing = record.length == 0;
            let Some(mut bytes) = record.bytes.get(..record.length) else {
                terminate_helper();
            };
            while !bytes.is_empty() {
                match rustix::io::write(std::io::stderr(), bytes) {
                    Ok(0) => terminate_helper(),
                    Ok(count) => {
                        let Some(rest) = bytes.get(count..) else {
                            terminate_helper();
                        };
                        bytes = rest;
                    },
                    Err(rustix::io::Errno::INTR) => {},
                    Err(_) => terminate_helper(),
                }
            }
            // The complete stderr write precedes admission of another record.
            // ACK itself must never block and strand an already-finished reader.
            idle.store(true, Ordering::Release);
            if rustix::net::send(std::io::stdout(), b"A", rustix::net::SendFlags::DONTWAIT) != Ok(1)
            {
                terminate_helper();
            }
            if closing {
                return if reader.join().is_ok() {
                    std::process::ExitCode::SUCCESS
                } else {
                    std::process::ExitCode::from(70)
                };
            }
        }
    }
    std::process::ExitCode::from(70)
}

#[cfg(unix)]
fn terminate_helper() -> ! {
    // SIGKILL has no destructors, atexit hooks, stdio flushing, or writer locks.
    if rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::KILL)
        .is_err()
    {
        // Core dumps are disabled before the reader starts. Abort is also a
        // non-flushing fallback if the operating system refuses our own kill.
        std::process::abort();
    }
    std::process::abort()
}

#[cfg(any(test, fuzzing))]
pub(super) fn decode_frame(bytes: &[u8]) -> Option<usize> {
    read_record(&mut std::io::Cursor::new(bytes))
        .ok()
        .map(|record| record.length)
}

#[cfg(test)]
mod tests;
