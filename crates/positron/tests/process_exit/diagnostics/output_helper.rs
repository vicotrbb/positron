//! Public subprocess outcomes for the private, authority-free output mode.
#![cfg(unix)]
use super::*;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ExitStatus};
use std::time::Instant;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ARGUMENT: &str = positron_runtime::OPERATIONAL_HELPER_ARGUMENT;

fn spawn_helper(stderr: Stdio) -> TestResult<(Child, UnixStream)> {
    let (parent, child) = UnixStream::pair()?;
    parent.set_read_timeout(Some(Duration::from_secs(2)))?;
    parent.set_write_timeout(Some(Duration::from_secs(2)))?;
    let input: OwnedFd = child.try_clone()?.into();
    let output: OwnedFd = child.into();
    let child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .arg(ARGUMENT)
        .env_clear()
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(output))
        .stderr(stderr)
        .spawn()?;
    Ok((child, parent))
}
fn wait(child: &mut Child) -> TestResult<ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err("output helper exceeded its exit bound".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn send(stream: &mut UnixStream, bytes: &[u8]) -> TestResult {
    stream.write_all(&u16::try_from(bytes.len())?.to_be_bytes())?;
    stream.write_all(bytes)?;
    Ok(())
}
pub(super) fn full_pipe() -> TestResult<(std::io::PipeReader, std::io::PipeWriter)> {
    let (reader, writer) = std::io::pipe()?;
    let flags = rustix::fs::fcntl_getfl(&writer)?;
    rustix::fs::fcntl_setfl(&writer, flags | rustix::fs::OFlags::NONBLOCK)?;
    for _ in 0..65536 {
        if rustix::io::write(&writer, &[0_u8; 4096]).is_err() {
            break;
        }
    }
    rustix::fs::fcntl_setfl(&writer, flags)?;
    Ok((reader, writer))
}

#[test]
fn output_helper_acknowledges_complete_records_and_reaps_after_normal_close() -> TestResult {
    let (mut reader, writer) = std::io::pipe()?;
    let (mut child, mut socket) = spawn_helper(Stdio::from(writer))?;
    send(&mut socket, b"positron: error configuration_rejected\n")?;
    let mut ack = [0_u8; 1];
    socket
        .read_exact(&mut ack)
        .map_err(|error| format!("record acknowledgment: {error}"))?;
    assert_eq!(ack, [b'A']);
    send(&mut socket, &[])?;
    socket
        .read_exact(&mut ack)
        .map_err(|error| format!("close acknowledgment: {error}"))?;
    assert_eq!(ack, [b'A']);
    assert!(wait(&mut child)?.success());
    let mut text = String::new();
    reader.read_to_string(&mut text)?;
    assert_eq!(text, "positron: error configuration_rejected\n");
    Ok(())
}

#[test]
fn output_helper_reader_ends_a_blocked_writer_after_abrupt_parent_eof() -> TestResult {
    let (_reader, writer) = full_pipe()?;
    let flags = rustix::fs::fcntl_getfl(&writer)?;
    let (mut child, mut socket) = spawn_helper(Stdio::from(writer.try_clone()?))?;
    send(&mut socket, &[b'x'; 510])?;
    std::thread::sleep(Duration::from_millis(25));
    assert!(child.try_wait()?.is_none());
    drop(socket);
    assert_eq!(wait(&mut child)?.signal(), Some(9));
    assert_eq!(rustix::fs::fcntl_getfl(&writer)?, flags);
    Ok(())
}

#[test]
fn output_helper_close_cannot_retire_the_death_watcher_behind_a_blocked_record() -> TestResult {
    let (mut reader, writer) = std::io::pipe()?;
    let (mut child, mut socket) = spawn_helper(Stdio::from(writer.try_clone()?))?;
    send(&mut socket, b"ready\n")?;
    let mut ack = [0_u8; 1];
    socket.read_exact(&mut ack)?;
    assert_eq!(ack, [b'A']);
    let mut ready = [0_u8; 6];
    reader.read_exact(&mut ready)?;
    assert_eq!(&ready, b"ready\n");
    let flags = rustix::fs::fcntl_getfl(&writer)?;
    rustix::fs::fcntl_setfl(&writer, flags | rustix::fs::OFlags::NONBLOCK)?;
    for _ in 0..65536 {
        if rustix::io::write(&writer, &[0_u8; 4096]).is_err() {
            break;
        }
    }
    rustix::fs::fcntl_setfl(&writer, flags)?;
    send(&mut socket, &[b'x'; 510])?;
    socket.set_read_timeout(Some(Duration::from_millis(50)))?;
    assert!(
        socket.read_exact(&mut ack).is_err(),
        "a full stderr cannot acknowledge the record"
    );
    send(&mut socket, &[])?;
    drop(socket);
    assert_eq!(wait(&mut child)?.signal(), Some(9));
    Ok(())
}

#[test]
fn output_helper_refuses_oversized_and_unacknowledged_record_overflow() -> TestResult {
    for oversized in [true, false] {
        let (_reader, writer) = full_pipe()?;
        let (mut child, mut socket) = spawn_helper(Stdio::from(writer))?;
        if oversized {
            socket.write_all(&511_u16.to_be_bytes())?;
        } else {
            for _ in 0..4 {
                if send(&mut socket, &[b'x'; 510]).is_err() {
                    break;
                }
            }
        }
        assert!(!wait(&mut child)?.success());
    }
    Ok(())
}

#[test]
fn output_helper_refuses_an_unrelated_inherited_descriptor_before_records() -> TestResult {
    // The shell owns the deliberately inheritable descriptor, so the Rust test
    // harness never exposes it to other concurrently spawned subprocesses.
    let status = Command::new("/bin/sh")
        .args([
            "-c",
            "exec 3</dev/null; exec \"$1\" \"$2\"",
            "positron-output-fd-test",
        ])
        .arg(env!("CARGO_BIN_EXE_positron"))
        .arg(ARGUMENT)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    assert_eq!(status.code(), Some(70));
    Ok(())
}

#[test]
fn native_startup_with_closed_or_full_stderr_is_bounded_and_preserves_its_exit() -> TestResult {
    for full in [false, true] {
        let (reader, writer) = if full { full_pipe()? } else { std::io::pipe()? };
        let retained_reader = full.then_some(reader);
        let started = Instant::now();
        let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
            .args(["serve", "--set", "storage.data_directory=relative"])
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()?;
        assert_eq!(
            wait(&mut child)
                .map_err(|error| format!("full={full}: {error}"))?
                .code(),
            Some(2)
        );
        assert!(started.elapsed() < Duration::from_secs(3));
        drop(retained_reader);
    }
    Ok(())
}

#[test]
fn output_helper_closed_acknowledgment_socket_terminates_without_waiting_for_eof() -> TestResult {
    let (mut socket, request) = UnixStream::pair()?;
    let (acknowledgment, closed_peer) = UnixStream::pair()?;
    drop(closed_peer);
    let request: OwnedFd = request.into();
    let acknowledgment: OwnedFd = acknowledgment.into();
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .arg(ARGUMENT)
        .env_clear()
        .stdin(Stdio::from(request))
        .stdout(Stdio::from(acknowledgment))
        .stderr(Stdio::null())
        .spawn()?;
    send(&mut socket, b"closed acknowledgment\n")?;
    assert_eq!(wait(&mut child)?.signal(), Some(9));
    Ok(())
}

#[test]
fn native_terminal_diagnostic_remains_text_and_preserves_caller_nonblock_flags() -> TestResult {
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY)?;
    rustix::io::fcntl_setfd(&master, rustix::io::FdFlags::CLOEXEC)?;
    grantpt(&master)?;
    unlockpt(&master)?;
    let name = ptsname(&master, Vec::new())?;
    let slave = std::fs::File::from(rustix::fs::open(
        name.as_c_str(),
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?);
    let flags = rustix::fs::fcntl_getfl(&slave)? & rustix::fs::OFlags::NONBLOCK;
    let status = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["serve", "--set", "storage.data_directory=relative"])
        .stdout(Stdio::null())
        .stderr(Stdio::from(slave.try_clone()?))
        .status()?;
    assert_eq!(status.code(), Some(2));
    assert_eq!(
        rustix::fs::fcntl_getfl(&slave)? & rustix::fs::OFlags::NONBLOCK,
        flags
    );
    rustix::fs::fcntl_setfl(
        &master,
        rustix::fs::fcntl_getfl(&master)? | rustix::fs::OFlags::NONBLOCK,
    )?;
    let mut bytes = [0_u8; 512];
    let count = rustix::io::read(&master, &mut bytes)?;
    assert_eq!(
        std::str::from_utf8(bytes.get(..count).ok_or("terminal bytes")?)?.trim(),
        "positron: error configuration_rejected"
    );
    Ok(())
}
