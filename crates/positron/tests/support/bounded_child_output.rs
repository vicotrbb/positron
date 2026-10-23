//! Bounded output capture while existing fixture watchdogs wait for child exit.
use std::{
    io::Read,
    process::Child,
    time::{Duration, Instant},
};

const CAPTURE_LIMIT: u64 = 1024 * 1024;

fn capture(pipe: Option<impl Read>) -> std::io::Result<Vec<u8>> {
    let Some(mut pipe) = pipe else {
        return Ok(Vec::new());
    };
    let mut bytes = Vec::new();
    pipe.by_ref()
        .take(CAPTURE_LIMIT + 1)
        .read_to_end(&mut bytes)?;
    // Retain a bounded diagnostic, but never block the child on excess output.
    std::io::copy(&mut pipe, &mut std::io::sink())?;
    Ok(bytes)
}

pub fn wait_before(
    mut child: Child,
    deadline: Instant,
    poll_interval: Duration,
    timeout_message: &'static str,
) -> std::io::Result<std::process::Output> {
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    std::thread::scope(|scope| {
        let stdout = scope.spawn(|| capture(stdout));
        let stderr = scope.spawn(|| capture(stderr));
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if Instant::now() < deadline => {},
                Ok(None) => {
                    break Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        timeout_message,
                    ));
                },
                Err(error) => break Err(error),
            }
            std::thread::sleep(poll_interval);
        };
        // Reap before joining readers, including on a polling error or expiry.
        let cleanup = if status.is_err() {
            let killed = child.kill();
            let waited = child.wait();
            killed.and(waited.map(|_| ()))
        } else {
            Ok(())
        };
        let stdout = stdout.join();
        let stderr = stderr.join();
        cleanup?;
        let status = status?;
        let stdout =
            stdout.map_err(|_| std::io::Error::other("child stdout reader panicked"))??;
        let stderr =
            stderr.map_err(|_| std::io::Error::other("child stderr reader panicked"))??;
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                timeout_message,
            ));
        }
        if stdout.len() as u64 > CAPTURE_LIMIT || stderr.len() as u64 > CAPTURE_LIMIT {
            return Err(std::io::Error::other(
                "child output exceeded fixture capture bound",
            ));
        }
        Ok(std::process::Output {
            status,
            stdout,
            stderr,
        })
    })
}
