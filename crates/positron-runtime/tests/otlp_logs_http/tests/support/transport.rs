use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use super::TestError;

pub(super) fn exchange(
    endpoint: SocketAddr,
    request_head: &[u8],
    body: &[u8],
    deadline: Option<Instant>,
) -> Result<Vec<u8>, TestError> {
    let timeout = remaining(deadline)?.map_or(Duration::from_secs(2), |remaining| {
        remaining.min(Duration::from_secs(2))
    });
    let mut reader = TcpStream::connect_timeout(&endpoint, timeout)?;
    let mut writer = reader.try_clone()?;

    std::thread::scope(|scope| {
        let write = scope.spawn(move || write_request(&mut writer, request_head, body, deadline));
        let response = read_response(&mut reader, deadline);
        let write = write
            .join()
            .map_err(|_| std::io::Error::other("HTTP request writer panicked"))?;
        write?;
        Ok(response?)
    })
}

pub(super) fn exchange_stalled(
    endpoint: SocketAddr,
    request_head: &[u8],
) -> Result<Vec<u8>, TestError> {
    let mut stream = TcpStream::connect_timeout(&endpoint, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(4)))?;
    stream.write_all(request_head)?;
    Ok(read_response(&mut stream, None)?)
}

fn write_request(
    stream: &mut TcpStream,
    request_head: &[u8],
    body: &[u8],
    deadline: Option<Instant>,
) -> Result<(), std::io::Error> {
    if let Some(timeout) = remaining(deadline)? {
        stream.set_write_timeout(Some(timeout))?;
    }
    stream.write_all(request_head)?;
    if let Some(timeout) = remaining(deadline)? {
        stream.set_write_timeout(Some(timeout))?;
    }
    match stream.write_all(body) {
        Ok(()) => {},
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            ) => {},
        Err(error) => return Err(error),
    }
    match stream.shutdown(Shutdown::Write) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotConnected => Ok(()),
        Err(error) => Err(error),
    }
}

fn read_response(
    stream: &mut TcpStream,
    deadline: Option<Instant>,
) -> Result<Vec<u8>, std::io::Error> {
    let mut response = Vec::new();
    let mut buffer = [0_u8; 1_024];
    loop {
        if let Some(timeout) = remaining(deadline)? {
            stream.set_read_timeout(Some(timeout))?;
        }
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(response),
            Ok(read) => response.extend_from_slice(&buffer[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {
                return Ok(response);
            },
            Err(error) => return Err(error),
        }
    }
}

fn remaining(deadline: Option<Instant>) -> Result<Option<Duration>, std::io::Error> {
    deadline
        .map(|deadline| {
            deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "HTTP request deadline expired",
                    )
                })
        })
        .transpose()
}
