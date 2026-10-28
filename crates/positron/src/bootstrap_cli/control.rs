//! One non-retrying owner-local claim request. Failed delivery never recreates a claim.
use std::{
    io::{Read, Write},
    path::Path,
    time::Duration,
};
use zeroize::Zeroizing;

const UNAVAILABLE: &str = "bootstrap claim unavailable; consumed credentials cannot be redisplayed";

pub(super) fn claim(path: &Path) -> Result<(), &'static str> {
    let deadline = Duration::from_secs(5);
    let mut stream =
        crate::control_socket::connect_owner_control(path, deadline).map_err(|_| UNAVAILABLE)?;
    stream
        .set_read_timeout(Some(deadline))
        .map_err(|_| UNAVAILABLE)?;
    stream
        .set_write_timeout(Some(deadline))
        .map_err(|_| UNAVAILABLE)?;
    stream.write_all(b"POST /control/bootstrap/claim HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").map_err(|_| UNAVAILABLE)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(512));
    stream
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| UNAVAILABLE)?;
    let body = response_body(&bytes)?;
    std::io::stdout()
        .lock()
        .write_all(body.as_bytes())
        .map_err(|_| UNAVAILABLE)
}

pub(crate) fn response_body(bytes: &[u8]) -> Result<&str, &'static str> {
    if bytes.len() > 4096 {
        return Err(UNAVAILABLE);
    }
    let response = std::str::from_utf8(bytes).map_err(|_| UNAVAILABLE)?;
    let (head, body) = response.split_once("\r\n\r\n").ok_or(UNAVAILABLE)?;
    if !head.starts_with("HTTP/1.1 200 OK\r\n") || !valid_claim(body) {
        return Err(UNAVAILABLE);
    }
    let mut lengths = head
        .lines()
        .filter_map(|line| line.strip_prefix("Content-Length: "));
    if lengths.next().and_then(|value| value.parse::<usize>().ok()) != Some(body.len())
        || lengths.next().is_some()
    {
        return Err(UNAVAILABLE);
    }
    Ok(body)
}

fn valid_claim(body: &str) -> bool {
    if !body.ends_with('\n') || body.len() > 512 {
        return false;
    }
    let mut seen = 0_u8;
    for line in body.lines() {
        let Some((name, value)) = line.split_once('=') else {
            return false;
        };
        let mask = match name {
            "administrator_secret" => 1,
            "ingest_secret" => 2,
            "query_secret" => 4,
            _ => return false,
        };
        if seen & mask != 0 || positron_governance::PresentedCredential::parse(value).is_err() {
            return false;
        }
        seen |= mask;
    }
    seen & 1 != 0
}
