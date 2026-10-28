//! One non-retrying owner-local claim request. Failed delivery never recreates a claim.
use std::{io::Write, path::Path};

const UNAVAILABLE: &str = "bootstrap claim unavailable; consumed credentials cannot be redisplayed";

pub(super) fn claim(path: &Path) -> Result<(), &'static str> {
    let bytes = crate::control_socket::owner_control_request(
        path,
        b"POST /control/bootstrap/claim HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        4096,
        |bytes| response_body(bytes).is_ok(),
    ).map_err(|_| UNAVAILABLE)?;
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
    let mut length = None;
    for header in head.lines().skip(1) {
        let (name, value) = header.split_once(':').ok_or(UNAVAILABLE)?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(UNAVAILABLE);
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(UNAVAILABLE);
            }
            length = Some(value.trim().parse::<usize>().map_err(|_| UNAVAILABLE)?);
        }
    }
    if length != Some(body.len()) {
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

#[cfg(test)]
mod tests {
    use super::response_body;

    #[test]
    fn claim_completion_requires_a_complete_unambiguous_credential_frame() {
        let body = format!("administrator_secret=pos_{}\n", "00".repeat(32));
        let frame = |headers: &str| format!("HTTP/1.1 200 OK\r\n{headers}\r\n{body}");
        let length = format!("Content-Length: {}\r\n", body.len());
        let valid = frame(&length);
        assert_eq!(response_body(valid.as_bytes()), Ok(body.as_str()));
        for rejected in [
            valid[..valid.len() - 1].to_owned(),
            format!("{valid}x"),
            frame(&format!("{length}content-length: {}\r\n", body.len())),
            frame(&format!("{length}Transfer-Encoding: chunked\r\n")),
            frame(&format!("{length}transfer-encoding: identity\r\n")),
            frame(""),
            "x".repeat(4097),
        ] {
            assert!(
                response_body(rejected.as_bytes()).is_err(),
                "ambiguous claim frame accepted"
            );
        }
    }
}
