pub(super) fn service_log_diagnostic(
    reader: impl std::io::Read,
    claims: &str,
) -> std::io::Result<String> {
    use std::io::Read;
    let mut log = String::new();
    reader.take(16_384).read_to_string(&mut log)?;
    for (name, value) in claims.lines().filter_map(|line| line.split_once('=')) {
        if name.ends_with("_secret") && !value.is_empty() {
            log = log.replace(value, "[REDACTED]");
        }
    }
    Ok(log)
}

#[test]
fn service_log_diagnostic_bounds_input_and_redacts_claimed_secrets() {
    let claims = "ingest_secret=ingest-secret-canary\nquery_secret=query-secret-canary\nadministrator_secret=administrator-secret-canary\n";
    let log = format!(
        "ingest-secret-canary query-secret-canary administrator-secret-canary {}outside-bound",
        "x".repeat(16_384)
    );
    let diagnostic = service_log_diagnostic(std::io::Cursor::new(log), claims).unwrap();
    assert!(diagnostic.len() <= 16_384);
    assert_eq!(diagnostic.matches("[REDACTED]").count(), 3);
    for secret in [
        "ingest-secret-canary",
        "query-secret-canary",
        "administrator-secret-canary",
        "outside-bound",
    ] {
        assert!(!diagnostic.contains(secret));
    }
}

pub(super) fn ingest_response(mut reader: impl std::io::Read) -> std::io::Result<String> {
    use std::io::{Error, ErrorKind};
    let invalid = |message| Error::new(ErrorKind::InvalidData, message);
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        if response.len() == 65_536 {
            return Err(invalid("ingest response headers exceed bound"));
        }
        let mut byte = [0];
        reader.read_exact(&mut byte)?;
        response.extend_from_slice(&byte);
    }
    let headers = std::str::from_utf8(&response)
        .map_err(|_| invalid("ingest response headers are not UTF-8"))?;
    let status = headers.lines().next().unwrap_or_default().to_owned();
    let mut length = None;
    for (name, value) in headers.lines().filter_map(|line| line.split_once(':')) {
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(invalid("ingest response has unsupported transfer encoding"));
        }
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = value
                .trim()
                .parse::<usize>()
                .map_err(|_| invalid("ingest response has invalid length"))?;
            if length.replace(parsed).is_some() {
                return Err(invalid("ingest response has duplicate length"));
            }
        }
    }
    let length = length.ok_or_else(|| invalid("ingest response has no length"))?;
    if length > 65_536 - response.len() {
        return Err(invalid("ingest response body exceeds bound"));
    }
    let body_start = response.len();
    response.resize(body_start + length, 0);
    reader
        .read_exact(
            response
                .get_mut(body_start..)
                .ok_or_else(|| invalid("body range"))?,
        )
        .map_err(|error| Error::new(error.kind(), format!("incomplete {status} body: {error}")))?;
    String::from_utf8(response).map_err(|_| invalid("ingest response is not UTF-8"))
}

#[test]
fn complete_ingest_response_does_not_require_connection_closure() {
    struct ResetAfter(std::io::Cursor<&'static [u8]>);
    impl std::io::Read for ResetAfter {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let count = std::io::Read::read(&mut self.0, buffer)?;
            if count == 0 {
                Err(std::io::ErrorKind::ConnectionReset.into())
            } else {
                Ok(count)
            }
        }
    }
    for response in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
        b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\nContent-Length: 2\r\n\r\n{}"
            .as_slice(),
    ] {
        assert_eq!(
            ingest_response(ResetAfter(std::io::Cursor::new(response))).unwrap(),
            std::str::from_utf8(response).unwrap()
        );
    }
    for response in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}".as_slice(),
    ] {
        assert_eq!(
            ingest_response(ResetAfter(std::io::Cursor::new(response)))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::ConnectionReset
        );
    }
}

#[test]
fn ingest_response_refuses_incomplete_ambiguous_and_oversized_framing() {
    for response in [
        "HTTP/1.1 200 OK\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n\r\n",
    ] {
        assert!(ingest_response(std::io::Cursor::new(response)).is_err());
    }
    assert!(ingest_response(std::io::Cursor::new(vec![b'a'; 65_537])).is_err());
}
