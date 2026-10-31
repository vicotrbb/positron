//! One bounded, non-retrying request to the existing process reload owner.
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Failure {
    Timeout,
    EndpointUnavailable,
    PeerClosed,
    IncompleteResponse,
    AuthenticationRejected,
    OwnerUnavailable,
    UnexpectedStatus,
    InvalidResponse,
}

impl Failure {
    pub(super) const fn code(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::EndpointUnavailable => "endpoint_unavailable",
            Self::PeerClosed => "peer_closed",
            Self::IncompleteResponse => "incomplete_response",
            Self::AuthenticationRejected => "authentication_rejected",
            Self::OwnerUnavailable => "owner_unavailable",
            Self::UnexpectedStatus => "unexpected_status",
            Self::InvalidResponse => "invalid_response",
        }
    }

    fn transport(error: std::io::Error) -> Self {
        use std::io::ErrorKind;
        match error.kind() {
            ErrorKind::TimedOut => Self::Timeout,
            ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
            | ErrorKind::UnexpectedEof => Self::PeerClosed,
            ErrorKind::InvalidData => Self::InvalidResponse,
            _ => Self::EndpointUnavailable,
        }
    }
}

pub(super) fn request(path: &Path, bearer: &str) -> Result<String, Failure> {
    let request = zeroize::Zeroizing::new(format!(
        "POST /control/configuration/reload HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {bearer}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    ));
    let response =
        crate::control_socket::owner_control_request(path, request.as_bytes(), 1024, |bytes| {
            validate_response(bytes).is_ok()
        })
        .map_err(Failure::transport)?;
    validate_response(&response)?;
    Ok("status=reload_requested\n".to_owned())
}

pub(super) fn validate_response(response: &[u8]) -> Result<(), Failure> {
    if response.len() > 1024 {
        return Err(Failure::InvalidResponse);
    }
    if response.is_empty() {
        return Err(Failure::PeerClosed);
    }
    let response = std::str::from_utf8(response).map_err(|_| Failure::InvalidResponse)?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or(Failure::IncompleteResponse)?;
    let status = head
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("HTTP/1.1 "))
        .and_then(|line| line.split_once(' '))
        .map(|(code, _)| code)
        .filter(|code| code.len() == 3 && code.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or(Failure::InvalidResponse)?;
    let mut lengths = head
        .lines()
        .filter_map(|line| line.strip_prefix("Content-Length: "));
    let length = lengths.next().ok_or(Failure::InvalidResponse)?;
    if lengths.next().is_some() {
        return Err(Failure::InvalidResponse);
    }
    let expected = length
        .parse::<usize>()
        .map_err(|_| Failure::InvalidResponse)?;
    if body.len() < expected {
        return Err(Failure::IncompleteResponse);
    }
    if body.len() != expected {
        return Err(Failure::InvalidResponse);
    }
    match status {
        "401" => return Err(Failure::AuthenticationRejected),
        "503" => return Err(Failure::OwnerUnavailable),
        "202" => {},
        _ => return Err(Failure::UnexpectedStatus),
    }
    if !head.starts_with("HTTP/1.1 202 Accepted\r\n")
        || length != "24"
        || body != "status=reload_requested\n"
    {
        return Err(Failure::InvalidResponse);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_response;
    #[test]
    fn only_a_complete_unambiguous_reload_acknowledgment_is_accepted() {
        let valid = b"HTTP/1.1 202 Accepted\r\nContent-Type: text/plain\r\nContent-Length: 24\r\nConnection: close\r\n\r\nstatus=reload_requested\n";
        assert!(validate_response(valid).is_ok());
        for invalid in [
            valid[..valid.len()-1].to_vec(),
            [valid.as_slice(), b"x"].concat(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 24\r\n\r\nstatus=reload_requested\n".to_vec(),
            b"HTTP/1.1 202 Accepted\r\nContent-Length: 24\r\nContent-Length: 24\r\n\r\nstatus=reload_requested\n".to_vec(),
            vec![b'x'; 1025],
        ] { assert!(validate_response(&invalid).is_err()); }
    }
}
