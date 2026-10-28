//! One bounded, non-retrying request to the existing process reload owner.
use std::path::Path;

pub(super) fn request(path: &Path) -> Result<String, ()> {
    let response = crate::control_socket::owner_control_request(
        path,
        b"POST /control/configuration/reload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        1024,
        |bytes| validate_response(bytes).is_ok(),
    ).map_err(|_| ())?;
    validate_response(&response)?;
    Ok("status=reload_requested\n".to_owned())
}

pub(super) fn validate_response(response: &[u8]) -> Result<(), ()> {
    if response.len() > 1024 {
        return Err(());
    }
    let response = std::str::from_utf8(response).map_err(|_| ())?;
    let (head, body) = response.split_once("\r\n\r\n").ok_or(())?;
    let mut lengths = head
        .lines()
        .filter_map(|line| line.strip_prefix("Content-Length: "));
    if !head.starts_with("HTTP/1.1 202 Accepted\r\n")
        || lengths.next() != Some("24")
        || lengths.next().is_some()
        || body != "status=reload_requested\n"
    {
        return Err(());
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
