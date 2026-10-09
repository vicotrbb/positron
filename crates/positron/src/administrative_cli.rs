use std::collections::BTreeMap;
use std::io::{IsTerminal, Read};
use std::net::SocketAddr;
use std::process::ExitCode;

use positron_api::api_keys::ApiKeyTransport;
use zeroize::Zeroizing;

pub(super) fn exit(result: Result<(), &'static str>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("positron: {message}");
            ExitCode::from(2)
        },
    }
}

pub(super) fn credential() -> Result<Zeroizing<String>, &'static str> {
    let mut input = std::io::stdin();
    if input.is_terminal() {
        return Err("credential input must be a pipe; terminal input is refused to prevent echo");
    }
    read_credential(&mut input)
}

pub(super) fn read_credential(input: &mut impl Read) -> Result<Zeroizing<String>, &'static str> {
    let mut credential = Zeroizing::new(String::new());
    input
        .take(1025)
        .read_to_string(&mut credential)
        .map_err(|_| "credential input unavailable")?;
    let bearer = credential.trim_end_matches(['\r', '\n']);
    if credential.len() > 1024
        || bearer.is_empty()
        || bearer.len() > 1024
        || !bearer
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err("invalid credential input");
    }
    Ok(credential)
}

pub(super) fn required_transport_option(
    options: &mut BTreeMap<String, String>,
    name: &str,
) -> Result<String, &'static str> {
    options.remove(name).ok_or(match name {
        "--endpoint" => "--endpoint is required",
        "--server-name" => "--server-name is required for TLS",
        _ => "--trust-file is required unless --allow-plaintext is explicit",
    })
}

pub(super) fn transport(
    options: &mut BTreeMap<String, String>,
    allow_plaintext: bool,
    required: fn(&mut BTreeMap<String, String>, &str) -> Result<String, &'static str>,
) -> Result<ApiKeyTransport, &'static str> {
    let endpoint: SocketAddr = required(options, "--endpoint")?
        .parse()
        .map_err(|_| "invalid API endpoint")?;
    if endpoint.port() == 0 {
        return Err("invalid API endpoint");
    }
    if allow_plaintext {
        if options.contains_key("--server-name") || options.contains_key("--trust-file") {
            return Err("TLS options do not apply to plaintext opt-out");
        }
        Ok(ApiKeyTransport::PlaintextOptOut { endpoint })
    } else {
        Ok(ApiKeyTransport::Tls {
            endpoint,
            server_name: required(options, "--server-name")?,
            trust_file: required(options, "--trust-file")?.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_bounds_include_line_endings_and_reject_invalid_input() {
        for valid in [
            "a".repeat(1024),
            format!("{}\r\n", "a".repeat(1022)),
            "key_A-1.\n".to_owned(),
        ] {
            let credential = read_credential(&mut valid.as_bytes()).expect("bounded credential");
            assert_eq!(*credential, valid);
        }
        for invalid in [
            String::new(),
            "\r\n".to_owned(),
            "a".repeat(1025),
            format!("{}\n", "a".repeat(1024)),
            "key value".to_owned(),
            "key\nvalue".to_owned(),
            "é".to_owned(),
        ] {
            assert_eq!(
                read_credential(&mut invalid.as_bytes()).unwrap_err(),
                "invalid credential input"
            );
        }
    }

    #[test]
    fn credential_reader_stops_at_the_probe_byte() {
        let bytes = vec![b'a'; 4096];
        let mut input = std::io::Cursor::new(bytes);
        assert!(read_credential(&mut input).is_err());
        assert_eq!(input.position(), 1025);
    }

    #[test]
    fn credential_read_failures_are_explicit() {
        struct Unavailable;
        impl Read for Unavailable {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("unavailable"))
            }
        }
        assert_eq!(
            read_credential(&mut Unavailable).unwrap_err(),
            "credential input unavailable"
        );
        assert_eq!(
            read_credential(&mut &[0xff][..]).unwrap_err(),
            "credential input unavailable"
        );
    }
}
