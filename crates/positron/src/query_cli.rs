//! The bounded Log CLI uses the generated canonical HTTP client.
use positron_api::log_query::{LogQueryRequest, LogQueryServiceClient, MAX_REQUEST_BYTES};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    process::ExitCode,
};

pub(super) fn run(mut arguments: impl Iterator<Item = String>) -> ExitCode {
    crate::administrative_cli::exit((|| {
        let mut options = BTreeMap::new();
        let mut credential_stdin = false;
        let mut plaintext = false;
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--credential-stdin" if !credential_stdin => credential_stdin = true,
                "--allow-plaintext" if !plaintext => plaintext = true,
                "--endpoint" | "--server-name" | "--trust-file" | "--request" => {
                    let value = arguments.next().ok_or("missing query option value")?;
                    if options.insert(argument, value).is_some() {
                        return Err("duplicate query option");
                    }
                },
                _ => return Err("unknown or duplicate query option"),
            }
        }
        if !credential_stdin {
            return Err("--credential-stdin is required");
        }
        let transport = crate::administrative_cli::transport(
            &mut options,
            plaintext,
            crate::administrative_cli::required_transport_option,
        )?;
        let path = options.remove("--request").ok_or("--request is required")?;
        let file = std::fs::File::open(path).map_err(|_| "query request unavailable")?;
        let mut bytes = Vec::new();
        file.take(MAX_REQUEST_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "query request unavailable")?;
        let request =
            LogQueryRequest::decode(&bytes).map_err(|_| "invalid bounded query request")?;
        let credential = crate::administrative_cli::credential()?;
        let client =
            LogQueryServiceClient::new(transport).map_err(|_| "query transport unavailable")?;
        let response = client
            .execute(credential.trim_end_matches(['\r', '\n']), &request)
            .map_err(client_failure)?;
        let output = response.encode().map_err(|_| "invalid query response")?;
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(&output)
            .map_err(|_| "query output unavailable")?;
        stdout
            .write_all(b"\n")
            .map_err(|_| "query output unavailable")?;
        stdout.flush().map_err(|_| "query output unavailable")
    })())
}

fn client_failure(failure: positron_api::log_query::LogQueryServiceClientFailure) -> &'static str {
    use positron_api::log_query::LogQueryServiceClientFailure as F;
    match failure {
        F::InvalidRequest => "invalid bounded query request",
        F::AuthenticationRejected => "query authentication rejected",
        F::CapacityUnavailable => "query capacity unavailable; retry after backoff",
        F::QueryUnavailable => "query unavailable; inspect instance readiness",
        F::Transport => "query transport or response unavailable",
    }
}
