use super::{BackupServiceClient, client_failure};
use positron_api::backup::BackupListRequest;
use std::{collections::BTreeMap, io::Write};
pub(super) fn execute(
    mut arguments: impl Iterator<Item = String>,
    output: &mut impl Write,
) -> Result<(), &'static str> {
    let mut options = BTreeMap::new();
    let mut credential_stdin = false;
    let mut allow_plaintext = false;
    while let Some(option) = arguments.next() {
        match option.as_str() {
            "--credential-stdin" if !credential_stdin => credential_stdin = true,
            "--allow-plaintext" if !allow_plaintext => allow_plaintext = true,
            "--endpoint" | "--server-name" | "--trust-file" | "--repository-id" | "--limit"
            | "--cursor" => {
                let value = arguments.next().ok_or("missing backup list option value")?;
                if value.is_empty() || value.len() > 2048 || options.insert(option, value).is_some()
                {
                    return Err("invalid or duplicate backup list option");
                }
            },
            _ => return Err("unknown or duplicate backup list option"),
        }
    }
    if !credential_stdin {
        return Err("--credential-stdin is required");
    }
    let transport = crate::administrative_cli::transport(
        &mut options,
        allow_plaintext,
        crate::administrative_cli::required_transport_option,
    )?;
    let request = BackupListRequest {
        repository_id: options
            .remove("--repository-id")
            .ok_or("backup list requires --repository-id")?,
        limit: options
            .remove("--limit")
            .map(|value| {
                value
                    .parse::<u32>()
                    .map_err(|_| "invalid backup list limit")
            })
            .transpose()?
            .unwrap_or(128),
        cursor: options.remove("--cursor"),
    };
    request
        .encode()
        .map_err(|_| "invalid backup list repository, limit or cursor")?;
    let credential = crate::administrative_cli::credential()?;
    let client = BackupServiceClient::new(transport).map_err(client_failure)?;
    let response = client
        .list(credential.trim_end_matches(['\r', '\n']), &request)
        .map_err(client_failure)?;
    writeln!(output,"repository_id={} instance_id={} provider_kind={} format_epoch={} integrity_fingerprint={} prefix_commitment={}",response.repository.repository_id,response.repository.instance_id,response.repository.provider_kind,response.repository.format_epoch,response.repository.integrity_fingerprint,response.repository.prefix_commitment).map_err(|_|"backup list output unavailable")?;
    if let Some(generation) = response.registry_generation_checksum {
        writeln!(output, "registry_generation_checksum={generation}")
            .map_err(|_| "backup list output unavailable")?;
    }
    for entry in response.entries {
        writeln!(output,"snapshot_id={} manifest_checksum={} created_unix_seconds={} retain_until_unix_seconds={}",entry.snapshot_id,entry.manifest_checksum,entry.created_unix_seconds,entry.retain_until_unix_seconds).map_err(|_|"backup list output unavailable")?;
    }
    if let Some(cursor) = response.next_cursor {
        writeln!(output, "next_cursor={cursor}").map_err(|_| "backup list output unavailable")?;
    }
    Ok(())
}
