//! Native binary exit and secret-safe diagnostics.

use std::process::Command;

#[cfg(unix)]
use positron_kernel::MountQualification;
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::process::Stdio;
#[cfg(unix)]
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[cfg(unix)]
use std::{io::Read, io::Write, net::TcpStream};
#[cfg(unix)]
use std::{os::fd::OwnedFd, os::unix::net::UnixStream};

#[cfg(unix)]
static PROCESS_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[path = "support.rs"]
pub(super) mod support;
use support::*;

#[path = "diagnostics/bundles.rs"]
mod bundles;
#[path = "diagnostics/cli.rs"]
mod cli;
#[path = "diagnostics/live_control.rs"]
mod live_control;
#[path = "diagnostics/offline.rs"]
mod offline;

#[cfg(unix)]
#[derive(Clone, Copy)]
enum SupportBundleOutput {
    SignedEncrypted,
    SignedPlaintext,
    UnsignedKeyUnavailableEncrypted,
}

#[cfg(unix)]
impl SupportBundleOutput {
    const fn label(self) -> &'static str {
        match self {
            Self::SignedEncrypted => "support-bounds-signed-encrypted",
            Self::SignedPlaintext => "support-bounds-signed-plaintext",
            Self::UnsignedKeyUnavailableEncrypted => "support-bounds-unsigned-encrypted",
        }
    }

    const fn requires_credential(self) -> bool {
        matches!(self, Self::SignedEncrypted | Self::SignedPlaintext)
    }

    const fn encrypts(self) -> bool {
        matches!(
            self,
            Self::SignedEncrypted | Self::UnsignedKeyUnavailableEncrypted
        )
    }
}

#[cfg(unix)]
fn persist_sanitized_crash_record(
    paths: &BootstrapPaths,
    data_directory: &std::path::Path,
    finding_code: &'static str,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let instance = InstanceBootstrap::reopen(paths)?;
    let record = positron_kernel::CrashRecord::new("serving", finding_code, "runtime")
        .map_err(|failure| format!("crash record: {failure:?}"))?;
    instance
        .crash_records()?
        .persist(&record)
        .map_err(|failure| format!("persist crash record: {failure:?}"))?;
    data_directory
        .join("diagnostics/crash-records")
        .read_dir()?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max_by_key(|entry| entry.file_name())
        .map(|entry| entry.path())
        .ok_or_else(|| "persisted crash record missing".into())
}

#[cfg(unix)]
fn invoke_support_bundle<I, S>(
    config: &std::path::Path,
    output: &std::path::Path,
    mode: SupportBundleOutput,
    credential: Option<&str>,
    extra: I,
) -> Result<(std::process::Output, Vec<u8>), Box<dyn std::error::Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    use age::{Decryptor, Identity};

    let mut command = Command::new(env!("CARGO_BIN_EXE_positron"));
    command
        .args(["support", "bundle", "create", "--config"])
        .arg(config)
        .args(["--output"])
        .arg(output);
    let identity = mode.encrypts().then(age::x25519::Identity::generate);
    if let Some(identity) = identity.as_ref() {
        command
            .arg("--recipient")
            .arg(identity.to_public().to_string());
    } else {
        command.arg("--allow-plaintext-bundle");
    }
    if mode.requires_credential() {
        command.arg("--credential-stdin").stdin(Stdio::piped());
    } else {
        command.arg("--offline-key-unavailable");
    }
    command.args(extra).stdout(Stdio::piped());
    let output_result = if let Some(credential) = credential {
        let mut child = command.spawn()?;
        let mut input = child.stdin.take().ok_or("support bundle stdin")?;
        input.write_all(credential.as_bytes())?;
        input.write_all(b"\n")?;
        drop(input);
        child.wait_with_output()?
    } else {
        command.output()?
    };
    let archive = if output_result.status.success() {
        match identity {
            Some(identity) => {
                let encrypted = fs::read(output)?;
                let decryptor = Decryptor::new(&encrypted[..])?;
                let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn Identity))?;
                let mut archive = Vec::new();
                reader.read_to_end(&mut archive)?;
                archive
            },
            None => fs::read(output)?,
        }
    } else {
        Vec::new()
    };
    if output_result.status.success() && archive.is_empty() {
        return Err(format!(
            "empty support archive mode={} path={} on-disk-bytes={} stdout={}",
            mode.label(),
            output.display(),
            fs::metadata(output)?.len(),
            String::from_utf8_lossy(&output_result.stdout),
        )
        .into());
    }
    Ok((output_result, archive))
}

#[cfg(unix)]
fn archive_member(archive: &[u8], wanted: &str) -> Result<String, Box<dyn std::error::Error>> {
    let archive_bytes = archive.len();
    let mut archive = tar::Archive::new(archive);
    let mut observed = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if path.as_os_str() == std::ffi::OsStr::new(wanted) {
            let mut bytes = String::new();
            entry.read_to_string(&mut bytes)?;
            return Ok(bytes);
        }
        observed.push(path.display().to_string());
    }
    Err(format!(
        "missing archive member {wanted}; archive_bytes={}; saw {observed:?}",
        archive_bytes
    )
    .into())
}

#[cfg(unix)]
fn verify_authenticated_bundle_archive(
    archive: &[u8],
    expected: positron_kernel::BootstrapIntegrityIdentity,
) -> Result<(), Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};

    let mut entries = tar::Archive::new(archive);
    let mut members = std::collections::BTreeMap::new();
    for entry in entries.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let path = path.to_str().ok_or("non-utf8 bundle member")?.to_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        if members.insert(path, bytes).is_some() {
            return Err("duplicate bundle member".into());
        }
    }
    let manifest = members.remove("manifest.txt").ok_or("missing manifest")?;
    let signature = members
        .remove("manifest-signature.txt")
        .ok_or("missing manifest signature")?;
    let signature = std::str::from_utf8(&signature)?;
    let mut signature_fields = signature.lines();
    let public_key = signature_fields
        .next()
        .and_then(|line| line.strip_prefix("integrity_identity="))
        .ok_or("missing signature identity")?;
    let signature_bytes = signature_fields
        .next()
        .and_then(|line| line.strip_prefix("signature="))
        .ok_or("missing signature bytes")?;
    if signature_fields.next().is_some() || public_key != hex_bytes(&expected.public_key()) {
        return Err("signature identity differs from current instance identity".into());
    }
    let signature = positron_kernel::ExportManifestSignature::new(
        expected,
        decode_fixed_hex::<64>(signature_bytes)?,
    )?;
    signature.verify(expected, &manifest)?;

    let manifest = std::str::from_utf8(&manifest)?;
    let mut expected_members = std::collections::BTreeSet::new();
    let mut redaction_digest = None;
    for line in manifest.lines() {
        if let Some(record) = line.strip_prefix("member=") {
            let mut fields = record.split_whitespace();
            let path = fields.next().ok_or("manifest member path")?;
            let byte_count = fields
                .next()
                .and_then(|field| field.strip_prefix("bytes="))
                .ok_or("manifest member size")?
                .parse::<usize>()?;
            let digest = fields
                .next()
                .and_then(|field| field.strip_prefix("sha256="))
                .ok_or("manifest member digest")?;
            if fields.next().is_some() || !expected_members.insert(path.to_owned()) {
                return Err("malformed or duplicate manifest member".into());
            }
            let actual = members
                .get(path)
                .ok_or("manifest member absent from archive")?;
            if actual.len() != byte_count || hex_bytes(&Sha256::digest(actual)) != digest {
                return Err("manifest member digest mismatch".into());
            }
        } else if let Some(digest) = line.strip_prefix("redaction_report_sha256=") {
            redaction_digest = Some(digest);
        }
    }
    let redaction = members
        .get("redaction-report.txt")
        .ok_or("missing redaction report")?;
    let actual_redaction_digest = hex_bytes(&Sha256::digest(redaction));
    if redaction_digest != Some(actual_redaction_digest.as_str()) {
        return Err("redaction report digest mismatch".into());
    }
    if members
        .keys()
        .any(|path| path != "redaction-report.txt" && !expected_members.contains(path))
    {
        return Err("archive member omitted from signed manifest".into());
    }
    Ok(())
}

#[cfg(unix)]
fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(unix)]
fn decode_fixed_hex<const N: usize>(encoded: &str) -> Result<[u8; N], Box<dyn std::error::Error>> {
    if encoded.len() != N.saturating_mul(2) {
        return Err("invalid hex length".into());
    }
    let mut bytes = [0_u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let offset = index.checked_mul(2).ok_or("hex offset")?;
        *byte = u8::from_str_radix(encoded.get(offset..offset + 2).ok_or("hex slice")?, 16)?;
    }
    Ok(bytes)
}

#[cfg(unix)]
fn initialized_doctor_fixture(
    label: &str,
) -> Result<(std::path::PathBuf, ChildRoots, std::path::PathBuf), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-doctor-{label}-{nonce}"));
    let roots = ChildRoots::new(&root)?;
    let paths = BootstrapPaths::new(&roots.data, &roots.secrets, MountQualification::LocalHost)?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let config = root.join("positron.toml");
    fs::write(
        &config,
        process_configuration(&root, &roots.data, &roots.secrets, available_ports()?),
    )?;
    Ok((root, roots, config))
}

#[cfg(unix)]
fn initialized_support_bundle_fixture(
    label: &str,
) -> Result<(std::path::PathBuf, ChildRoots, std::path::PathBuf), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-support-{label}-{nonce}"));
    let roots = ChildRoots::new(&root)?;
    let paths = BootstrapPaths::new(&roots.data, &roots.secrets, MountQualification::LocalHost)?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let config = root.join("positron.toml");
    fs::write(
        &config,
        process_configuration(
            &root,
            &roots.data,
            &roots.secrets,
            [42_001, 42_002, 42_003, 42_004, 42_005],
        ),
    )?;
    Ok((root, roots, config))
}

#[cfg(unix)]
fn volume_bytes(
    root: &std::path::Path,
) -> Result<Vec<(std::path::PathBuf, Vec<u8>)>, std::io::Error> {
    fn walk(
        root: &std::path::Path,
        current: &std::path::Path,
        output: &mut Vec<(std::path::PathBuf, Vec<u8>)>,
    ) -> Result<(), std::io::Error> {
        let mut entries = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .map_err(std::io::Error::other)?
                .to_path_buf();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                output.push((relative.clone(), Vec::new()));
                walk(root, &path, output)?;
            } else if kind.is_file() {
                output.push((relative, fs::read(path)?));
            }
        }
        Ok(())
    }
    let mut output = Vec::new();
    walk(root, root, &mut output)?;
    Ok(output)
}
