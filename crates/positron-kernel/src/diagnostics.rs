//! Kernel-owned bounded crash evidence.  This module deliberately accepts only
//! closed vocabulary fields; it never receives panic payloads or backtraces.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
    time::{Duration, SystemTime},
};

use sha2::{Digest, Sha256};

use crate::{OwnedPrimaryDataVolume, StorageKernelResourceAuthority};

const MAX_RECORD_BYTES: usize = 384;
const MAX_RECORDS: usize = 32;
const MAX_ENUMERATED_ENTRIES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrashRecordFailure {
    Unavailable,
    Full,
    Invalid,
}

/// A sanitized record whose fields are validated before any storage I/O.
pub struct CrashRecord {
    phase: &'static str,
    finding_code: &'static str,
    component: &'static str,
    catalog_generation: Option<u64>,
    backtrace_identity: String,
}

impl CrashRecord {
    pub fn new(
        phase: &'static str,
        finding_code: &'static str,
        component: &'static str,
    ) -> Result<Self, CrashRecordFailure> {
        (valid(phase) && valid(finding_code) && valid(component))
            .then_some(Self {
                phase,
                finding_code,
                component,
                catalog_generation: None,
                backtrace_identity: "unavailable".to_owned(),
            })
            .ok_or(CrashRecordFailure::Invalid)
    }
    #[must_use]
    pub fn with_catalog_generation(mut self, generation: u64) -> Self {
        self.catalog_generation = Some(generation);
        self
    }
    #[must_use]
    pub fn with_backtrace(mut self, backtrace: &std::backtrace::Backtrace) -> Self {
        self.backtrace_identity = match backtrace.status() {
            std::backtrace::BacktraceStatus::Captured => {
                let digest = Sha256::digest(format!("{backtrace:?}").as_bytes());
                format!("sha256-{}", hex(&digest[..8]))
            },
            std::backtrace::BacktraceStatus::Disabled => "disabled".to_owned(),
            _ => "unavailable".to_owned(),
        };
        self
    }
    pub fn render(&self) -> String {
        format!(
            "record_version=1\nproduct=positron\nbuild_identity={}\nphase={}\ncomponent={}\nfinding_code={}\nbacktrace_identity={}\ncatalog_generation={}\noperation_generation=unavailable\n",
            env!("CARGO_PKG_VERSION"),
            self.phase,
            self.component,
            self.finding_code,
            self.backtrace_identity,
            self.catalog_generation
                .map_or_else(|| "unavailable".to_owned(), |value| value.to_string())
        )
    }
}

/// Holds a duplicate of the Kernel's already-qualified root handle. It cannot
/// be built from an application path, and therefore remains valid only while
/// the Storage Kernel owns the Primary Data Volume.
pub struct CrashRecordStore {
    _root: File,
    root_path: PathBuf,
}

impl CrashRecordStore {
    pub fn from_authority(
        authority: &StorageKernelResourceAuthority,
    ) -> Result<Self, CrashRecordFailure> {
        let volume = authority
            .primary_data_volume()
            .ok_or(CrashRecordFailure::Unavailable)?;
        Self::from_volume(volume)
    }
    pub fn from_volume(volume: &OwnedPrimaryDataVolume) -> Result<Self, CrashRecordFailure> {
        volume
            ._root
            .try_clone()
            .map(|root| Self {
                _root: root,
                root_path: volume.root_path.clone(),
            })
            .map_err(|_| CrashRecordFailure::Unavailable)
    }
    fn directory(&self) -> PathBuf {
        self.root_path.join("diagnostics").join("crash-records")
    }
    pub fn persist(&self, record: &CrashRecord) -> Result<(), CrashRecordFailure> {
        let directory = self.directory();
        fs::create_dir_all(&directory).map_err(|_| CrashRecordFailure::Unavailable)?;
        let metadata =
            fs::symlink_metadata(&directory).map_err(|_| CrashRecordFailure::Unavailable)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(CrashRecordFailure::Unavailable);
        }
        let bytes = record.render().into_bytes();
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(CrashRecordFailure::Invalid);
        }
        for sequence in 0..MAX_RECORDS {
            let path = directory.join(format!("record-{sequence:020}.txt"));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    set_owner_only(&file)?;
                    file.write_all(&bytes)
                        .map_err(|_| CrashRecordFailure::Unavailable)?;
                    return file.sync_all().map_err(|_| CrashRecordFailure::Unavailable);
                },
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(CrashRecordFailure::Unavailable),
            }
        }
        Err(CrashRecordFailure::Full)
    }
    pub fn read_recent(
        &self,
        window: Duration,
        maximum_files: usize,
        maximum_bytes: usize,
        now: SystemTime,
    ) -> Result<CrashReadout, CrashRecordFailure> {
        let mut entries = match fs::read_dir(self.directory()) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(CrashReadout::empty());
            },
            Err(_) => return Err(CrashRecordFailure::Unavailable),
        };
        let mut records = Vec::new();
        let mut omissions = Vec::new();
        let mut total = 0usize;
        for entry in entries.by_ref().take(MAX_ENUMERATED_ENTRIES) {
            let entry = entry.map_err(|_| CrashRecordFailure::Unavailable)?;
            if records.len() == maximum_files {
                omit_once(&mut omissions, "crash_record_file_limit");
                break;
            }
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|_| CrashRecordFailure::Unavailable)?;
            if file_type.is_symlink() || !file_type.is_file() {
                omit_once(&mut omissions, "unsafe_crash_record_file");
                continue;
            }
            if !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("record-") && name.ends_with(".txt"))
            {
                omit_once(&mut omissions, "unknown_crash_record_file");
                continue;
            }
            let metadata = entry
                .metadata()
                .map_err(|_| CrashRecordFailure::Unavailable)?;
            let fresh = metadata
                .modified()
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .is_some_and(|age| age <= window);
            if !fresh {
                omit_once(&mut omissions, "crash_record_log_window");
                continue;
            }
            if metadata.len() > MAX_RECORD_BYTES as u64 {
                omit_once(&mut omissions, "oversize_crash_record");
                continue;
            }
            let mut bytes = Vec::new();
            File::open(path)
                .map_err(|_| CrashRecordFailure::Unavailable)?
                .take((MAX_RECORD_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| CrashRecordFailure::Unavailable)?;
            if bytes.len() > MAX_RECORD_BYTES || !valid_rendered(&bytes) {
                omit_once(&mut omissions, "malformed_crash_record");
                continue;
            }
            let next = total
                .checked_add(bytes.len())
                .ok_or(CrashRecordFailure::Unavailable)?;
            if next > maximum_bytes {
                omit_once(&mut omissions, "crash_record_byte_limit");
                break;
            }
            total = next;
            records.push(bytes);
        }
        // Reading one additional directory entry proves that the bounded
        // inspection intentionally omitted an unknown number of entries. It
        // does not validate, stat, or open that entry.
        if entries
            .next()
            .transpose()
            .map_err(|_| CrashRecordFailure::Unavailable)?
            .is_some()
        {
            omit_once(&mut omissions, "crash_record_enumeration_limit");
        }
        records.sort();
        Ok(CrashReadout { records, omissions })
    }
}

pub struct CrashReadout {
    records: Vec<Vec<u8>>,
    omissions: Vec<&'static str>,
}
impl CrashReadout {
    fn empty() -> Self {
        Self {
            records: Vec::new(),
            omissions: Vec::new(),
        }
    }
    pub fn render(&self) -> String {
        if self.records.is_empty() {
            return "record_count=0\n".to_owned();
        }
        self.records
            .iter()
            .enumerate()
            .map(|(index, record)| {
                format!("record_index={index}\n{}", String::from_utf8_lossy(record))
            })
            .collect()
    }
    pub fn omissions(&self) -> &[&'static str] {
        &self.omissions
    }
}
fn valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}
fn valid_rendered(bytes: &[u8]) -> bool {
    let Ok(value) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut fields = value.strip_suffix('\n').unwrap_or(value).split('\n');
    let expected = [
        ("record_version", Some("1")),
        ("product", Some("positron")),
        ("build_identity", None),
        ("phase", None),
        ("component", None),
        ("finding_code", None),
        ("backtrace_identity", None),
        ("catalog_generation", None),
        ("operation_generation", Some("unavailable")),
    ];
    expected.into_iter().all(|(key, fixed)| {
        let Some((actual_key, value)) = fields.next().and_then(|line| line.split_once('=')) else {
            return false;
        };
        actual_key == key
            && fixed.map_or_else(
                || canonical_crash_value(key, value),
                |expected| value == expected,
            )
    }) && fields.next().is_none()
}

fn canonical_crash_value(key: &str, value: &str) -> bool {
    match key {
        "build_identity" => safe_value(value),
        "phase" => matches!(
            value,
            "starting" | "serving" | "draining" | "stopping" | "fenced"
        ),
        "component" => matches!(value, "runtime" | "catalog" | "serving_loop"),
        "finding_code" => matches!(
            value,
            "runtime_serving_loop_panicked"
                | "runtime_poll_panicked"
                | "joined_task_panicked"
                | "runtime_drain_failed"
                | "runtime_startup_failed"
                | "catalog_unavailable"
        ),
        "backtrace_identity" => {
            value == "unavailable"
                || value == "disabled"
                || (value.len() == 23
                    && value.starts_with("sha256-")
                    && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit()))
        },
        "catalog_generation" => value == "unavailable" || value.parse::<u64>().is_ok(),
        _ => false,
    }
}
fn safe_value(value: &str) -> bool {
    value == "unavailable"
        || (!value.is_empty()
            && value.len() <= 96
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'_' | b'.' | b'-')
            }))
}
fn omit_once(values: &mut Vec<&'static str>, value: &'static str) {
    if !values.contains(&value) {
        values.push(value);
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn set_owner_only(file: &File) -> Result<(), CrashRecordFailure> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| CrashRecordFailure::Unavailable)
}

/// Exercises the exact bounded decoder applied to untrusted persisted crash
/// records after their file-size limit has been enforced by `read_recent`.
#[cfg(fuzzing)]
pub fn fuzz_crash_record_decoder(data: &[u8]) {
    let bounded = &data[..data.len().min(MAX_RECORD_BYTES + 1)];
    let _ = valid_rendered(bounded);
}
