//! Bounded, typed crash evidence. Crash payloads and backtraces never enter
//! this store: a record consists solely of validated vocabulary values.

use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime},
};

const MAX_RECORD_BYTES: usize = 384;
const MAX_RECORDS: usize = 32;
static NEXT_RECORD: AtomicU64 = AtomicU64::new(0);

pub(crate) struct SanitizedCrashRecord {
    phase: &'static str,
    finding_code: &'static str,
    component: &'static str,
    catalog_generation: Option<u64>,
    backtrace_identity: String,
}

impl SanitizedCrashRecord {
    pub(crate) fn new(
        phase: &'static str,
        finding_code: &'static str,
        component: &'static str,
    ) -> Result<Self, ()> {
        (valid(phase) && valid(finding_code) && valid(component))
            .then_some(Self {
                phase,
                finding_code,
                component,
                catalog_generation: None,
                backtrace_identity: "unavailable".to_owned(),
            })
            .ok_or(())
    }

    pub(crate) fn render(&self) -> String {
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

    pub(crate) fn with_catalog_generation(mut self, catalog_generation: u64) -> Self {
        self.catalog_generation = Some(catalog_generation);
        self
    }

    pub(crate) fn with_backtrace(mut self, backtrace: &std::backtrace::Backtrace) -> Self {
        self.backtrace_identity = match backtrace.status() {
            std::backtrace::BacktraceStatus::Captured => {
                let rendered = format!("{backtrace:?}");
                let digest = Sha256::digest(rendered.as_bytes());
                format!("sha256-{}", hex(&digest[..8]))
            },
            std::backtrace::BacktraceStatus::Disabled => "disabled".to_owned(),
            _ => "unavailable".to_owned(),
        };
        self
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut rendered = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        rendered.push_str(&format!("{byte:02x}"));
    }
    rendered
}

pub(crate) struct CrashRecordStore {
    directory: PathBuf,
}

impl CrashRecordStore {
    pub(crate) fn under_data_directory(data_directory: &Path) -> Self {
        Self {
            directory: data_directory.join("diagnostics").join("crash-records"),
        }
    }

    /// Persists one already-sanitized record. A full or unavailable bounded
    /// store fails closed and never writes a free-form substitute.
    pub(crate) fn persist(&self, record: &SanitizedCrashRecord) -> Result<(), ()> {
        fs::create_dir_all(&self.directory).map_err(|_| ())?;
        let directory = fs::symlink_metadata(&self.directory).map_err(|_| ())?;
        if directory.file_type().is_symlink() || !directory.is_dir() {
            return Err(());
        }
        if fs::read_dir(&self.directory).map_err(|_| ())?.count() >= MAX_RECORDS {
            return Err(());
        }
        let sequence = NEXT_RECORD.fetch_add(1, Ordering::Relaxed);
        let path = self.directory.join(format!("record-{sequence:020}.txt"));
        let bytes = record.render().into_bytes();
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(());
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| ())?;
        set_owner_only(&file)?;
        file.write_all(&bytes).map_err(|_| ())?;
        file.sync_all().map_err(|_| ())
    }

    /// Reads only canonical crash-record files. The caller receives explicit
    /// omissions for unknown, stale, malformed, over-limit input.
    pub(crate) fn read_recent(
        &self,
        window: Duration,
        maximum_files: usize,
        maximum_bytes: usize,
        now: SystemTime,
    ) -> Result<CrashReadout, ()> {
        let entries = match fs::read_dir(&self.directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(CrashReadout::empty());
            },
            Err(_) => return Err(()),
        };
        let mut records = Vec::new();
        let mut omissions = Vec::new();
        let mut total = 0usize;
        for entry in entries {
            let entry = entry.map_err(|_| ())?;
            if records.len() == maximum_files {
                omit_once(&mut omissions, "crash_record_file_limit");
                break;
            }
            let path = entry.path();
            let file_type = entry.file_type().map_err(|_| ())?;
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
            let metadata = entry.metadata().map_err(|_| ())?;
            let fresh = metadata
                .modified()
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .is_some_and(|age| age <= window);
            if !fresh {
                omit_once(&mut omissions, "crash_record_log_window");
                continue;
            }
            if metadata.len() > u64::try_from(MAX_RECORD_BYTES).map_err(|_| ())? {
                omit_once(&mut omissions, "oversize_crash_record");
                continue;
            }
            let mut bytes = Vec::new();
            File::open(path)
                .map_err(|_| ())?
                .take(u64::try_from(MAX_RECORD_BYTES + 1).map_err(|_| ())?)
                .read_to_end(&mut bytes)
                .map_err(|_| ())?;
            if bytes.len() > MAX_RECORD_BYTES || !valid_rendered(&bytes) {
                omit_once(&mut omissions, "malformed_crash_record");
                continue;
            }
            let next = total.checked_add(bytes.len()).ok_or(())?;
            if next > maximum_bytes {
                omit_once(&mut omissions, "crash_record_byte_limit");
                break;
            }
            total = next;
            records.push(bytes);
        }
        records.sort();
        Ok(CrashReadout { records, omissions })
    }
}

pub(crate) struct CrashReadout {
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
    pub(crate) fn render(&self) -> String {
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
    pub(crate) fn omissions(&self) -> &[&'static str] {
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
    std::str::from_utf8(bytes).is_ok_and(|value| {
        value.lines().all(|line| {
            line.split_once('=')
                .is_some_and(|(key, value)| valid(key) && safe_value(value))
        })
    })
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

#[cfg(unix)]
fn set_owner_only(file: &File) -> Result<(), ()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| ())
}
#[cfg(not(unix))]
fn set_owner_only(_file: &File) -> Result<(), ()> {
    Ok(())
}
