//! Deterministic native distribution wrapping. Release Trust signs the resulting inventory.
use crate::ReleaseError;
use flate2::{Compression, GzBuilder};

/// Exact Release 1 archive platforms; there is no host-dependent fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeTarget {
    LinuxX86_64,
    LinuxAarch64,
    MacosX86_64,
    MacosAarch64,
}
impl std::str::FromStr for NativeTarget {
    type Err = ReleaseError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "linux-x86_64" => Ok(Self::LinuxX86_64),
            "linux-aarch64" => Ok(Self::LinuxAarch64),
            "macos-x86_64" => Ok(Self::MacosX86_64),
            "macos-aarch64" => Ok(Self::MacosAarch64),
            _ => Err(ReleaseError::Unsupported),
        }
    }
}
impl NativeTarget {
    fn linux(self) -> bool {
        matches!(self, Self::LinuxX86_64 | Self::LinuxAarch64)
    }
    fn check(self, binary: &[u8]) -> Result<(), ReleaseError> {
        let matches = match self {
            Self::LinuxX86_64 | Self::LinuxAarch64 => {
                binary.starts_with(b"\x7fELF\x02\x01\x01")
                    && matches!(binary.get(16..18), Some([2 | 3, 0]))
                    && binary.get(18..20)
                        == Some(match self {
                            Self::LinuxX86_64 => [62, 0].as_slice(),
                            _ => [183, 0].as_slice(),
                        })
            },
            Self::MacosX86_64 | Self::MacosAarch64 => {
                binary.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
                    && binary.get(4..8)
                        == Some(match self {
                            Self::MacosX86_64 => [7, 0, 0, 1].as_slice(),
                            _ => [12, 0, 0, 1].as_slice(),
                        })
                    && binary.get(12..16) == Some([2, 0, 0, 0].as_slice())
            },
        };
        if matches {
            Ok(())
        } else {
            Err(ReleaseError::IdentityMismatch)
        }
    }
}

/// Wrap an unchanged native executable with the generated contract and operator examples.
/// This emits unsigned payload bytes, not a signed or publishable release.
/// Inputs and output are bounded to the existing release scanner's 512 MiB ceiling.
pub fn native_archive(target: NativeTarget, binary: &[u8]) -> Result<Vec<u8>, ReleaseError> {
    if binary.len() > 500 << 20 {
        return Err(ReleaseError::LimitExceeded);
    }
    target.check(binary)?;
    let gzip = GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(gzip);
    let example = positron_config::generated_example();
    let schema = positron_config::generated_json_schema();
    let reference = positron_config::generated_reference();
    for (name, bytes, mode) in [
        (
            "LICENSE",
            include_bytes!("../../../LICENSE").as_slice(),
            0o644,
        ),
        (
            "README.md",
            include_bytes!("../../../deploy/native/README.md").as_slice(),
            0o644,
        ),
        ("bin/positron", binary, 0o755),
        ("etc/positron.toml.example", example.as_bytes(), 0o644),
        (
            "docs/operations/release-trust.md",
            include_bytes!("../../../docs/operations/release-trust.md").as_slice(),
            0o644,
        ),
        (
            "docs/operations/repository.md",
            include_bytes!("../../../docs/operations/repository.md").as_slice(),
            0o644,
        ),
        (
            "docs/operations/restore.md",
            include_bytes!("../../../docs/operations/restore.md").as_slice(),
            0o644,
        ),
        (
            "docs/operations/upgrades.md",
            include_bytes!("../../../docs/operations/upgrades.md").as_slice(),
            0o644,
        ),
        (
            "docs/operations/local-key-recovery.md",
            include_bytes!("../../../docs/operations/local-key-recovery.md").as_slice(),
            0o644,
        ),
        ("share/config.schema.json", schema.as_bytes(), 0o644),
        ("share/configuration.md", reference.as_bytes(), 0o644),
        if target.linux() {
            (
                "share/positron.service",
                include_bytes!("../../../deploy/native/positron.service").as_slice(),
                0o644,
            )
        } else {
            (
                "share/com.guaracloud.positron.plist",
                include_bytes!("../../../deploy/native/com.guaracloud.positron.plist").as_slice(),
                0o644,
            )
        },
    ] {
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(bytes.len() as u64);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_mode(mode);
        header.set_cksum();
        archive
            .append_data(&mut header, format!("positron/{name}"), bytes)
            .map_err(|_| ReleaseError::Unavailable)?;
    }
    archive
        .into_inner()
        .and_then(|gzip| gzip.finish())
        .map_err(|_| ReleaseError::Unavailable)
}
