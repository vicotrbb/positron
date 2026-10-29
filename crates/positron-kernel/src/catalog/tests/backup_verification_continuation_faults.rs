use super::*;
use std::io::{Read, Seek, SeekFrom, Write};

pub(super) fn incomplete_owner_index(
    catalog: &Catalog<'_>,
    operation: [u8; 16],
) -> Result<(), Box<dyn std::error::Error>> {
    let name = operation
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let directory = format!("backup-captures/{name}");
    rustix::fs::mkdirat(
        catalog.export_output_root()?,
        directory.as_str(),
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::XUSR,
    )?;
    let file = format!("{directory}/index.partial");
    let mut file = std::fs::File::from(rustix::fs::openat(
        catalog.export_output_root()?,
        file.as_str(),
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )?);
    file.write_all(b"interrupted uncommitted owner index")?;
    file.sync_all()?;
    Ok(())
}

pub(super) fn reference_rejections(
    catalog: &Catalog<'_>,
    binding: BackupVerificationBinding,
    reference: BackupVerificationReference,
    index: &[u8],
    grant: ResourceAmounts,
) -> Result<(), Box<dyn std::error::Error>> {
    let read = |binding, reference| {
        catalog.resume_backup_verification_continuation(binding, reference, index, grant)
    };
    for wrong in [
        BackupVerificationBinding {
            operation: [0x71; 16],
            ..binding
        },
        BackupVerificationBinding {
            intent: [0x72; 32],
            ..binding
        },
        BackupVerificationBinding {
            capture_operation: [0x73; 16],
            ..binding
        },
        BackupVerificationBinding {
            capture_request: [0x74; 32],
            ..binding
        },
        BackupVerificationBinding {
            manifest: [0x75; 32],
            ..binding
        },
        BackupVerificationBinding {
            registry: [0x76; 32],
            ..binding
        },
        BackupVerificationBinding {
            index: [0x77; 32],
            ..binding
        },
    ] {
        assert!(
            read(wrong, reference).is_err(),
            "an unrelated authenticated binding cannot resume this artifact"
        );
    }
    for wrong in [
        BackupVerificationReference {
            identity: [0x81; 32],
            ..reference
        },
        BackupVerificationReference {
            sequence: reference.sequence + 1,
            ..reference
        },
        BackupVerificationReference {
            predecessor: [0x82; 32],
            ..reference
        },
    ] {
        assert!(
            read(binding, wrong).is_err(),
            "missing or substituted references must fail closed"
        );
    }
    let mut file = continuation_file(catalog, binding.operation, reference.identity, false)?;
    let mut original = Vec::new();
    file.read_to_end(&mut original)?;
    let mut corrupted = original.clone();
    *corrupted.last_mut().ok_or("protected artifact")? ^= 1;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&corrupted)?;
    file.sync_all()?;
    assert!(
        read(binding, reference).is_err(),
        "ciphertext corruption cannot fall back to a fresh native verification"
    );
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&original)?;
    file.sync_all()?;
    assert!(read(binding, reference).is_ok());
    Ok(())
}
